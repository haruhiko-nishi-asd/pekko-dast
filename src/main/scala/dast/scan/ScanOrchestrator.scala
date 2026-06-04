package dast.scan

import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.util.Failure
import scala.util.Success
import scala.util.Try

import org.slf4j.LoggerFactory

import dast.ActionClass
import dast.Authorization
import dast.ClientStateSnapshot
import dast.ConsentGate
import dast.Finding
import dast.FindingKind
import dast.GateDecision
import dast.InjectionPoint
import dast.LlmDecision
import dast.LlmDecision.*
import dast.Markers
import dast.SinkScanOp
import dast.Tier1
import dast.analyzer.AnalyzerContext

/** Runs a bounded scan of one authorized target by composing the DAST pieces.
  *
  * Capture client state once, run the deterministic Tier 1 checks (always),
  * then loop up to `maxSteps`: ask the analyzer for one decision and act on it.
  * `Probe` decisions are re-checked against the [[ConsentGate]] here (so an
  * observe-only authorization yields a capture + Tier 1 scan with no active
  * work) and, when permitted, run [[dast.ProbeOp]]. `Done` or budget exhaustion
  * finishes the scan with all findings.
  *
  * This is a sequential async pipeline expressed as a plain `Future`: effects
  * (capture / analyze / probe) are injected so it is testable with stubs and no
  * browser or model, and it fails soft throughout — a capture failure yields no
  * findings, and every effect failure folds to a safe step (the analyzer
  * already fails closed to `Done`).
  */
object ScanOrchestrator:

  private val log = LoggerFactory.getLogger("dast.scan.ScanOrchestrator")

  /** The browser/model effects, injected for testability. `sinkScan` delivers a
    * benign marker through a source and returns the DOM sinks it reached.
    */
  final case class Effects(
      capture: String => Future[ClientStateSnapshot],
      analyze: AnalyzerContext => Future[LlmDecision],
      probe: (String, InjectionPoint, String, String) => Future[Option[Finding]],
      sinkScan: (String, InjectionPoint, String) => Future[Set[String]],
      // Deterministic HTTP probes over the URL's query params (browser-free).
      redirectScan: String => Future[Vector[Finding]] =
        _ => Future.successful(Vector.empty),
      sqlScan: String => Future[Vector[Finding]] =
        _ => Future.successful(Vector.empty),
      ssrfScan: String => Future[Vector[Finding]] =
        _ => Future.successful(Vector.empty),
  )

  /** Injection-point candidates derived from a URL's query-param names. Pure.
    */
  def injectionPointsOf(url: String): Seq[String] = Try(
    new java.net.URI(url).getRawQuery,
  ).toOption.flatMap(Option(_))
    .map(_.split("&").toSeq.filter(_.nonEmpty).map(_.split("=", 2)(0)).distinct)
    .getOrElse(Seq.empty)

  /** Run the scan, completing with all findings (Tier 1 + confirmed probes). */
  def run(
      auth: Authorization,
      effects: Effects,
      target: String,
      maxSteps: Int = 8,
      freshMarker: () => String = () => Markers.fresh(),
  )(using ExecutionContext): Future[Vector[Finding]] =

    // The analyzer/probe loop: one decision per step, bounded by `budget`.
    def step(
        snapshot: ClientStateSnapshot,
        findings: Vector[Finding],
        budget: Int,
        attempted: Set[(String, String)],
    ): Future[Vector[Finding]] =
      if budget <= 0 then Future.successful(findings)
      else
        val points = injectionPointsOf(target)
        log.info(s"Asking analyzer (step ${maxSteps - budget +
            1}/$maxSteps) for " + s"$target: injection points [${points
            .mkString(", ")}]")
        val context = AnalyzerContext
          .fromSnapshot(snapshot, injectionPointIds = points)
        effects.analyze(context).recover { case _ => LlmDecision.Done }
          .flatMap {
            case Done =>
              log.info(s"Analyzer decided: Done for $target")
              Future.successful(findings)
            case Probe(injectionPointId, payloadId) =>
              log.info(
                s"Analyzer decided: Probe param '$injectionPointId' with " +
                  s"payload '$payloadId' on $target",
              )
              val key = (injectionPointId, payloadId)
              if attempted.contains(key) then
                // Re-selected an attempted probe: converged with nothing new, so
                // finish rather than burn budget re-confirming the same finding.
                log.info(
                  s"Probe '$injectionPointId'/'$payloadId' already attempted " +
                    s"on $target; finishing",
                )
                Future.successful(findings)
              else
                ConsentGate.decide(auth, ActionClass.Active, target) match
                  case GateDecision.Permit =>
                    val point = InjectionPoint.QueryParam(injectionPointId)
                    effects.probe(target, point, payloadId, freshMarker())
                      .recover { case _ => None }.flatMap { found =>
                        found match
                          case Some(f) => log
                              .info(s"Probe CONFIRMED on $target: ${f.evidence}")
                          case None => log.info(
                              s"Probe not confirmed on $target (no execution)",
                            )
                        // Dedupe by replay handle so a finding is never recorded
                        // twice.
                        val merged = found.toVector
                          .foldLeft(findings)((acc, f) =>
                            if acc.exists(_.replay == f.replay) then acc
                            else acc :+ f,
                          )
                        step(snapshot, merged, budget - 1, attempted + key)
                      }
                  case GateDecision.Deny(reason) =>
                    log.info(s"Probe denied for $target: $reason")
                    step(snapshot, findings, budget - 1, attempted + key)
            case other => // Navigate / Classify: acknowledged, no state change
              log.info(
                s"Analyzer decided: $other for $target (no action this slice)",
              )
              step(snapshot, findings, budget - 1, attempted)
          }

    effects.capture(target).transformWith {
      case Failure(e) =>
        log.warn(s"Capture failed for $target: ${Option(e.getMessage)
            .getOrElse(e.toString)}")
        Future.successful(Vector.empty)
      case Success(snapshot) =>
        log.info(
          s"Captured $target: ${snapshot.cookies.size} cookie(s) " +
            s"[${snapshot.cookies.map(_.name).mkString(", ")}], " +
            s"${snapshot.localStorage.size} localStorage, " +
            s"${snapshot.sessionStorage.size} sessionStorage key(s)",
        )
        val tier1 = Tier1.run(snapshot).toVector
        // A DOM sink-scan is active work (it injects a marker), so it only runs
        // under an authorized active scope; otherwise go straight to the loop.
        ConsentGate.decide(auth, ActionClass.Active, target) match
          case GateDecision.Deny(_) =>
            // Observe-only: capture + Tier 1 only. No sink-scan, no analyzer
            // call, so it stays free and fully deterministic.
            Future.successful(tier1)
          case GateDecision.Permit =>
            val sinkF = effects
              .sinkScan(target, InjectionPoint.Fragment, freshMarker())
              .recover { case _ => Set.empty[String] }
            sinkF.flatMap { sinks =>
              val dom = SinkScanOp.toFindings(InjectionPoint.Fragment, sinks)
                .toVector
              // Deterministic, browser-free HTTP probes run together before the
              // model loop. Each fails soft to no findings.
              val httpF = Future.sequence(Seq(
                effects.redirectScan(target),
                effects.sqlScan(target),
                effects.ssrfScan(target),
              )).map(_.flatten.toVector).recover { case _ => Vector.empty }
              httpF.flatMap { http =>
                val all = tier1 ++ dom ++ http
                val redirects = all.count(_.kind == FindingKind.OpenRedirect)
                val sqli = all.count(_.kind == FindingKind.SqlInjection)
                val ssrf = all.count(_.kind == FindingKind.Ssrf)
                if redirects > 0 || sqli > 0 || ssrf > 0 then
                  log.info(
                    s"HTTP probes on $target: $redirects open-redirect, " +
                      s"$sqli SQLi, $ssrf SSRF",
                  )
                step(snapshot, all, maxSteps, Set.empty)
              }
            }
    }
