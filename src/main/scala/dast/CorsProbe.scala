package dast

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.slf4j.LoggerFactory

/** Browser-free, HTTP-level CORS misconfiguration probe.
  *
  * Sends one GET carrying a forged `Origin` ([[CorsCheck.probeOrigin]]) and
  * judges the response's ACAO / ACAC headers via [[CorsCheck.analyze]]. One
  * request per target (CORS is a per-response policy, not per-parameter). Runs
  * only under an authorized active scope; the HTTP call is live-only, the
  * verdict it composes is unit tested in [[CorsCheck]].
  */
object CorsProbe:

  private val log = LoggerFactory.getLogger("dast.CorsProbe")

  private val UserAgent =
    "pekko-dast-scanner/0.1 (+authorized security testing)"

  def scan(target: String)(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[Vector[Finding]] =
    val targetHost = scala.util.Try(new java.net.URI(target).getHost).toOption
      .flatMap(Option(_))
    // One request per forged Origin (the bare sentinel plus host-derived ones
    // that catch suffix/prefix allow-list bugs). Keep only the most severe
    // finding so the variants do not produce duplicate CORS findings.
    Future.sequence(CorsCheck.probeOrigins(targetHost).map(probe(target, _)))
      .map(_.flatten.sortBy(severityRank).headOption.toVector)

  private def probe(target: String, origin: String)(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[Option[Finding]] =
    val request = HttpRequest(
      uri = target,
      headers = List(
        headers.RawHeader("User-Agent", UserAgent),
        headers.RawHeader("Origin", origin),
      ),
    )
    ProbeHttp.send("cors", request).map { response =>
      response.entity.discardBytes()
      def header(name: String): Option[String] = response.headers
        .find(_.lowercaseName() == name.toLowerCase).map(_.value())
      CorsCheck.analyze(
        origin,
        header("access-control-allow-origin"),
        header("access-control-allow-credentials"),
      )
    }.recover { case t =>
      log.warn(
        "CORS probe error for {} (origin {}): {}",
        target,
        origin,
        t.getMessage,
      )
      None
    }

  private def severityRank(f: Finding): Int = f.severity match
    case Severity.Critical => 0
    case Severity.High => 1
    case Severity.Medium => 2
    case Severity.Low => 3
    case Severity.Info => 4
