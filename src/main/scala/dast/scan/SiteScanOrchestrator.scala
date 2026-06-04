package dast.scan

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.slf4j.LoggerFactory

import dast.Finding

/** Scans a whole site: discover the in-scope URLs from a seed, then run the
  * single-URL scan ([[ScanOrchestrator]], via the injected `scanOne`) on each,
  * aggregating into one per-URL report.
  *
  * Discovery is read-only; per-URL active probing stays gated by `ConsentGate`
  * inside `scanOne`. A plain sequential `Future`: effects are injected so this
  * crawl-then-scan-each loop is testable with stubs. URLs are scoped / deduped
  * / capped by [[Scope]]; a failed `discover` falls back to scanning the seed,
  * and a failed `scanOne` contributes an empty result rather than aborting.
  */
object SiteScanOrchestrator:

  private val log = LoggerFactory.getLogger("dast.scan.SiteScanOrchestrator")

  /** Injected effects, for testability. */
  final case class Effects(
      discover: String => Future[Seq[String]],
      scanOne: String => Future[Vector[Finding]],
  )

  /** Run the site scan, completing with findings grouped per scanned URL (seed
    * first).
    */
  def run(effects: Effects, seed: String, maxPages: Int = 20)(using
      ExecutionContext,
  ): Future[Vector[(String, Vector[Finding])]] = effects.discover(seed)
    .recover { case e =>
      log.warn(s"Discovery failed for $seed: ${Option(e.getMessage)
          .getOrElse(e.toString)};" + " scanning seed only")
      Seq.empty
    }.flatMap { urls =>
      val frontier = Scope.frontier(seed, urls, maxPages)
      // Scan each URL in order, threading the accumulator through a Future chain
      // (sequential, one in flight at a time, as the actor version was).
      frontier.foldLeft(Future.successful(Vector.empty[(String, Vector[Finding])])) {
        (accF, url) =>
          accF.flatMap { acc =>
            effects.scanOne(url).recover { case _ => Vector.empty } // fail soft
              .map(fs => acc :+ (url -> fs))
          }
      }.map { results =>
        log.info(s"Site scan complete for $seed: ${results
            .size} url(s), " + s"${results.map(_._2.size).sum} finding(s)")
        results
      }
    }
