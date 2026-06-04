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
    val request = HttpRequest(
      uri = target,
      headers = List(
        headers.RawHeader("User-Agent", UserAgent),
        headers.RawHeader("Origin", CorsCheck.probeOrigin),
      ),
    )
    ProbeHttp.send("cors", request).map { response =>
      response.entity.discardBytes()
      def header(name: String): Option[String] = response.headers
        .find(_.lowercaseName() == name.toLowerCase).map(_.value())
      CorsCheck.analyze(
        CorsCheck.probeOrigin,
        header("access-control-allow-origin"),
        header("access-control-allow-credentials"),
      ).toVector
    }.recover { case t =>
      log.warn("CORS probe error for {}: {}", target, t.getMessage)
      Vector.empty
    }
