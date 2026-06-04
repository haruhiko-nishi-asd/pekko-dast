package dast

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.HttpRequest
import org.apache.pekko.http.scaladsl.model.HttpResponse

/** A throttled, target-facing request that — when [[EvidenceLog]] is on —
  * records the request line plus the response status / headers / timing, a
  * replayable proof that this exact probe request was made (and what it
  * returned). The response body is NOT consumed here, so callers read it as
  * before. Drop-in for `HttpThrottle(Http()(system).singleRequest(request))`,
  * tagged with the `check` that issued it.
  */
object ProbeHttp:

  def send(check: String, request: HttpRequest)(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[HttpResponse] =
    val sent = HttpThrottle(Http()(system).singleRequest(request))
    if !EvidenceLog.enabled then sent
    else
      val t0 = System.nanoTime()
      sent.map { resp =>
        EvidenceLog.http(
          check,
          request.method.value,
          request.uri.toString,
          resp.status.intValue(),
          (System.nanoTime() - t0) / 1000000,
          resp.headers.map(h => h.name() -> h.value()).toSeq,
        )
        resp
      }
