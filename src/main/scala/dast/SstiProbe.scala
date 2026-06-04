package dast

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.unmarshalling.Unmarshal
import org.slf4j.LoggerFactory

/** Browser-free, HTTP-level server-side template injection probe.
  *
  * Per query parameter it fetches a baseline, then injects each
  * [[SstiCheck.payloads]] entry and confirms via [[SstiCheck.confirms]] (the
  * evaluated product present, the raw expression absent). At most one finding
  * per parameter (first confirming payload wins). Runs only under an authorized
  * active scope (the orchestrator gates it); the HTTP call is exercised only
  * live, the confirm logic it composes is unit tested in [[SstiCheck]].
  */
object SstiProbe:

  private val log = LoggerFactory.getLogger("dast.SstiProbe")

  private val UserAgent =
    "pekko-dast-scanner/0.1 (+authorized security testing)"

  def scan(
      target: String,
  )(using ActorSystem[?], ExecutionContext): Future[Vector[Finding]] = Future
    .sequence(SstiCheck.paramNames(target).map(p => probeParam(target, p)))
    .map(_.flatten.toVector)

  private def probeParam(target: String, name: String)(using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Option[Finding]] =
    val point = InjectionPoint.QueryParam(name)
    bodyOf(target).flatMap { baseline =>
      SstiCheck.payloads
        .foldLeft(Future.successful(Option.empty[Finding])) { (acc, payload) =>
          acc.flatMap {
            case some @ Some(_) => Future.successful(some)
            case None => bodyOf(point.placeInto(target, payload)).map { body =>
                if SstiCheck.confirms(baseline, body) then
                  Some(SstiCheck.toFinding(point, payload))
                else None
              }
          }
        }
    }

  private def bodyOf(url: String)(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[String] = ProbeHttp.send(
    "ssti",
    HttpRequest(
      uri = url,
      headers = List(headers.RawHeader("User-Agent", UserAgent)),
    ),
  ).flatMap(r => Unmarshal(r.entity).to[String]).recover { case t =>
    log.warn("SSTI probe error for {}: {}", url, t.getMessage)
    ""
  }
