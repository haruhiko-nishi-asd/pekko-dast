package dast

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.unmarshalling.Unmarshal
import org.slf4j.LoggerFactory

/** Browser-free, HTTP-level path-traversal / LFI probe.
  *
  * Per query parameter it fetches a baseline, then injects each
  * [[PathTraversalCheck.payloads]] entry and confirms via
  * [[PathTraversalCheck.confirms]] (a known-file signature present that the
  * baseline lacked). At most one finding per parameter. Runs only under an
  * authorized active scope; the HTTP call is live-only, the confirm logic is
  * unit tested in [[PathTraversalCheck]].
  */
object PathTraversalProbe:

  private val log = LoggerFactory.getLogger("dast.PathTraversalProbe")

  private val UserAgent =
    "pekko-dast-scanner/0.1 (+authorized security testing)"

  def scan(
      target: String,
  )(using ActorSystem[?], ExecutionContext): Future[Vector[Finding]] = Future
    .sequence(
      PathTraversalCheck.paramNames(target).map(p => probeParam(target, p)),
    ).map(_.flatten.toVector)

  private def probeParam(target: String, name: String)(using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Option[Finding]] =
    val point = InjectionPoint.QueryParam(name)
    bodyOf(target).flatMap { baseline =>
      PathTraversalCheck.payloads
        .foldLeft(Future.successful(Option.empty[Finding])) { (acc, payload) =>
          acc.flatMap {
            case some @ Some(_) => Future.successful(some)
            case None => bodyOf(point.placeInto(target, payload)).map { body =>
                PathTraversalCheck.confirms(baseline, body)
                  .map(file => PathTraversalCheck.toFinding(point, file, payload))
              }
          }
        }
    }

  private def bodyOf(url: String)(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[String] = ProbeHttp.send(
    "path-traversal",
    HttpRequest(
      uri = url,
      headers = List(headers.RawHeader("User-Agent", UserAgent)),
    ),
  ).flatMap(r => Unmarshal(r.entity).to[String]).recover { case t =>
    log.warn("Path-traversal probe error for {}: {}", url, t.getMessage)
    ""
  }
