package dast

import java.net.URLDecoder
import java.nio.charset.StandardCharsets

import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.util.Try

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.unmarshalling.Unmarshal
import org.slf4j.LoggerFactory

/** Browser-free, HTTP-level SQL-injection probe over a URL's query parameters.
  *
  * Per parameter, against a [[SqlInjectionCheck]] baseline:
  *   1. Error-based: inject a quote; confirm if a DB error signature appears
  *      that was absent from the baseline.
  *   2. Time-based: try DB-specific sleep payloads; confirm only when the
  *      injected request is slower than baseline by the threshold AND a re-test
  *      is slow too (one slow response could be noise; two is the payload).
  *
  * First confirming technique per parameter wins (at most one finding each).
  * Runs only under an authorized active scope (the orchestrator gates it) and
  * identifies itself with the scanner User-Agent. The HTTP/timing calls are
  * exercised only live; the verdicts they compose are unit tested.
  */
object SqlInjectionProbe:

  private val log = LoggerFactory.getLogger("dast.SqlInjectionProbe")

  private val UserAgent =
    "pekko-dast-scanner/0.1 (+authorized security testing)"

  def scan(target: String)(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[Vector[Finding]] =
    val params = SqlInjectionCheck.paramNames(target)
    Future.sequence(params.map(p => probeParam(target, p)))
      .map(_.flatten.toVector)

  private def probeParam(target: String, name: String)(using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Option[Finding]] =
    val point = InjectionPoint.QueryParam(name)
    val original = paramValue(target, name)

    fetch(target).flatMap {
      case None => Future.successful(None) // no baseline -> cannot judge
      case Some((baselineMs, baselineBody)) =>
        val errUrl = point
          .placeInto(target, SqlInjectionCheck.errorPayload(original))
        fetch(errUrl).flatMap { errResult =>
          errorFinding(point, baselineBody, errResult) match
            case some @ Some(_) => Future.successful(some)
            case None => timeBased(target, point, original, baselineMs)
        }
    }

  /** Error-based verdict: an error signature present now but not in baseline.
    */
  private def errorFinding(
      point: InjectionPoint,
      baselineBody: String,
      errResult: Option[(Long, String)],
  ): Option[Finding] = errResult.flatMap { case (_, body) =>
    SqlInjectionCheck.detectNewError(baselineBody, body)
      .map(db => SqlInjectionCheck.errorFinding(point, db))
  }

  /** Time-based: first payload that is slow under a differential re-test wins.
    *
    * The initial `baselineMs` is only a cheap pre-filter. A hit must then beat
    * a BENIGN request re-measured at confirm time (not the stale baseline): a
    * site that simply became slow overall makes the benign request slow too, so
    * the injected-minus-benign delta stays below threshold and nothing is
    * reported. Measuring benign and injected back to back also rules out a
    * one-off spike.
    */
  private def timeBased(
      target: String,
      point: InjectionPoint,
      original: String,
      baselineMs: Long,
  )(using ActorSystem[?], ExecutionContext): Future[Option[Finding]] =
    val benignUrl = point.placeInto(target, original)
    SqlInjectionCheck.timePayloads(original)
      .foldLeft(Future.successful(Option.empty[Finding])) {
        case (acc, (label, value)) => acc.flatMap {
            case some @ Some(_) => Future.successful(some)
            case None =>
              val url = point.placeInto(target, value)
              fetch(url).flatMap {
                case Some((ms1, _))
                    if SqlInjectionCheck.confirmsTiming(baselineMs, ms1) =>
                  for
                    benign <- fetch(benignUrl)
                    injected <- fetch(url)
                  yield (benign, injected) match
                    case (Some((benignMs, _)), Some((ms2, _)))
                        if SqlInjectionCheck.confirmsTiming(benignMs, ms2) =>
                      Some(SqlInjectionCheck.timeFinding(point, label))
                    case _ => None
                case _ => Future.successful(None)
              }
          }
      }

  /** GET `url` (no redirect following), returning (elapsed ms, body). None on
    * any failure, so a failed request never fabricates a timing or error hit.
    */
  private def fetch(url: String)(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[Option[(Long, String)]] =
    val request = HttpRequest(
      method = HttpMethods.GET,
      uri = url,
      headers = List(headers.RawHeader("User-Agent", UserAgent)),
    )
    val start = System.nanoTime()
    ProbeHttp.send("sqli", request).flatMap { response =>
      Unmarshal(response.entity).to[String]
        .map(body => Some(((System.nanoTime() - start) / 1000000L, body)))
    }.recover { case t =>
      log.warn("SQLi probe error for {}: {}", url, t.getMessage)
      None
    }

  private def paramValue(url: String, name: String): String = Try {
    Option(new java.net.URI(url).getRawQuery).getOrElse("").split("&").iterator
      .map(_.split("=", 2)).collectFirst {
        case Array(k, v) if dec(k) == name => dec(v)
      }.getOrElse("")
  }.getOrElse("")

  private def dec(s: String): String =
    Try(URLDecoder.decode(s, StandardCharsets.UTF_8)).getOrElse(s)
