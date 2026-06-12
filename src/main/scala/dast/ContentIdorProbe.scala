package dast

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.unmarshalling.Unmarshal
import org.slf4j.LoggerFactory

import dast.ContentIdor.Proposal

/** Browser-free probe that runs [[ContentIdor]] proposals as the authenticated
  * caller and confirms IDOR by cross-user diff: baseline the caller's own id,
  * then for each candidate id check whether the response is a 2xx whose
  * discriminator field is present and DIFFERENT from the caller's own (so a
  * record that isn't theirs came back). Reuses [[IdorPlan.extractField]] /
  * [[IdorPlan.confirms]]. Gated by [[ConsentGate]]; throttled; uses the
  * post-login session cookie. HTTP is live-only.
  */
object ContentIdorProbe:

  private val log = LoggerFactory.getLogger("dast.ContentIdorProbe")

  private val UserAgent =
    "pekko-dast-scanner/0.1 (+authorized security testing)"

  /** `markers` are model-free leak tokens harvested from the OTHER account's
    * content (see [[ContentIdor.markersFrom]]); they back up the model's `leak`
    * so recall does not depend on the model naming the right data string.
    */
  def run(
      proposals: Seq[Proposal],
      cookie: Option[String],
      auth: Authorization,
      markers: Seq[String] = Nil,
  )(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[Vector[Finding]] = Future.sequence(proposals.map(p =>
    probe(p, cookie, auth, markers).map { result =>
      result match
        case Some(f) => log.info("IDOR CONFIRMED: {}", f.evidence)
        case None => log.info(
            "IDOR not confirmed: {} {} (own={}, candidates=[{}], field={})",
            p.method,
            p.urlTemplate,
            p.ownValue,
            p.candidates.mkString(", "),
            p.discriminatorField,
          )
      EvidenceLog.decision(
        "idor",
        s"${p.method} ${p.urlTemplate}",
        s"candidates=[${p.candidates.mkString(",")}] field=${p
            .discriminatorField}",
        result.isDefined,
      )
      result
    },
  )).map(_.flatten.toVector)

  private def probe(
      p: Proposal,
      cookie: Option[String],
      auth: Authorization,
      markers: Seq[String],
  )(using ActorSystem[?], ExecutionContext): Future[Option[Finding]] =
    val baselineUrl = ContentIdor.fill(p.urlTemplate, p.ownValue)
    ConsentGate.decide(auth, ActionClass.Active, baselineUrl) match
      case GateDecision.Deny(reason) =>
        log.info("IDOR test skipped ({}): {}", baselineUrl, reason)
        Future.successful(None)
      case GateDecision.Permit => fetch(p, p.ownValue, cookie, auth).flatMap {
          case Some((s, body)) if s >= 200 && s <= 299 =>
            // Leak markers (work on HTML): the model's data leak plus tokens
            // harvested deterministically from the OTHER account's content.
            // Drop any that is an id in play (ids echo, proving nothing).
            val leakMarkers = (ContentIdor.dataLeak(p).toSeq ++ markers)
              .distinct.filter(m => m != p.ownValue && !p.candidates.contains(m))
            // JSON field: the per-user field differing from this baseline.
            val fieldDiff: Future[Option[Finding]] =
              IdorPlan.extractField(body, p.discriminatorField) match
                case None => Future.successful(None)
                case Some(own) => firstHit(p, own, cookie, auth)
            // Leak markers are best-effort and noisy (the model may name a
            // non-distinctive token, e.g. a field NAME present in every
            // response); a leak miss must NOT suppress the sound field-diff
            // path, so fall through to it when no marker confirms.
            if leakMarkers.nonEmpty then
              firstHitLeak(p, body, leakMarkers, cookie, auth).flatMap {
                case found @ Some(_) => Future.successful(found)
                case None => fieldDiff
              }
            else fieldDiff
          case _ => Future.successful(None)
        }

  private def firstHitLeak(
      p: Proposal,
      ownBody: String,
      markers: Seq[String],
      cookie: Option[String],
      auth: Authorization,
  )(using ActorSystem[?], ExecutionContext): Future[Option[Finding]] = p
    .candidates
    .foldLeft(Future.successful(Option.empty[Finding])) { (acc, candidate) =>
      acc.flatMap {
        case some @ Some(_) => Future.successful(some)
        case None => fetch(p, candidate, cookie, auth).map {
            case Some((s, body)) if s >= 200 && s <= 299 =>
              markers.find(m => ContentIdor.confirmsLeak(ownBody, body, m))
                .map(m => ContentIdor.leakFinding(p, candidate, m))
            case _ => None
          }
      }
    }

  private def firstHit(
      p: Proposal,
      ownValue: String,
      cookie: Option[String],
      auth: Authorization,
  )(using ActorSystem[?], ExecutionContext): Future[Option[Finding]] = p
    .candidates
    .foldLeft(Future.successful(Option.empty[Finding])) { (acc, candidate) =>
      acc.flatMap {
        case some @ Some(_) => Future.successful(some)
        case None => fetch(p, candidate, cookie, auth).flatMap {
            case Some((s, body))
                if IdorPlan.confirms(
                  ownValue,
                  candidate,
                  s,
                  body,
                  p.discriminatorField,
                ) =>
              // Re-fetch and require the discriminator value to be stable, so a
              // volatile per-request field cannot false-confirm.
              fetch(p, candidate, cookie, auth).map {
                case Some((_, body2))
                    if IdorPlan
                      .stableField(body, body2, p.discriminatorField) =>
                  val leaked = IdorPlan.extractField(body, p.discriminatorField)
                    .getOrElse("")
                  Some(ContentIdor.toFinding(p, candidate, leaked))
                case _ => None
              }
            case _ => Future.successful(None)
          }
      }
    }

  /** Issue one request for a filled-in id. Every candidate URL re-clears the
    * consent gate: the template is model-authored (a prompt-injected page could
    * steer it), so gating only the baseline would let a candidate id whose host
    * differs from the baseline's escape scope. Off-scope or non-2xx -> None, so
    * a denied or failed request never fabricates a finding.
    */
  private def fetch(
      p: Proposal,
      id: String,
      cookie: Option[String],
      auth: Authorization,
  )(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[Option[(Int, String)]] =
    val url = ContentIdor.fill(p.urlTemplate, id)
    ConsentGate.decide(auth, ActionClass.Active, url) match
      case GateDecision.Deny(reason) =>
        log.info("IDOR candidate skipped ({}): {}", url, reason)
        Future.successful(None)
      case GateDecision.Permit =>
        val hs = headers.RawHeader("User-Agent", UserAgent) ::
          cookie.map(c => headers.RawHeader("Cookie", c)).toList
        val request =
          if p.isPost then
            HttpRequest(
              method = HttpMethods.POST,
              uri = url,
              headers = hs,
              entity = HttpEntity(
                ContentTypes.`application/x-www-form-urlencoded`,
                p.bodyTemplate.map(b => ContentIdor.fill(b, id)).getOrElse(""),
              ),
            )
          else HttpRequest(HttpMethods.GET, url, hs)
        ProbeHttp.send("content-idor", request).flatMap { response =>
          Unmarshal(response.entity).to[String]
            .map(body => Some((response.status.intValue(), body)))
        }.recover { case t =>
          log.warn("IDOR probe error: {}", t.getMessage)
          None
        }
