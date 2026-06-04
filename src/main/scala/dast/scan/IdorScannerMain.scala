package dast.scan

import scala.concurrent.ExecutionContext
import scala.util.Try

import org.apache.pekko.actor.typed.ActorSystem

import dast.AccessControlCheck
import dast.AccessControlCheck.Identity
import dast.Authorization
import dast.DastConfig

/** Runnable LLM-planned IDOR scanner.
  *
  * Takes a URL and an identity spec (the same JSON as [[AccessScannerMain]];
  * the first identity is used for the authenticated session). The model
  * proposes IDOR tests from the observed page; deterministic code confirms by
  * cross-value comparison. Active by nature, gated against
  * `DAST_AUTHORIZED_HOSTS`. Needs `ANTHROPIC_API_KEY` for the planner (fails
  * closed to no plan otherwise).
  *
  * Usage: sbt "runMain dast.scan.IdorScannerMain <url> <identity-spec.json>"
  */
object IdorScannerMain:

  def main(args: Array[String]): Unit =
    val url = args.headOption.filter(_.nonEmpty)
    val specPath = args.drop(1).headOption.filter(_.nonEmpty)
      .orElse(DastConfig.get("DAST_ACCESS_SPEC"))
    (url, specPath) match
      case (Some(target), Some(path)) => loadIdentity(path) match
          case Left(err) =>
            Console.err.println(err)
            sys.exit(2)
          case Right(identity) => run(target, identity)
      case _ =>
        Console.err.println("usage: IdorScannerMain <url> <identity-spec.json>")
        sys.exit(2)

  private def run(url: String, identity: Identity): Unit = ScanMain
    .run("dast-idor-scanner") { ctx =>
      given ActorSystem[?] = ctx.system
      given ExecutionContext = ctx.executionContext
      val auth = authorization
      ctx.log.info(
        "IDOR scan from {} (active scope: {}, maxPages={}, maxDepth={})",
        url,
        if auth.allowActive then auth.authorizedHosts.mkString(",")
        else "observe-only (skipped)",
        maxPages,
        maxDepth,
      )
      Scanner.runIdor(
        ctx,
        url,
        identity,
        auth,
        navTimeoutMs,
        maxDepth,
        maxPages,
        maxHops,
        postBudget,
      ).map(fs => FindingsReport.render(url, fs))
    }

  private def loadIdentity(path: String): Either[String, Identity] = Try {
    val src = scala.io.Source.fromFile(path, "UTF-8")
    try src.mkString
    finally src.close()
  }.toEither.left.map(e => s"cannot read spec '$path': ${e.getMessage}")
    .flatMap(AccessControlCheck.parseSpec(_).left.map(e => s"invalid spec: $e"))
    .flatMap(_.identities.values.headOption.toRight("spec has no identities"))

  private def navTimeoutMs: Int = DastConfig.getInt("DAST_NAV_TIMEOUT_MS", 30000)
  private def maxDepth: Int = DastConfig.getInt("DAST_MAX_DEPTH", 2)
  private def maxPages: Int = DastConfig.getInt("DAST_MAX_PAGES", 20)
  private def maxHops: Int = DastConfig.getInt("DAST_MAX_HOPS", 4)
  private def postBudget: Int = DastConfig.getInt("DAST_POST_BUDGET", 3)

  private def authorization: Authorization = DastConfig
    .get("DAST_AUTHORIZED_HOSTS") match
    case Some(hosts) => Authorization
        .active(hosts.split(",").map(_.trim).toIndexedSeq*)
    case None => Authorization.ObserveOnly
