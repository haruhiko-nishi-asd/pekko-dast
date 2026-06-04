package dast.scan

import scala.concurrent.ExecutionContext
import scala.util.Try

import org.apache.pekko.actor.typed.ActorSystem

import dast.AccessControlCheck
import dast.AccessControlCheck.AccessSpec
import dast.Authorization
import dast.DastConfig

/** Runnable, spec-driven access-control / IDOR scanner.
  *
  * Reads a JSON spec (path arg, or `DAST_ACCESS_SPEC`) describing captured
  * identities and assertion cases, then runs [[AccessControlProbe]] and prints
  * a findings report. Active by nature, so every case is gated against
  * `DAST_AUTHORIZED_HOSTS`; with none set, all cases are skipped
  * (observe-only). Wiring around tested components; exercised only by a live
  * run.
  *
  * Usage: sbt "runMain dast.scan.AccessScannerMain access-spec.json"
  */
object AccessScannerMain:

  def main(args: Array[String]): Unit = args.headOption.filter(_.nonEmpty)
    .orElse(DastConfig.get("DAST_ACCESS_SPEC")) match
    case None =>
      Console.err.println("usage: AccessScannerMain <spec.json>")
      sys.exit(2)
    case Some(path) => readFile(path)
        .flatMap(AccessControlCheck.parseSpec) match
        case Left(err) =>
          Console.err.println(s"cannot use spec '$path': $err")
          sys.exit(2)
        case Right(spec) => run(spec)

  private def run(spec: AccessSpec): Unit = ScanMain
    .run("dast-access-scanner") { ctx =>
      given ActorSystem[?] = ctx.system
      given ExecutionContext = ctx.executionContext
      val auth = authorization
      val logins = spec.identities.values.count(_.login.isDefined)
      ctx.log.info(
        "Access-control scan: {} case(s), {} login(s), active scope: {}",
        spec.cases.size,
        logins,
        if auth.allowActive then auth.authorizedHosts.mkString(",")
        else "observe-only (all cases skipped)",
      )
      Scanner.runAccess(ctx, spec, auth, navTimeoutMs)
        .map(fs => FindingsReport.render("access-control", fs))
    }

  private def navTimeoutMs: Int = DastConfig.getInt("DAST_NAV_TIMEOUT_MS", 30000)

  private def authorization: Authorization = DastConfig
    .get("DAST_AUTHORIZED_HOSTS") match
    case Some(hosts) => Authorization
        .active(hosts.split(",").map(_.trim).toIndexedSeq*)
    case None => Authorization.ObserveOnly

  private def readFile(path: String): Either[String, String] = Try {
    val src = scala.io.Source.fromFile(path, "UTF-8")
    try src.mkString
    finally src.close()
  }.toEither.left.map(e =>
    s"cannot read spec '$path': ${Option(e.getMessage).getOrElse(e.toString)}",
  )
