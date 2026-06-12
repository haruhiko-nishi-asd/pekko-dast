package dast.scan

import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.util.Failure
import scala.util.Success

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.scaladsl.ActorContext
import org.apache.pekko.actor.typed.scaladsl.Behaviors

/** Hosts a one-shot scan in a throwaway typed `ActorSystem`, prints the report
  * it renders, and terminates the system.
  *
  * The scanners themselves are plain `Future`-returning methods; an
  * `ActorSystem` is still needed (Pekko HTTP and the browser pool require one),
  * so this centralises that lifecycle. Each `*Main` is then just argument
  * parsing plus the scan call — no per-main `Behavior` / message protocol.
  */
object ScanMain:

  /** Run `scan` (given the guardian's context) and print the report string it
    * produces, then terminate. A failure is logged and still terminates
    * cleanly.
    */
  def run(systemName: String)(
      scan: ActorContext[Nothing] => Future[String],
  ): Unit =
    val guardian = Behaviors.setup[Nothing] { ctx =>
      given ExecutionContext = ctx.executionContext
      scan(ctx).onComplete { result =>
        // Persist the evidence transcript (no-op unless DAST_EVIDENCE_FILE set).
        dast.EvidenceLog.flush()
        result match
          case Success(report) =>
            println(report)
            // Self-contained HTML view (no-op unless DAST_REPORT_FILE set).
            writeHtmlReport(report)
            // Agent-ready remediation brief (no-op unless DAST_REMEDIATION_FILE
            // set).
            writeRemediationReport(report)
          case Failure(e) => ctx.log.error("Scan failed: {}", e.toString)
        ctx.system.terminate()
      }
      Behaviors.empty
    }
    ActorSystem[Nothing](guardian, systemName)

  /** Write a self-contained HTML view of the run to `DAST_REPORT_FILE`, pairing
    * the findings with the in-memory evidence transcript. Best-effort and off
    * by default -- no file, no cost, unless the var is set.
    */
  private def writeHtmlReport(reportJson: String): Unit = dast.DastConfig
    .get("DAST_REPORT_FILE").filter(_.nonEmpty).foreach { path =>
      try
        val report = ujson.read(reportJson)
        val evidence = dast.EvidenceLog.render().linesIterator.filter(_.nonEmpty)
          .map(ujson.read(_)).toSeq
        java.nio.file.Files.writeString(
          java.nio.file.Paths.get(path),
          ReportHtml.render(report, evidence),
        )
      catch { case _: Exception => () }
    }

  /** Write a Markdown remediation brief (an instruction set for a coding agent
    * to patch the findings) to `DAST_REMEDIATION_FILE`. Best-effort and off by
    * default -- no file, no cost, unless the var is set.
    */
  private def writeRemediationReport(reportJson: String): Unit = dast.DastConfig
    .get("DAST_REMEDIATION_FILE").filter(_.nonEmpty).foreach { path =>
      try java.nio.file.Files.writeString(
          java.nio.file.Paths.get(path),
          RemediationReport.render(ujson.read(reportJson)),
        )
      catch { case _: Exception => () }
    }
