package dast.scan

import scala.concurrent.ExecutionContext
import scala.util.Failure
import scala.util.Success

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.actor.typed.scaladsl.ActorContext
import org.apache.pekko.actor.typed.scaladsl.Behaviors

import scala.concurrent.Future

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
      scan(ctx).onComplete {
        case Success(report) =>
          println(report)
          ctx.system.terminate()
        case Failure(e) =>
          ctx.log.error("Scan failed: {}", e.toString)
          ctx.system.terminate()
      }
      Behaviors.empty
    }
    ActorSystem[Nothing](guardian, systemName)
