package dast.analyzer

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.slf4j.LoggerFactory

import dast.FormParse.FormInfo
import dast.NavStep

/** The per-hop navigation planner: given the current page (indexed forms +
  * links) and the history, the model chooses ONE next [[NavStep]] (follow a
  * link, submit a form, or done) via the forced tool ([[LlmClient]]).
  *
  * The model drives the trajectory (README navigation-action carve-out) but
  * picks only indexed elements -- it never authors a URL or code (§0.2). Fails
  * closed to [[NavStep.Done]] (which ends the loop).
  *
  * [[inputToStep]] is pure and unit tested; the transport lives in
  * [[LlmClient]].
  */
object NavStepPlanner:

  private val log = LoggerFactory.getLogger("dast.analyzer.NavStepPlanner")

  val ToolName = "choose_navigation_step"
  val MaxTokens = 512

  private val SystemPrompt =
    "You are the navigation step of a consented scan. From the current " +
      "authenticated page, choose ONE next action to reach pages that LIST " +
      "objects (search/filter/lookup results) so an IDOR check can run: follow " +
      "a link, submit a form, or finish. For a form, set safe=true only when " +
      "the submission is non-state-changing (a search/filter/lookup); never for " +
      "create/update/delete/pay/logout/email. Pick only the indexed elements " +
      "shown. Choose done when nothing new remains. You never write code."

  private val schema: ujson.Value = ujson.Obj(
    "type" -> "object",
    "properties" -> ujson.Obj(
      "action" -> ujson.Obj(
        "type" -> "string",
        "enum" -> ujson.Arr("follow", "submit", "done"),
      ),
      "linkIndex" -> ujson.Obj("type" -> "integer"),
      "formIndex" -> ujson.Obj("type" -> "integer"),
      "values" -> ujson.Obj("type" -> "object"),
      "safe" -> ujson.Obj("type" -> "boolean"),
    ),
    "required" -> ujson.Arr("action"),
  )

  val Tool: ToolSpec =
    ToolSpec(ToolName, "Choose the next navigation step.", schema)

  /** Map the tool input to a step, failing closed to `Done`. */
  def inputToStep(input: ujson.Value): NavStep = NavStep.parse(input)

  def plan(
      url: String,
      forms: Seq[FormInfo],
      links: Seq[String],
      history: Seq[String],
  )(using ActorSystem[?], ExecutionContext): Future[NavStep] = LlmClient
    .fromConfig.callTool(
      SystemPrompt,
      NavStep.render(url, forms, links, history),
      Tool,
      MaxTokens,
    ).map { in =>
      val step = in.map(inputToStep).getOrElse(NavStep.Done)
      log.info("Navigator step for {}: {}", url, step)
      step
    }
