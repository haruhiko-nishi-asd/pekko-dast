package dast.analyzer

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.slf4j.LoggerFactory

import dast.ClickStep
import dast.ClickTarget

/** The per-hop click planner: given the live page (its enumerated, indexed
  * clickable controls) and the history, the model chooses ONE control to click
  * (or done) via the forced tool ([[LlmClient]]).
  *
  * The model drives the trajectory but picks only an enumerated `data-dast-id`
  * — it never authors a selector or code. The destructive floor still applies
  * downstream in [[dast.ClickGuard]], so a model misjudgement cannot fire a
  * destructive control. Fails closed to [[ClickStep.Done]] (which ends the
  * loop). [[inputToStep]] is pure and unit tested; the transport is
  * [[LlmClient]].
  */
object ClickPlanner:

  private val log = LoggerFactory.getLogger("dast.analyzer.ClickPlanner")

  val ToolName = "choose_click"
  val MaxTokens = 512

  private val SystemPrompt = "You are the click-exploration step of a consented scan. From the current " +
    "authenticated page, choose ONE control to click to reveal new state " +
    "(open a menu, tab, accordion, or detail view), or scroll to load more " +
    "rows of a long/paginated list, or finish. Pick only the indexed controls " +
    "shown, by id. Never choose a control that creates, updates, deletes, " +
    "pays, or logs out. Choose done when nothing new remains. You never write " +
    "code."

  private val schema: ujson.Value = ujson.Obj(
    "type" -> "object",
    "properties" -> ujson.Obj(
      "action" ->
        ujson
          .Obj("type" -> "string", "enum" -> ujson.Arr("click", "scroll", "done")),
      "elementId" -> ujson.Obj("type" -> "integer"),
    ),
    "required" -> ujson.Arr("action"),
  )

  val Tool: ToolSpec =
    ToolSpec(ToolName, "Choose the next control to click.", schema)

  /** Map the tool input to a step, failing closed to `Done`. */
  def inputToStep(input: ujson.Value): ClickStep = ClickStep.parse(input)

  def plan(
      url: String,
      targets: Seq[ClickTarget],
      history: Seq[String],
      clicked: Seq[String],
  )(using ActorSystem[?], ExecutionContext): Future[ClickStep] = LlmClient
    .fromConfig.callTool(
      SystemPrompt,
      ClickStep.render(url, targets, history, clicked),
      Tool,
      MaxTokens,
    ).map { in =>
      val step = in.map(inputToStep).getOrElse(ClickStep.Done)
      log.info("Click planner step for {}: {}", url, step)
      step
    }
