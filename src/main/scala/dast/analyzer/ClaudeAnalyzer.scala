package dast.analyzer

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.slf4j.LoggerFactory

import dast.DecisionParser
import dast.LlmDecision

/** Turns an [[AnalyzerContext]] into one validated [[LlmDecision]] by forcing
  * the model to call the closed `decide` tool through [[LlmClient]] (the §0.2
  * boundary), then running its argument object through [[DecisionParser]] (the
  * authoritative validator that rejects anything off-menu).
  *
  * Fails closed: a missing key, transport error, missing tool call, or parse
  * failure all yield [[LlmDecision.Done]] (a no-op), never a guess.
  *
  * [[inputToDecision]] is pure and unit tested; the LLM transport lives in
  * [[LlmClient]]. Run [[analyze]] from an ordinary actor via `ctx.pipeToSelf`,
  * never on a pinned browser thread.
  */
object ClaudeAnalyzer:

  private val log = LoggerFactory.getLogger("dast.analyzer.ClaudeAnalyzer")

  val MaxTokens = 1024

  private val SystemPrompt = "You are the decision step of a consented DAST (dynamic application security " +
    "testing) scanner. Given the observed state of a page, select exactly one " +
    "next action by calling the `decide` tool. You never write or return code; " +
    "you only choose from the tool's menu. Prefer passive actions (navigate, " +
    "classify) and choose an active probe only when an injection point is " +
    "plausibly exploitable. When nothing useful remains, choose kind=done."

  /** The single forced tool: the closed `LlmDecision` schema. */
  val Tool: ToolSpec =
    val t = DecisionTool.tool
    ToolSpec(DecisionTool.Name, t("description").str, t("input_schema"))

  /** Map the tool's argument object to a decision, failing closed to `Done` via
    * the authoritative [[DecisionParser]].
    */
  def inputToDecision(input: ujson.Value): LlmDecision = DecisionParser
    .parse(ujson.write(input)).toOption.getOrElse(LlmDecision.Done)

  /** Call the configured LLM and return the decision. Never throws and never
    * blocks the caller; any failure resolves to `Done`.
    */
  def analyze(
      context: AnalyzerContext,
  )(using ActorSystem[?], ExecutionContext): Future[LlmDecision] =
    log.info("Analyzer prompt for {}:\n{}", context.url, context.render)
    LlmClient.fromConfig.callTool(SystemPrompt, context.render, Tool, MaxTokens)
      .map(_.map(inputToDecision).getOrElse(LlmDecision.Done))
