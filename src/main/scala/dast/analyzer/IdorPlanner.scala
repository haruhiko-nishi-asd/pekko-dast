package dast.analyzer

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.slf4j.LoggerFactory

import dast.IdorPlan
import dast.IdorPlan.Observation
import dast.IdorPlan.Proposal

/** The LLM planning step for IDOR: turn an [[Observation]] of an authenticated
  * page into proposed access-control tests via the forced tool ([[LlmClient]],
  * the §0.2 boundary).
  *
  * This is where the model earns its place: it reasons about which parameter is
  * an object reference, which neighbours are worth trying, and which response
  * field is per-user. It supplies only those parameters;
  * [[IdorPlan.parseProposals]] validates them and deterministic code
  * ([[dast.IdorProbe]]) confirms. Fails closed to an empty plan.
  *
  * [[inputToProposals]] is pure and unit tested; the transport lives in
  * [[LlmClient]].
  */
object IdorPlanner:

  private val log = LoggerFactory.getLogger("dast.analyzer.IdorPlanner")

  val ToolName = "propose_idor_tests"
  val MaxTokens = 1024

  private val SystemPrompt = "You are the planning step of a consented IDOR (insecure direct object " +
    "reference) check. Given an authenticated page, its query parameters with " +
    "current values, and the response's JSON field names, propose access-" +
    "control tests by calling the tool. For each parameter that looks like an " +
    "object reference (an id, account, order, user, etc.), give: the caller's " +
    "own current value, a few neighbour values to try (e.g. nearby ids), and " +
    "the response field that is per-user and would reveal another user's " +
    "record if it changed. Propose an empty list when no parameter is an " +
    "object reference. You never write code; you only fill the tool's fields."

  private val schema: ujson.Value = ujson.Obj(
    "type" -> "object",
    "properties" -> ujson.Obj(
      "proposals" -> ujson.Obj(
        "type" -> "array",
        "items" -> ujson.Obj(
          "type" -> "object",
          "properties" -> ujson.Obj(
            "param" -> ujson.Obj("type" -> "string"),
            "ownValue" -> ujson.Obj("type" -> "string"),
            "candidates" ->
              ujson
                .Obj("type" -> "array", "items" -> ujson.Obj("type" -> "string")),
            "discriminatorField" -> ujson.Obj("type" -> "string"),
          ),
          "required" ->
            ujson.Arr("param", "ownValue", "candidates", "discriminatorField"),
        ),
      ),
    ),
    "required" -> ujson.Arr("proposals"),
  )

  val Tool: ToolSpec = ToolSpec(
    ToolName,
    "Propose IDOR tests for an authenticated page (or an empty list).",
    schema,
  )

  /** Pull the tool input's `proposals` and validate, failing closed. */
  def inputToProposals(input: ujson.Value): Seq[Proposal] = input.objOpt
    .flatMap(_.get("proposals")).map(IdorPlan.parseProposals)
    .getOrElse(Seq.empty)

  /** Call the configured LLM for a plan. Never throws; any failure -> no plan.
    */
  def plan(
      obs: Observation,
  )(using ActorSystem[?], ExecutionContext): Future[Seq[Proposal]] =
    log.info("Planning IDOR for {}", obs.url)
    LlmClient.fromConfig.callTool(SystemPrompt, obs.render, Tool, MaxTokens)
      .map(_.map(inputToProposals).getOrElse(Seq.empty))
