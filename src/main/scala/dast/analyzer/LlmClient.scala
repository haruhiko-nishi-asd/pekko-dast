package dast.analyzer

import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.util.Try

import org.apache.pekko.actor.typed.ActorSystem
import org.apache.pekko.http.scaladsl.Http
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.unmarshalling.Unmarshal
import org.slf4j.LoggerFactory

import dast.DastConfig

/** A function the model is forced to call: a name, a description, and a
  * JSON-Schema object (the `{type:"object", properties, required}` shape)
  * describing its parameters. Provider-neutral; each [[LlmClient]] renders it
  * into its own wire format.
  */
final case class ToolSpec(name: String, description: String, schema: ujson.Value)

/** The single boundary between the scanner and any LLM (README): given a system
  * prompt and user content, force the model to call `tool` and return its raw
  * argument object. Deterministic code parses that object; the model never
  * authors executed code.
  *
  * Fail-closed: returns `None` (never throws) on a missing API key, transport
  * error, non-success status, or a response with no tool call, so every caller
  * degrades to a safe no-op.
  *
  * Implementations exist for Anthropic (default), OpenAI, and Gemini; pick one
  * with `DAST_LLM_PROVIDER`. The request builders and response extractors are
  * pure and unit tested; the HTTP call is exercised only live.
  */
trait LlmClient:
  def callTool(system: String, user: String, tool: ToolSpec, maxTokens: Int)(
      using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Option[ujson.Value]]

object LlmClient:

  private val log = LoggerFactory.getLogger("dast.analyzer.LlmClient")

  /** The configured client. `DAST_LLM_PROVIDER`: `anthropic` (default) |
    * `openai` | `gemini`.
    */
  def fromConfig: LlmClient = DastConfig.get("DAST_LLM_PROVIDER")
    .map(_.trim.toLowerCase) match
    case Some("openai") => OpenAiClient
    case Some("gemini") => GeminiClient
    case _ => AnthropicClient

  /** Shared transport + fail-closed wrapping: send `request`, and on a 2xx run
    * the provider's pure `extract` over the parsed JSON body. Any non-success,
    * transport error, or absent tool call resolves to `None`.
    */
  private[analyzer] def send(
      request: HttpRequest,
      extract: ujson.Value => Option[ujson.Value],
      provider: String,
  )(using
      system: ActorSystem[?],
      ec: ExecutionContext,
  ): Future[Option[ujson.Value]] = Http()(system).singleRequest(request).flatMap {
    response =>
      if response.status.isSuccess() then
        Unmarshal(response.entity).to[String].map { raw =>
          val out = Try(ujson.read(raw)).toOption.flatMap(extract)
          if out.isEmpty then
            log.warn("{}: no tool call in response: {}", provider, raw.take(500))
          out
        }
      else
        response.entity.discardBytes()
        log.warn("{} request failed: {}", provider, response.status)
        Future.successful(None)
  }.recover { case t =>
    log.warn("{} request error: {}", provider, t.getMessage)
    None
  }

/** Anthropic Messages API. The system prompt and tool are marked cache-friendly
  * (the static prefix every call shares).
  */
object AnthropicClient extends LlmClient:

  private val log = LoggerFactory.getLogger("dast.analyzer.AnthropicClient")

  val Endpoint = "https://api.anthropic.com/v1/messages"
  val Version = "2023-06-01"

  // Sonnet is the default: it catches the cross-account IDOR step (the hardest
  // judgment in a scan) at roughly a fifth of Opus's token cost, while the
  // cheaper Haiku tier was observed to miss it. Override with ANTHROPIC_MODEL
  // (e.g. claude-opus-4-8) for maximum reasoning, or a Haiku tier to minimise
  // cost on simpler targets.
  def model: String = DastConfig.get("ANTHROPIC_MODEL")
    .getOrElse("claude-sonnet-4-6")

  /** Pure: the Messages request body. No sampling/thinking params. */
  def requestBody(
      system: String,
      user: String,
      tool: ToolSpec,
      maxTokens: Int,
      model: String,
  ): ujson.Value =
    val ephemeral = ujson.Obj("type" -> "ephemeral")
    ujson.Obj(
      "model" -> model,
      "max_tokens" -> maxTokens,
      "system" -> ujson.Arr(
        ujson
          .Obj("type" -> "text", "text" -> system, "cache_control" -> ephemeral),
      ),
      "tools" -> ujson.Arr(ujson.Obj(
        "name" -> tool.name,
        "description" -> tool.description,
        "input_schema" -> tool.schema,
        "cache_control" -> ephemeral,
      )),
      "tool_choice" -> ujson.Obj("type" -> "tool", "name" -> tool.name),
      "messages" -> ujson.Arr(ujson.Obj("role" -> "user", "content" -> user)),
    )

  /** Pure: the forced tool's `input` from a Messages response, or None. */
  def toolInput(body: ujson.Value, toolName: String): Option[ujson.Value] = body
    .objOpt.flatMap(_.get("content")).flatMap(_.arrOpt).flatMap { blocks =>
      blocks.find(b =>
        b.objOpt.exists(o =>
          o.get("type").flatMap(_.strOpt).contains("tool_use") && o.get("name")
            .flatMap(_.strOpt).contains(toolName),
        ),
      )
    }.flatMap(_.objOpt.flatMap(_.get("input")))

  def callTool(system: String, user: String, tool: ToolSpec, maxTokens: Int)(
      using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Option[ujson.Value]] = DastConfig.get("ANTHROPIC_API_KEY") match
    case None =>
      log.warn("ANTHROPIC_API_KEY not set (env or .env); failing closed")
      Future.successful(None)
    case Some(apiKey) =>
      val request = HttpRequest(
        method = HttpMethods.POST,
        uri = Endpoint,
        headers = List(
          headers.RawHeader("x-api-key", apiKey),
          headers.RawHeader("anthropic-version", Version),
        ),
        entity = HttpEntity(
          ContentTypes.`application/json`,
          ujson.write(requestBody(system, user, tool, maxTokens, model)),
        ),
      )
      LlmClient.send(request, toolInput(_, tool.name), "Anthropic")

/** OpenAI Chat Completions API with function calling. */
object OpenAiClient extends LlmClient:

  private val log = LoggerFactory.getLogger("dast.analyzer.OpenAiClient")

  val Endpoint = "https://api.openai.com/v1/chat/completions"

  def model: String = DastConfig.get("OPENAI_MODEL").getOrElse("gpt-4o")

  /** Pure: the chat/completions request body forcing one function. */
  def requestBody(
      system: String,
      user: String,
      tool: ToolSpec,
      maxTokens: Int,
      model: String,
  ): ujson.Value = ujson.Obj(
    "model" -> model,
    "max_tokens" -> maxTokens,
    "messages" -> ujson.Arr(
      ujson.Obj("role" -> "system", "content" -> system),
      ujson.Obj("role" -> "user", "content" -> user),
    ),
    "tools" -> ujson.Arr(ujson.Obj(
      "type" -> "function",
      "function" -> ujson.Obj(
        "name" -> tool.name,
        "description" -> tool.description,
        "parameters" -> tool.schema,
      ),
    )),
    "tool_choice" ->
      ujson
        .Obj("type" -> "function", "function" -> ujson.Obj("name" -> tool.name)),
  )

  /** Pure: the first tool call's `arguments` (a JSON string) parsed to an
    * object, or None.
    */
  def toolInput(body: ujson.Value, toolName: String): Option[ujson.Value] = body
    .objOpt.flatMap(_.get("choices")).flatMap(_.arrOpt).flatMap(_.headOption)
    .flatMap(_.objOpt.flatMap(_.get("message")))
    .flatMap(_.objOpt.flatMap(_.get("tool_calls"))).flatMap(_.arrOpt)
    .flatMap(_.headOption).flatMap(_.objOpt.flatMap(_.get("function")))
    .flatMap(_.objOpt.flatMap(_.get("arguments"))).flatMap(_.strOpt)
    .flatMap(s => Try(ujson.read(s)).toOption)

  def callTool(system: String, user: String, tool: ToolSpec, maxTokens: Int)(
      using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Option[ujson.Value]] = DastConfig.get("OPENAI_API_KEY") match
    case None =>
      log.warn("OPENAI_API_KEY not set (env or .env); failing closed")
      Future.successful(None)
    case Some(apiKey) =>
      val request = HttpRequest(
        method = HttpMethods.POST,
        uri = Endpoint,
        headers = List(headers.RawHeader("Authorization", s"Bearer $apiKey")),
        entity = HttpEntity(
          ContentTypes.`application/json`,
          ujson.write(requestBody(system, user, tool, maxTokens, model)),
        ),
      )
      LlmClient.send(request, toolInput(_, tool.name), "OpenAI")

/** Google Gemini generateContent API with function declarations. */
object GeminiClient extends LlmClient:

  private val log = LoggerFactory.getLogger("dast.analyzer.GeminiClient")

  /** Reasoning ("thinking") models spend output tokens before emitting the
    * forced function call, and those `thoughtsTokenCount` tokens count against
    * `maxOutputTokens`. With a small ceiling the budget is spent thinking first
    * (`finishReason: MAX_TOKENS`, empty content, no tool call). So we bound
    * thinking to a fixed budget and raise the ceiling to cover it PLUS the
    * caller's tokens, guaranteeing the tool call fits. Version-agnostic: on
    * non-thinking models `thinkingConfig` is ignored, so this is a safe no-op.
    */
  private val ThinkingBudget = 2048

  def model: String = DastConfig.get("GEMINI_MODEL")
    .getOrElse("gemini-2.0-flash")

  def endpoint(model: String, apiKey: String): String =
    s"https://generativelanguage.googleapis.com/v1beta/models/$model:generateContent?key=$apiKey"

  /** Pure: the generateContent request body forcing one function. */
  def requestBody(
      system: String,
      user: String,
      tool: ToolSpec,
      maxTokens: Int,
  ): ujson.Value = ujson.Obj(
    "systemInstruction" ->
      ujson.Obj("parts" -> ujson.Arr(ujson.Obj("text" -> system))),
    "contents" -> ujson.Arr(
      ujson.Obj("role" -> "user", "parts" -> ujson.Arr(ujson.Obj("text" -> user))),
    ),
    "tools" -> ujson.Arr(ujson.Obj(
      "functionDeclarations" -> ujson.Arr(ujson.Obj(
        "name" -> tool.name,
        "description" -> tool.description,
        "parameters" -> tool.schema,
      )),
    )),
    "toolConfig" -> ujson.Obj(
      "functionCallingConfig" ->
        ujson.Obj("mode" -> "ANY", "allowedFunctionNames" -> ujson.Arr(tool.name)),
    ),
    "generationConfig" -> ujson.Obj(
      // Headroom for thinking + the tool call (see ThinkingBudget).
      "maxOutputTokens" -> (maxTokens + ThinkingBudget),
      "thinkingConfig" -> ujson.Obj("thinkingBudget" -> ThinkingBudget),
    ),
  )

  /** Pure: the first part's `functionCall.args` object, or None. */
  def toolInput(body: ujson.Value, toolName: String): Option[ujson.Value] = body
    .objOpt.flatMap(_.get("candidates")).flatMap(_.arrOpt).flatMap(_.headOption)
    .flatMap(_.objOpt.flatMap(_.get("content")))
    .flatMap(_.objOpt.flatMap(_.get("parts"))).flatMap(_.arrOpt)
    .flatMap { parts =>
      parts.flatMap(_.objOpt.flatMap(_.get("functionCall"))).headOption
    }.flatMap(_.objOpt.flatMap(_.get("args")))

  def callTool(system: String, user: String, tool: ToolSpec, maxTokens: Int)(
      using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Option[ujson.Value]] = DastConfig.get("GEMINI_API_KEY") match
    case None =>
      log.warn("GEMINI_API_KEY not set (env or .env); failing closed")
      Future.successful(None)
    case Some(apiKey) =>
      val request = HttpRequest(
        method = HttpMethods.POST,
        uri = endpoint(model, apiKey),
        entity = HttpEntity(
          ContentTypes.`application/json`,
          ujson.write(requestBody(system, user, tool, maxTokens)),
        ),
      )
      LlmClient.send(request, toolInput(_, tool.name), "Gemini")
