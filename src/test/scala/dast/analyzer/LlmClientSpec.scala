package dast.analyzer

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Pure request-builder and response-extractor tests for each provider client.
  * The HTTP call (`callTool`) is exercised only live.
  */
class LlmClientSpec extends AnyWordSpec with Matchers {

  private val tool = ToolSpec(
    "propose",
    "desc",
    ujson.Obj(
      "type" -> "object",
      "properties" -> ujson.Obj("x" -> ujson.Obj("type" -> "string")),
    ),
  )

  "AnthropicClient.requestBody" should {
    val body = AnthropicClient.requestBody("sys", "user", tool, 1024, "claude-x")

    "force the tool and send no sampling or thinking params" in {
      body("tool_choice")("type").str shouldBe "tool"
      body("tool_choice")("name").str shouldBe "propose"
      body.obj.contains("temperature") shouldBe false
      body.obj.contains("thinking") shouldBe false
      body("model").str shouldBe "claude-x"
    }

    "mark the static prefix (system + tool) cache-friendly" in {
      body("system")(0).obj.contains("cache_control") shouldBe true
      body("tools")(0).obj.contains("cache_control") shouldBe true
    }

    "carry the tool schema" in {
      body("tools")(0)("input_schema")("properties")("x")("type").str shouldBe
        "string"
    }
  }

  "AnthropicClient.toolInput" should {
    def toolUse(input: ujson.Value): ujson.Value = ujson
      .Obj("type" -> "tool_use", "name" -> "propose", "input" -> input)
    def resp(blocks: ujson.Value*): ujson.Value = ujson
      .Obj("content" -> ujson.Arr(blocks*))

    "extract the forced tool's input" in {
      AnthropicClient.toolInput(resp(toolUse(ujson.Obj("k" -> 1))), "propose")
        .map(_("k").num) shouldBe Some(1.0)
    }
    "return None when there is no tool_use block" in {
      AnthropicClient.toolInput(
        resp(ujson.Obj("type" -> "text", "text" -> "hi")),
        "propose",
      ) shouldBe None
    }
    "return None for a wrong tool name" in {
      AnthropicClient
        .toolInput(resp(toolUse(ujson.Obj("k" -> 1))), "other") shouldBe None
    }
    "return None on a malformed body" in {
      AnthropicClient.toolInput(ujson.Obj(), "propose") shouldBe None
    }
  }

  "OpenAiClient.requestBody" should {
    val body = OpenAiClient.requestBody("sys", "user", tool, 1024, "gpt-x")

    "force the function by name" in {
      body("tools")(0)("type").str shouldBe "function"
      body("tools")(0)("function")("name").str shouldBe "propose"
      body("tool_choice")("function")("name").str shouldBe "propose"
    }
    "send system then user messages" in {
      body("messages")(0)("role").str shouldBe "system"
      body("messages")(1)("role").str shouldBe "user"
    }
  }

  "OpenAiClient.toolInput" should {
    "parse the first tool call's stringified arguments" in {
      val resp = ujson.Obj(
        "choices" -> ujson.Arr(ujson.Obj(
          "message" -> ujson.Obj(
            "tool_calls" -> ujson.Arr(ujson.Obj(
              "function" ->
                ujson
                  .Obj("name" -> "propose", "arguments" -> "{\"proposals\":[]}"),
            )),
          ),
        )),
      )
      OpenAiClient.toolInput(resp, "propose")
        .map(_("proposals").arr.size) shouldBe Some(0)
    }
    "return None when there are no tool calls" in {
      val resp = ujson.Obj(
        "choices" ->
          ujson.Arr(ujson.Obj("message" -> ujson.Obj("content" -> "hi"))),
      )
      OpenAiClient.toolInput(resp, "propose") shouldBe None
    }
    "return None on unparseable arguments" in {
      val resp = ujson.Obj(
        "choices" -> ujson.Arr(ujson.Obj(
          "message" -> ujson.Obj(
            "tool_calls" -> ujson.Arr(ujson.Obj(
              "function" ->
                ujson.Obj("name" -> "propose", "arguments" -> "not json"),
            )),
          ),
        )),
      )
      OpenAiClient.toolInput(resp, "propose") shouldBe None
    }
  }

  "GeminiClient.requestBody" should {
    val body = GeminiClient.requestBody("sys", "user", tool, 1024)

    "declare the function and force it" in {
      body("tools")(0)("functionDeclarations")(0)("name").str shouldBe "propose"
      body("toolConfig")("functionCallingConfig")("mode").str shouldBe "ANY"
      body("toolConfig")("functionCallingConfig")("allowedFunctionNames")(0)
        .str shouldBe "propose"
    }
    "carry the system prompt and user content" in {
      body("systemInstruction")("parts")(0)("text").str shouldBe "sys"
      body("contents")(0)("parts")(0)("text").str shouldBe "user"
    }
    "bound thinking and size the ceiling so the tool call fits (thinking models)" in {
      val cfg = body("generationConfig")
      // Ceiling must exceed the caller's tokens by the thinking budget, so a
      // reasoning model can't exhaust it before emitting the forced call.
      cfg("maxOutputTokens").num.toInt should be > 1024
      cfg("thinkingConfig")("thinkingBudget").num.toInt should be > 0
      cfg("maxOutputTokens").num.toInt shouldBe
        (1024 + cfg("thinkingConfig")("thinkingBudget").num.toInt)
    }
  }

  "GeminiClient.toolInput" should {
    "extract the first functionCall args" in {
      val resp = ujson.Obj(
        "candidates" -> ujson.Arr(ujson.Obj(
          "content" -> ujson.Obj(
            "parts" -> ujson.Arr(ujson.Obj(
              "functionCall" -> ujson.Obj(
                "name" -> "propose",
                "args" -> ujson.Obj("proposals" -> ujson.Arr()),
              ),
            )),
          ),
        )),
      )
      GeminiClient.toolInput(resp, "propose")
        .map(_("proposals").arr.size) shouldBe Some(0)
    }
    "return None when there is no functionCall part" in {
      val resp = ujson.Obj(
        "candidates" -> ujson.Arr(ujson.Obj(
          "content" -> ujson.Obj("parts" -> ujson.Arr(ujson.Obj("text" -> "hi"))),
        )),
      )
      GeminiClient.toolInput(resp, "propose") shouldBe None
    }
  }
}
