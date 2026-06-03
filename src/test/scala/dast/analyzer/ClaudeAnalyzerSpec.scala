package dast.analyzer

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import dast.LlmDecision.*
import dast.PayloadLibrary

class ClaudeAnalyzerSpec extends AnyWordSpec with Matchers {

  "ClaudeAnalyzer.Tool" should {

    "force the decide tool" in { ClaudeAnalyzer.Tool.name shouldBe "decide" }

    "constrain payloadId to the audited library" in {
      val enumValues = ClaudeAnalyzer.Tool
        .schema("properties")("payloadId")("enum").arr.map(_.str).toSet
      enumValues shouldBe PayloadLibrary.ids
    }
  }

  "ClaudeAnalyzer.inputToDecision" should {

    "map a valid decide input to the decision" in {
      val input = ujson.Obj(
        "kind" -> "probe",
        "injectionPointId" -> "q",
        "payloadId" -> "img-onerror",
      )
      ClaudeAnalyzer.inputToDecision(input) shouldBe Probe("q", "img-onerror")
    }

    "fail closed to Done on an off-menu payloadId" in {
      val input = ujson.Obj(
        "kind" -> "probe",
        "injectionPointId" -> "q",
        "payloadId" -> "rm -rf",
      )
      ClaudeAnalyzer.inputToDecision(input) shouldBe Done
    }

    "fail closed to Done on a malformed input" in {
      ClaudeAnalyzer.inputToDecision(ujson.Obj()) shouldBe Done
    }
  }
}
