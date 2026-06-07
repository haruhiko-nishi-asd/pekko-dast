package dast.analyzer

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ContentIdorPlannerSpec extends AnyWordSpec with Matchers {

  "ContentIdorPlanner.fieldsFromResponses" should {
    "extract top-level JSON field names per endpoint, never values" in {
      val resps = Seq(
        "/api/me" -> """{"id":7,"email":"a@b.com","role":"admin"}""",
        "/api/orders" -> """[{"orderId":1,"ownerId":42}]""",
      )
      val fields = ContentIdorPlanner.fieldsFromResponses(resps)
      fields shouldBe Seq(
        "/api/me" -> Seq("id", "email", "role"),
        "/api/orders" -> Seq("orderId", "ownerId"),
      )
      // Values must not leak into the names channel.
      fields.flatMap(_._2) should not contain "a@b.com"
      fields.flatMap(_._2) should not contain "admin"
    }

    "drop endpoints whose body is not parseable JSON or carries no fields" in {
      ContentIdorPlanner.fieldsFromResponses(Seq(
        "/x" -> "not json",
        "/y" -> "[]",
        "/z" -> "42",
      )) shouldBe empty
    }

    "keep the first occurrence per url" in {
      val resps = Seq(
        "/api/me" -> """{"id":1}""",
        "/api/me" -> """{"id":2,"name":"x"}""",
      )
      ContentIdorPlanner.fieldsFromResponses(resps) shouldBe
        Seq("/api/me" -> Seq("id"))
    }
  }

  "ContentIdorPlanner.renderRespFields" should {
    "render names per endpoint and empty string for no fields" in {
      ContentIdorPlanner.renderRespFields(Seq.empty) shouldBe ""
      val out = ContentIdorPlanner
        .renderRespFields(Seq("/api/me" -> Seq("id", "role")))
      out should include("Response fields (names only):")
      out should include("/api/me: id, role")
    }
  }

  "ContentIdorPlanner.renderContext" should {
    "append the response-field block after the requests" in {
      val out = ContentIdorPlanner.renderContext(
        pages = Seq("https://h/p" -> "<html/>"),
        requests = Seq("https://h/api/me"),
        responseFields = Seq("https://h/api/me" -> Seq("id", "role")),
      )
      out should include("Observed requests:")
      out should include("Response fields (names only):")
      out should include("https://h/api/me: id, role")
      out should include("Authenticated pages:")
    }
  }
}
