package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class SstiCheckSpec extends AnyWordSpec with Matchers {

  "SstiCheck.confirms" should {

    "confirm when the evaluated product is present and the raw expression is not" in {
      SstiCheck.confirms(
        baselineBody = "<p>hello</p>",
        injectedBody = s"<p>${SstiCheck.product}</p>",
      ) shouldBe true
    }

    "reject reflection: the raw expression echoed back is not evaluation" in {
      SstiCheck.confirms("<p>hi</p>", s"<p>${SstiCheck.expr}</p>") shouldBe
        false
    }

    "reject when the product was already present in the baseline" in {
      val body = s"order total ${SstiCheck.product}"
      SstiCheck.confirms(baselineBody = body, injectedBody = body) shouldBe
        false
    }
  }

  "SstiCheck.payloads" should {
    "cover the common engine syntaxes" in {
      val ps = SstiCheck.payloads
      ps should contain("{{" + SstiCheck.expr + "}}")
      ps.exists(_.startsWith("${")) shouldBe true
      ps.exists(_.startsWith("<%=")) shouldBe true
    }
  }

  "SstiCheck.toFinding" should {
    "be a High, reproducible SSTI finding" in {
      val f = SstiCheck.toFinding(InjectionPoint.QueryParam("q"), "{{x}}")
      f.kind shouldBe FindingKind.Ssti
      f.severity shouldBe Severity.High
      f.reproducible shouldBe true
      f.replay should include("ssti query param 'q'")
    }
  }
}
