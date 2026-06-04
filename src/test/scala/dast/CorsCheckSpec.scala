package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class CorsCheckSpec extends AnyWordSpec with Matchers {

  private val origin = CorsCheck.probeOrigin

  "CorsCheck.analyze" should {

    "flag a reflected arbitrary origin WITH credentials as High" in {
      val f = CorsCheck.analyze(origin, Some(origin), Some("true")).get
      f.kind shouldBe FindingKind.Cors
      f.severity shouldBe Severity.High
      f.replay should include("reflected-origin+creds")
    }

    "flag the 'null' origin WITH credentials as High" in {
      CorsCheck.analyze(origin, Some("null"), Some("TRUE")).map(_.severity) shouldBe
        Some(Severity.High)
    }

    "flag a reflected origin WITHOUT credentials as Medium" in {
      CorsCheck.analyze(origin, Some(origin), None).map(_.severity) shouldBe
        Some(Severity.Medium)
    }

    "flag wildcard WITH credentials as Medium" in {
      CorsCheck.analyze(origin, Some("*"), Some("true")).map(_.severity) shouldBe
        Some(Severity.Medium)
    }

    "not flag wildcard without credentials, or an unrelated/absent ACAO" in {
      CorsCheck.analyze(origin, Some("*"), None) shouldBe None
      CorsCheck.analyze(origin, Some("https://app.example"), Some("true")) shouldBe
        None
      CorsCheck.analyze(origin, None, None) shouldBe None
    }
  }
}
