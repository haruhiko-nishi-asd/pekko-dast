package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ClickOpSpec extends AnyWordSpec with Matchers {

  private val authed = Authorization.active("example.com")
  private val benign = ClickTarget(3, "button", "Open menu", disabled = false)
  private val destructive = ClickTarget(4, "button", "Delete account", disabled = false)

  "ClickOp.precheck" should {

    "deny under the observe-only default (no browser touched)" in {
      ClickOp.precheck(Authorization.ObserveOnly, "https://example.com", benign) shouldBe
        Left("active testing is disabled (observe-only)")
    }

    "deny an off-scope host even for a benign control" in {
      ClickOp.precheck(authed, "https://evil.test", benign) shouldBe
        Left("host 'evil.test' is not in the authorized scope")
    }

    "deny a destructive control even on an authorized active host" in {
      // The gate would permit; the destructive floor is the hard stop.
      ClickOp.precheck(authed, "https://example.com", destructive) shouldBe
        Left("matches destructive pattern 'delete'")
    }

    "permit a benign control on an authorized active host" in {
      ClickOp.precheck(authed, "https://example.com", benign) shouldBe Right(())
    }
  }
}
