package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ClickGuardSpec extends AnyWordSpec with Matchers {

  private def target(name: String, role: String = "button", disabled: Boolean = false) =
    ClickTarget(0, role, name, disabled)

  "ClickGuard.allow" should {

    "permit a benign navigational control" in {
      ClickGuard.allow(target("Open menu")) shouldBe Right(())
      ClickGuard.allow(target("Details", role = "tab")) shouldBe Right(())
    }

    "refuse a disabled control before checking its name" in {
      ClickGuard.allow(target("Open menu", disabled = true)) shouldBe
        Left("control is disabled")
    }

    "refuse destructive controls by accessible name, case-insensitively" in {
      ClickGuard.allow(target("Delete account")).isLeft shouldBe true
      ClickGuard.allow(target("LOG OUT")) shouldBe
        Left("matches destructive pattern 'log out'")
      ClickGuard.allow(target("Pay now")) shouldBe
        Left("matches destructive pattern 'pay'")
      ClickGuard.allow(target("Confirm purchase")).isLeft shouldBe true
    }

    "also screen the role text, not only the name" in {
      ClickGuard.allow(target("", role = "delete-button")) shouldBe
        Left("matches destructive pattern 'delete'")
    }

    "match whole words only, so a destructive substring inside a word passes" in {
      // "Display" contains "pay" and "Carryover" contains "remove"-free, but the
      // deny-words must stand alone: these benign controls are allowed.
      ClickGuard.allow(target("Display options")) shouldBe Right(())
      ClickGuard.allow(target("Repayment history")) shouldBe Right(())
      // but the word on its own is still refused
      ClickGuard.allow(target("Pay invoice")) shouldBe
        Left("matches destructive pattern 'pay'")
    }
  }
}
