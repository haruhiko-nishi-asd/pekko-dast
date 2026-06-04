package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ClickStepSpec extends AnyWordSpec with Matchers {

  "ClickStep.parse" should {

    "parse a click with an integer or numeric-string elementId" in {
      ClickStep
        .parse(ujson.read("""{"action":"click","elementId":5}""")) shouldBe
        ClickStep.Click(5)
      ClickStep
        .parse(ujson.read("""{"action":"click","elementId":"5"}""")) shouldBe
        ClickStep.Click(5)
    }

    "parse scroll" in {
      ClickStep.parse(ujson.read("""{"action":"scroll"}""")) shouldBe
        ClickStep.Scroll
    }

    "parse done" in {
      ClickStep.parse(ujson.read("""{"action":"done"}""")) shouldBe
        ClickStep.Done
    }

    "fail closed to Done on off-menu input" in {
      // unknown action, missing/negative id, non-object — all become Done.
      ClickStep.parse(ujson.read("""{"action":"exfiltrate"}""")) shouldBe
        ClickStep.Done
      ClickStep.parse(ujson.read("""{"action":"click"}""")) shouldBe
        ClickStep.Done
      ClickStep
        .parse(ujson.read("""{"action":"click","elementId":-1}""")) shouldBe
        ClickStep.Done
      ClickStep.parse(ujson.read("""["click"]""")) shouldBe ClickStep.Done
    }
  }

  "ClickStep.render" should {

    "list the indexed controls and the history" in {
      val out = ClickStep.render(
        "https://app.example/x",
        Seq(
          ClickTarget(0, "button", "Open menu", disabled = false),
          ClickTarget(1, "tab", "Details", disabled = false),
        ),
        Seq("https://app.example/a"),
        Seq.empty,
      )
      out should include("Current page: https://app.example/x")
      out should include("#0 button \"Open menu\"")
      out should include("#1 tab \"Details\"")
      out should include("https://app.example/a")
    }

    "mark controls already clicked on this page so the model skips them" in {
      val out = ClickStep.render(
        "https://app.example/x",
        Seq(
          ClickTarget(0, "button", "Open menu", disabled = false),
          ClickTarget(1, "tab", "Details", disabled = false),
        ),
        Seq.empty,
        Seq("button/Open menu"),
      )
      out should include("#0 button \"Open menu\"  (already clicked)")
      (out should not).include("#1 tab \"Details\"  (already clicked)")
    }

    "show placeholders when there are no controls or history" in {
      val out = ClickStep
        .render("https://app.example/x", Seq.empty, Seq.empty, Seq.empty)
      out should include("(none)")
      out should include("(nothing yet)")
    }
  }
}
