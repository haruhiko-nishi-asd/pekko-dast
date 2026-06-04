package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ClickTargetScanOpSpec extends AnyWordSpec with Matchers {

  private def row(pairs: (String, Object)*): java.util.Map[String, Object] =
    val m = new java.util.LinkedHashMap[String, Object]()
    pairs.foreach((k, v) => m.put(k, v))
    m

  private def list(
      rows: java.util.Map[String, Object]*,
  ): java.util.List[Object] =
    val l = new java.util.ArrayList[Object]()
    rows.foreach(l.add)
    l

  "ClickTargetScanOp.parseTargets" should {

    "parse a list of element rows into ClickTargets, preserving the stamped id" in {
      val raw = list(
        row(
          "id" -> Integer.valueOf(0),
          "role" -> "button",
          "name" -> "Add to cart",
          "disabled" -> java.lang.Boolean.FALSE,
        ),
        row(
          "id" -> Integer.valueOf(1),
          "role" -> "link",
          "name" -> "Account",
          "disabled" -> java.lang.Boolean.TRUE,
        ),
      )
      ClickTargetScanOp.parseTargets(raw) shouldBe Seq(
        ClickTarget(0, "button", "Add to cart", disabled = false),
        ClickTarget(1, "link", "Account", disabled = true),
      )
    }

    "accept whole-number ids that arrive as Double or Long from the JS bridge" in {
      val raw = list(
        row(
          "id" -> java.lang.Double.valueOf(2.0),
          "role" -> "tab",
          "name" -> "X",
        ),
        row(
          "id" -> java.lang.Long.valueOf(3L),
          "role" -> "button",
          "name" -> "Y",
        ),
      )
      ClickTargetScanOp.parseTargets(raw).map(_.id) shouldBe Seq(2, 3)
    }

    "skip rows missing a usable integer id rather than throwing" in {
      val raw = list(
        row("role" -> "button", "name" -> "no id"),
        row("id" -> "nope", "role" -> "button", "name" -> "bad id"),
        row(
          "id" -> java.lang.Double.valueOf(1.5),
          "role" -> "button",
          "name" -> "fractional",
        ),
        row("id" -> Integer.valueOf(7), "role" -> "button", "name" -> "good"),
      )
      ClickTargetScanOp.parseTargets(raw) shouldBe
        Seq(ClickTarget(7, "button", "good", disabled = false))
    }

    "default missing role/name/disabled fields without throwing" in {
      val raw = list(row("id" -> Integer.valueOf(0)))
      ClickTargetScanOp.parseTargets(raw) shouldBe
        Seq(ClickTarget(0, "", "", disabled = false))
    }

    "tolerate non-list input and non-map rows" in {
      ClickTargetScanOp.parseTargets(null) shouldBe empty
      ClickTargetScanOp.parseTargets("nope") shouldBe empty

      val mixed = new java.util.ArrayList[Object]()
      mixed.add("not a row")
      mixed
        .add(row("id" -> Integer.valueOf(0), "role" -> "button", "name" -> "ok"))
      ClickTargetScanOp.parseTargets(mixed) shouldBe
        Seq(ClickTarget(0, "button", "ok", disabled = false))
    }

    "treat aria-disabled string 'true' as disabled" in {
      val raw = list(
        row("id" -> Integer.valueOf(0), "role" -> "button", "disabled" -> "true"),
      )
      ClickTargetScanOp.parseTargets(raw).head.disabled shouldBe true
    }

    "carry the hint so same-named controls stay distinct" in {
      val raw = list(
        row(
          "id" -> Integer.valueOf(0),
          "role" -> "button",
          "name" -> "View",
          "hint" -> "row-1",
        ),
        row(
          "id" -> Integer.valueOf(1),
          "role" -> "button",
          "name" -> "View",
          "hint" -> "row-2",
        ),
      )
      val ts = ClickTargetScanOp.parseTargets(raw)
      ts.map(_.hint) shouldBe Seq("row-1", "row-2")
      ts.map(_.key) shouldBe Seq("button/View/row-1", "button/View/row-2")
    }
  }

  "ClickTarget.key" should {
    "omit the hint when empty and include it otherwise" in {
      ClickTarget(0, "button", "Save", disabled = false).key shouldBe
        "button/Save"
      ClickTarget(0, "button", "Save", disabled = false, hint = "x")
        .key shouldBe "button/Save/x"
    }
  }

  "ClickTargetScanOp.EnumerateJs" should {

    "query the interactive controls, stamp ids, pierce shadow roots, and capture a hint" in {
      val js = ClickTargetScanOp.EnumerateJs
      js should include("input[type=submit]")
      js should include("[role=button]")
      js should include("data-dast-id")
      js should include("checkVisibility")
      js should include("aria-label")
      js should include("shadowRoot") // descends into open shadow roots
      js should include("hint")
      // offsetParent is the buggy test we deliberately avoid.
      (js should not).include("offsetParent")
    }
  }

  "ClickTarget.describe" should {

    "render a compact, model-facing line" in {
      ClickTarget(3, "button", "Add to cart", disabled = false)
        .describe shouldBe "#3 button \"Add to cart\""
      ClickTarget(4, "button", "", disabled = true).describe shouldBe
        "#4 button (no name) [disabled]"
    }

    "include the hint when present" in {
      ClickTarget(5, "button", "View", disabled = false, hint = "row-2")
        .describe shouldBe "#5 button \"View\" (row-2)"
    }
  }
}
