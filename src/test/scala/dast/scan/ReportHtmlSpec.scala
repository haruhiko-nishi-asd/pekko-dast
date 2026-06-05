package dast.scan

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ReportHtmlSpec extends AnyWordSpec with Matchers {

  private val single = ujson.Obj(
    "target" -> "https://app.example/",
    "findingCount" -> 1,
    "findings" -> ujson.Arr(ujson.Obj(
      "kind" -> "BrokenAccessControl",
      "severity" -> "High",
      "evidence" -> "GET /creatives?campaignId=01K returned another account's data",
      "reproducible" -> true,
      "replay" -> "idor GET /creatives?campaignId={id} id=01K leak=acme.example",
    )),
  )

  "ReportHtml" should {

    "render a self-contained document with the target and finding" in {
      val html = ReportHtml.render(single)
      html should startWith("<!doctype html>")
      html should include("<style>") // inline CSS, no external deps
      html should include("https://app.example/")
      html should include("BrokenAccessControl")
      html should include("High")
      html should include("confirmed") // reproducible badge
      html should include("idor GET /creatives") // replay handle shown
    }

    "render the site shape (findings grouped per page)" in {
      val site = ujson.Obj(
        "seed" -> "https://app.example/",
        "findingCount" -> 1,
        "pages" -> ujson.Arr(ujson.Obj(
          "url" -> "https://app.example/login",
          "findings" -> ujson.Arr(ujson.Obj(
            "kind" -> "MissingSecurityHeader",
            "severity" -> "Low",
            "evidence" -> "missing strict-transport-security",
            "reproducible" -> true,
            "replay" -> "header:strict-transport-security@/login",
          )),
        )),
      )
      val html = ReportHtml.render(site)
      html should include("https://app.example/login")
      html should include("MissingSecurityHeader")
    }

    "escape markup-significant characters from target content" in {
      val xss = ujson.Obj(
        "target" -> "https://app.example/",
        "findingCount" -> 1,
        "findings" -> ujson.Arr(ujson.Obj(
          "kind" -> "Xss",
          "severity" -> "High",
          "evidence" -> "reflected <script>alert(1)</script>",
          "reproducible" -> true,
          "replay" -> "probe q payload=img",
        )),
      )
      val html = ReportHtml.render(xss)
      html should include("&lt;script&gt;")
      html should not include "<script>alert(1)</script>"
    }

    "include the evidence transcript when records are present" in {
      val evidence = Seq[ujson.Value](
        ujson.Obj(
          "kind" -> "http",
          "check" -> "content-idor",
          "method" -> "GET",
          "url" -> "https://app.example/creatives?campaignId=01K",
          "status" -> 200,
          "ms" -> 44.0,
        ),
      )
      val html = ReportHtml.render(single, evidence)
      html should include("Evidence transcript")
      html should include("content-idor")
      html should include("01K")
      html should include("200")
    }

    "omit the evidence section entirely when there are no records" in {
      ReportHtml.render(single, Nil) should not include "Evidence transcript"
    }

    "show an empty state rather than crashing on zero findings" in {
      val empty = ujson
        .Obj("target" -> "https://app.example/", "findingCount" -> 0, "findings" -> ujson.Arr())
      ReportHtml.render(empty) should include("No findings")
    }
  }
}
