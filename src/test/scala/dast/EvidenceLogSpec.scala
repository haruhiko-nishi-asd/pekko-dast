package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class EvidenceLogSpec extends AnyWordSpec with Matchers {

  "EvidenceLog" should {

    "record nothing while disabled (the default), keeping it free and silent" in {
      EvidenceLog.setEnabled(false)
      EvidenceLog
        .http("sqli", "GET", "http://x/?id=1'", 500, 12, Seq("Server" -> "x"))
      EvidenceLog
        .decision("xss", "query param 'q'", "img-onerror", confirmed = true)
      EvidenceLog.render() shouldBe ""
    }

    "record http + decision lines as parseable JSON Lines when enabled" in {
      EvidenceLog.setEnabled(true)
      try
        EvidenceLog.http(
          "ut-sqli",
          "GET",
          "http://x/?id=1'",
          500,
          12,
          Seq("Content-Type" -> "text/html"),
        )
        EvidenceLog
          .decision("ut-xss", "query param 'q'", "img-onerror", confirmed = true)

        val byCheck = EvidenceLog.render().split("\n").map(ujson.read(_))
          .groupBy(_.obj.get("check").map(_.str).getOrElse(""))

        val http = byCheck("ut-sqli").head
        http("kind").str shouldBe "http"
        http("method").str shouldBe "GET"
        http("status").num.toInt shouldBe 500
        http("responseHeaders")("Content-Type").str shouldBe "text/html"

        val dec = byCheck("ut-xss").head
        dec("kind").str shouldBe "decision"
        dec("point").str shouldBe "query param 'q'"
        dec("confirmed").bool shouldBe true
      finally EvidenceLog.setEnabled(false)
    }
  }
}
