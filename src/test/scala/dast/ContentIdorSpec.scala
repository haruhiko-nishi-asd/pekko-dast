package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ContentIdorSpec extends AnyWordSpec with Matchers {

  "ContentIdor.fill" should {
    "substitute the {id} placeholder" in {
      ContentIdor.fill("https://h/c?campaignId={id}", "01KT") shouldBe
        "https://h/c?campaignId=01KT"
      ContentIdor.fill("campaignId={id}&x=1", "9") shouldBe "campaignId=9&x=1"
    }
  }

  "ContentIdor.parseProposals" should {
    "parse a query-param test" in {
      val arr = ujson.read(
        """[{
        "method":"GET",
        "urlTemplate":"https://h/creatives?campaignId={id}",
        "ownValue":"01OWN","candidates":["01OTHER"],"discriminatorField":"name"
      }]""",
      )
      val ps = ContentIdor.parseProposals(arr)
      ps should have size 1
      ps.head.method shouldBe "GET"
      ps.head.bodyTemplate shouldBe None
      ps.head.candidates shouldBe Seq("01OTHER")
      ps.head.isPost shouldBe false
    }
    "parse a POST body test" in {
      val arr = ujson.read(
        """[{
        "method":"POST","urlTemplate":"https://h/creatives",
        "bodyTemplate":"campaignId={id}","ownValue":"1","candidates":["2","3"],
        "discriminatorField":"owner"
      }]""",
      )
      val p = ContentIdor.parseProposals(arr).head
      p.isPost shouldBe true
      p.bodyTemplate shouldBe Some("campaignId={id}")
    }
    "drop proposals with no {id}, no candidates, or no field AND no leak" in {
      ContentIdor.parseProposals(ujson.read(
        """[
        {"urlTemplate":"https://h/x","ownValue":"1","candidates":["2"],"discriminatorField":"f"},
        {"urlTemplate":"https://h/x?id={id}","ownValue":"1","candidates":[],"discriminatorField":"f"},
        {"urlTemplate":"https://h/x?id={id}","ownValue":"1","candidates":["2"]}
      ]""",
      )) shouldBe empty
    }
    "parse a leak-marker test without a discriminatorField" in {
      val arr = ujson.read(
        """[{
        "urlTemplate":"https://h/creatives?campaignId={id}",
        "ownValue":"01OWN","candidates":["01OTHER"],"leak":"bizreach.biz"
      }]""",
      )
      val p = ContentIdor.parseProposals(arr).head
      p.leak shouldBe Some("bizreach.biz")
      p.discriminatorField shouldBe ""
    }
  }

  "ContentIdor.confirmsLeak" should {
    "confirm when the victim's marker is in the candidate body but not the baseline" in {
      ContentIdor.confirmsLeak(
        ownBaselineBody = "<div id=creatives-area>No creatives yet</div>",
        candidateBody =
          "<div id=creatives-area>Creative - bizreach.biz Active</div>",
        leak = "bizreach.biz",
      ) shouldBe true
    }
    "not confirm when the marker is already in the caller's own baseline" in {
      ContentIdor.confirmsLeak(
        "my own bizreach.biz",
        "bizreach.biz",
        "bizreach.biz",
      ) shouldBe false
    }
    "not confirm when the marker is absent from the candidate body" in {
      ContentIdor
        .confirmsLeak("own", "No creatives yet", "bizreach.biz") shouldBe false
    }
    "not confirm on an empty marker" in {
      ContentIdor.confirmsLeak("a", "b", "") shouldBe false
    }
  }

  "ContentIdor.dataLeak" should {
    def p(leak: Option[String]) = ContentIdor
      .Proposal("GET", "u?id={id}", None, "01OWN", Seq("01OTHER"), "", leak)
    "accept a data marker that is not one of the ids in play" in {
      ContentIdor.dataLeak(p(Some("bizreach.biz"))) shouldBe Some("bizreach.biz")
    }
    "reject a marker equal to a candidate id (an id echoes, proving nothing)" in {
      ContentIdor.dataLeak(p(Some("01OTHER"))) shouldBe None
    }
    "reject a marker equal to the caller's own id" in {
      ContentIdor.dataLeak(p(Some("01OWN"))) shouldBe None
    }
    "be None when there is no leak marker" in {
      ContentIdor.dataLeak(p(None)) shouldBe None
    }
  }

  "ContentIdor.markersFrom" should {
    "surface data tokens in the other account's content but not the caller's own" in {
      val victim =
        "<div>Creative - bizreach.biz Active</div> contact victim@corp.com"
      val own = "<div>Creative - mycorp.example No data</div>"
      val ms = ContentIdor.markersFrom(victim, own)
      ms should contain("bizreach.biz")
      ms should contain("victim@corp.com")
    }
    "drop tokens shared by both pages (CDN / script domains)" in {
      val ms = ContentIdor.markersFrom(
        "shell cdn.tailwindcss.com data bizreach.biz",
        "shell cdn.tailwindcss.com own only",
      )
      ms should contain("bizreach.biz")
      ms should not contain "cdn.tailwindcss.com"
    }
  }

  "ContentIdor.toFinding" should {
    "be a reproducible High naming method, candidate, and field" in {
      val p = ContentIdor
        .Proposal("GET", "https://h/c?id={id}", None, "1", Seq("2"), "email")
      val f = ContentIdor.toFinding(p, "2", "bob@x")
      f.kind shouldBe FindingKind.BrokenAccessControl
      f.severity shouldBe Severity.High
      f.replay should include("id=2")
      f.replay should include("field=email")
    }
  }

  "ContentIdor.leakFinding" should {
    "be a reproducible High naming the candidate and the leaked marker" in {
      val p = ContentIdor.Proposal(
        "GET",
        "https://h/c?campaignId={id}",
        None,
        "1",
        Seq("2"),
        "",
        Some("bizreach.biz"),
      )
      val f = ContentIdor.leakFinding(p, "01VICTIM", "bizreach.biz")
      f.kind shouldBe FindingKind.BrokenAccessControl
      f.severity shouldBe Severity.High
      f.replay should include("id=01VICTIM")
      f.replay should include("leak=bizreach.biz")
      f.evidence should include("bizreach.biz")
    }
  }
}
