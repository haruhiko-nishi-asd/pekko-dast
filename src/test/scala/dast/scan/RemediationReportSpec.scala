package dast.scan

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import dast.Finding
import dast.FindingKind
import dast.Severity

class RemediationReportSpec extends AnyWordSpec with Matchers {

  private def report(target: String, findings: Seq[Finding]): ujson.Value =
    FindingsReport.toJson(target, findings)

  "Remediation.forKind" should {
    "map a known kind to its CWE/OWASP guidance" in {
      val g = Remediation.forKind("SqlInjection")
      g.cwe shouldBe "CWE-89"
      g.owasp should include("A03:2021")
      g.fix.toLowerCase should include("parameterized")
    }
    "fall back to a generic, still-actionable template for an unknown kind" in {
      val g = Remediation.forKind("SomethingNew")
      g.title shouldBe "SomethingNew"
      g.verify should include("replay")
    }
  }

  "RemediationReport.render" should {

    "produce an agent-oriented brief carrying evidence, reproduction and fix" in {
      val f = Finding(
        kind = FindingKind.SqlInjection,
        severity = Severity.High,
        evidence = "query param 'id' triggers a MySQL error when a quote is injected",
        reproducible = true,
        replay = "sqli query param 'id' technique=error",
      )
      val md = RemediationReport.render(report("https://app.example", Seq(f)))

      md should include("# Security remediation brief — https://app.example")
      md should include("access to the source code")
      md should include("SQL injection — CWE-89")
      md should include("query param 'id' triggers a MySQL error")
      // The replay handle is rendered as a reproduction block.
      md should include("sqli query param 'id' technique=error")
      md should include("**Fix:**")
      md should include("**Verify:**")
    }

    "order findings by severity, most severe first" in {
      val low = Finding(
        FindingKind.OpenRedirect,
        Severity.Medium,
        "medium finding",
        true,
        "redirect ...",
      )
      val crit = Finding(
        FindingKind.BrokenAccessControl,
        Severity.Critical,
        "critical finding",
        true,
        "idor ...",
      )
      val md = RemediationReport.render(report("t", Seq(low, crit)))
      md.indexOf("[CRITICAL]") should be < md.indexOf("[MEDIUM]")
    }

    "attach the endpoint URL for a site-shaped report" in {
      val f = Finding(
        FindingKind.Cors,
        Severity.High,
        "reflects an arbitrary Origin",
        true,
        "cors ...",
      )
      val site = FindingsReport
        .toJsonSite("https://seed", Seq("https://app.example/api" -> Seq(f)))
      val md = RemediationReport.render(site)
      md should include("**Endpoint:** https://app.example/api")
      md should include("CORS misconfiguration")
    }

    "say there is nothing to patch when there are no findings" in {
      val md = RemediationReport.render(report("t", Seq.empty))
      md should include("Confirmed findings: 0")
      md should include("nothing to patch")
    }

    "flag a non-reproducible finding for validation before code changes" in {
      val f = Finding(
        FindingKind.Xss,
        Severity.Medium,
        "sink reach",
        reproducible = false,
        replay = "xss ...",
      )
      RemediationReport.render(report("t", Seq(f))) should include(
        "not deterministically confirmed",
      )
    }
  }
}
