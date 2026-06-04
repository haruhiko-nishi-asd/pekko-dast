package dast.scan

import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration.*

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import dast.Finding
import dast.FindingKind
import dast.Severity
import dast.scan.SiteScanOrchestrator.*

class SiteScanOrchestratorSpec extends AnyWordSpec with Matchers {

  private val seed = "https://example.com"

  private def findingFor(url: String): Finding = Finding(
    FindingKind.Xss,
    Severity.Low,
    s"f:$url",
    reproducible = true,
    s"r:$url",
  )

  private def run(
      eff: Effects,
      maxPages: Int = 20,
  ): Vector[(String, Vector[Finding])] = Await
    .result(SiteScanOrchestrator.run(eff, seed, maxPages), 5.seconds)

  "SiteScanOrchestrator.run" should {

    "scan the seed plus each discovered in-scope URL, grouped" in {
      val results = run(Effects(
        discover = _ =>
          Future.successful(Seq(
            "https://example.com/a",
            "https://evil.test/x", // off-host, dropped by Scope
            "https://example.com/b",
          )),
        scanOne = url => Future.successful(Vector(findingFor(url))),
      ))
      results.map(_._1) shouldBe Seq(
        "https://example.com/",
        "https://example.com/a",
        "https://example.com/b",
      )
      results.foreach { case (url, fs) => fs shouldBe Vector(findingFor(url)) }
    }

    "fail soft: a failed scanOne yields an empty result, not an abort" in {
      val byUrl = run(Effects(
        discover = _ =>
          Future.successful(Seq("https://example.com/a", "https://example.com/b")),
        scanOne = url =>
          if url.endsWith("/b") then Future.failed(new RuntimeException("boom"))
          else Future.successful(Vector(findingFor(url))),
      )).toMap
      byUrl("https://example.com/a") shouldBe
        Vector(findingFor("https://example.com/a"))
      byUrl("https://example.com/b") shouldBe empty
    }

    "scan only the seed when discovery is empty" in {
      run(Effects(
        discover = _ => Future.successful(Seq.empty),
        scanOne = url => Future.successful(Vector(findingFor(url))),
      )).map(_._1) shouldBe Seq("https://example.com/")
    }

    "fall back to scanning the seed when discovery fails" in {
      run(Effects(
        discover = _ => Future.failed(new RuntimeException("boom")),
        scanOne = url => Future.successful(Vector(findingFor(url))),
      )).map(_._1) shouldBe Seq("https://example.com/")
    }

    "respect the maxPages cap" in {
      run(
        Effects(
          discover =
            _ => Future.successful((1 to 50).map(i => s"https://example.com/p$i")),
          scanOne = url => Future.successful(Vector(findingFor(url))),
        ),
        maxPages = 3,
      ) should have size 3
    }
  }
}
