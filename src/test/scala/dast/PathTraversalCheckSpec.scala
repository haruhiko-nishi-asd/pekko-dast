package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class PathTraversalCheckSpec extends AnyWordSpec with Matchers {

  "PathTraversalCheck.detect" should {

    "recognise an /etc/passwd body" in {
      PathTraversalCheck
        .detect("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon") shouldBe
        Some("/etc/passwd")
    }

    "recognise a win.ini body, case-insensitively" in {
      PathTraversalCheck
        .detect("; for 16-bit app support\n[Fonts]\n[Extensions]") shouldBe
        Some("win.ini")
    }

    "return None for an ordinary page" in {
      PathTraversalCheck.detect("<html>hello world</html>") shouldBe None
    }
  }

  "PathTraversalCheck.confirms" should {

    "confirm a file signature that was absent from the baseline" in {
      PathTraversalCheck.confirms(
        baselineBody = "<html>file not found</html>",
        injectedBody = "root:x:0:0:root:/root:/bin/bash",
      ) shouldBe Some("/etc/passwd")
    }

    "reject when the baseline already contained the signature" in {
      val body = "root:x:0:0:demo"
      PathTraversalCheck.confirms(body, body) shouldBe None
    }
  }

  "PathTraversalCheck.toFinding" should {
    "be a High, reproducible path-traversal finding" in {
      val f = PathTraversalCheck
        .toFinding(InjectionPoint.QueryParam("file"), "/etc/passwd", "../etc/passwd")
      f.kind shouldBe FindingKind.PathTraversal
      f.severity shouldBe Severity.High
      f.reproducible shouldBe true
      f.replay should include("path-traversal query param 'file'")
    }
  }
}
