package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class SecretInStorageCheckSpec extends AnyWordSpec with Matchers {

  // Standard jwt.io example token (header {"alg":"HS256","typ":"JWT"}).
  private val jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

  "SecretClassifier" should {

    "recognise a JWT" in {
      SecretClassifier.classify(jwt).map(_.kind) shouldBe
        Some(SecretClassifier.Kind.Jwt)
    }

    "recognise a known credential prefix" in {
      SecretClassifier.classify("AKIAIOSFODNN7EXAMPLE").map(_.kind) shouldBe
        Some(SecretClassifier.Kind.KnownCredential)
    }

    "recognise a high-entropy mixed token" in {
      SecretClassifier.classify("Zx9Qw3rT7yUiOpAs2DfGhJkL5bVcXmN8")
        .map(_.kind) shouldBe Some(SecretClassifier.Kind.HighEntropyToken)
    }

    "not flag benign values" in Seq(
      "en-US",
      "true",
      "dark",
      "1234567890",
      "12345678901234567890",
      "the quick brown fox jumps over the lazy dog",
      // Canonical UUID: a ubiquitous non-secret id that clears the entropy gate.
      "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "F47AC10B-58CC-4372-A567-0E02B2C3D479",
    ).foreach { v =>
      withClue(s"value '$v': ")(SecretClassifier.classify(v) shouldBe None)
    }
  }

  "SecretInStorageCheck" should {

    "flag a JWT in localStorage as High and not leak the value" in {
      val findings = SecretInStorageCheck.check(ClientStateSnapshot(
        url = "https://example.com",
        localStorage = Map("id_token" -> jwt),
      ))
      findings.map(_.kind) shouldBe Seq(FindingKind.SecretInStorage)
      findings.head.severity shouldBe Severity.High
      findings.head.replay shouldBe "localStorage['id_token']"
      (findings.head.evidence should not).include(jwt)
    }

    "escalate to Critical when an auth flow was observed" in {
      val findings = SecretInStorageCheck.check(ClientStateSnapshot(
        url = "https://example.com",
        sessionStorage = Map("access" -> jwt),
        observedAuthFlow = true,
      ))
      findings.head.severity shouldBe Severity.Critical
    }

    "report nothing for benign storage" in {
      SecretInStorageCheck.check(ClientStateSnapshot(
        url = "https://example.com",
        localStorage = Map("theme" -> "dark", "lang" -> "en-US"),
      )) shouldBe empty
    }
  }
}
