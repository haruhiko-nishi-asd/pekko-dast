package dast

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class JwtCheckSpec extends AnyWordSpec with Matchers {

  private def b64(s: String): String = java.util.Base64.getUrlEncoder
    .withoutPadding.encodeToString(s.getBytes("UTF-8"))

  private def hs256(header: String, payload: String, secret: String): String =
    val si = s"${b64(header)}.${b64(payload)}"
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"))
    val sig = java.util.Base64.getUrlEncoder.withoutPadding
      .encodeToString(mac.doFinal(si.getBytes("UTF-8")))
    s"$si.$sig"

  // The canonical jwt.io example token, signed with "your-256-bit-secret".
  private val weakToken =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

  "JwtCheck.analyze" should {

    "flag an HS256 token signed with a guessable secret as Critical" in {
      val fs = JwtCheck.analyze("cookie 'jwt'", weakToken)
      fs.map(_.kind) shouldBe Seq(FindingKind.JwtWeakness)
      fs.head.severity shouldBe Severity.Critical
      fs.head.evidence should not include "your-256-bit-secret" // secret not leaked
    }

    "also confirm a weak secret on a locally-signed token" in {
      val token = hs256("""{"alg":"HS256","typ":"JWT"}""", """{"sub":"1"}""", "secret")
      JwtCheck.analyze("localStorage 'auth'", token).map(_.severity) shouldBe
        Seq(Severity.Critical)
    }

    "flag an alg:none token as High" in {
      val token = s"${b64("""{"alg":"none","typ":"JWT"}""")}.${b64("""{"sub":"admin"}""")}."
      val fs = JwtCheck.analyze("cookie 'session'", token)
      fs.map(_.severity) shouldBe Seq(Severity.High)
      fs.head.replay should include("alg=none")
    }

    "not flag a token signed with a strong secret" in {
      val token =
        hs256("""{"alg":"HS256"}""", """{"sub":"1"}""", "Z9!longRandomNotInWordlist#2026")
      JwtCheck.analyze("cookie 'jwt'", token) shouldBe empty
    }

    "ignore a non-JWT string" in {
      JwtCheck.analyze("cookie 'x'", "not-a-token") shouldBe empty
    }
  }

  "JwtCheck.check" should {
    "find a weak-secret JWT carried in a cookie value (even with a Bearer prefix)" in {
      val snapshot = ClientStateSnapshot(
        url = "https://app.example",
        cookies = Seq(Cookie(
          "auth",
          s"Bearer $weakToken",
          "app.example",
          "/",
          httpOnly = true,
          secure = true,
          sameSite = Some("Lax"),
        )),
      )
      val fs = JwtCheck.check(snapshot)
      fs.map(_.kind) shouldBe Seq(FindingKind.JwtWeakness)
      fs.head.severity shouldBe Severity.Critical
    }
  }
}
