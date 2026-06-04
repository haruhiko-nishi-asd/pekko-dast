package dast

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import scala.util.Try

/** Pure, offline JWT-weakness check over captured client state.
  *
  * JWTs stashed in cookies or web storage are inspected without touching the
  * network. Two deterministic, high-signal weaknesses are reported:
  *
  *   - **alg: none** — the token declares no signature, so anyone can forge one.
  *   - **weak HMAC secret** — an `HS256/384/512` token whose signature verifies
  *     against a small wordlist of common secrets. A match is proof the secret
  *     is guessable, so any token (incl. an admin one) can be forged. The
  *     verification is real HMAC, computed locally, so a hit is not a guess.
  *
  * No network and no model, so it runs in [[Tier1]]. Pure and unit tested; the
  * secret value is never embedded in a finding.
  */
object JwtCheck:

  /** A small wordlist of secrets seen in tutorials / defaults / weak configs. */
  private val weakSecrets: Seq[String] = Seq(
    "secret",
    "password",
    "123456",
    "changeme",
    "jwt",
    "key",
    "admin",
    "test",
    "your-256-bit-secret",
    "secretkey",
    "private",
    "token",
    "qwerty",
    "root",
    "default",
    "s3cr3t",
    "supersecret",
    "mysecret",
    "secret123",
  )

  // Every JWT starts `eyJ` (base64url of `{"`); pull candidates out of a value
  // so a wrapper like `Bearer <jwt>` or a JSON blob still yields the token.
  private val jwtRe =
    """eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*""".r

  /** All JWT-weakness findings from a snapshot's cookies and web storage. */
  def check(snapshot: ClientStateSnapshot): Seq[Finding] =
    sources(snapshot).flatMap { (source, value) =>
      jwtRe.findAllIn(value).toSeq.flatMap(token => analyze(source, token))
    }.distinctBy(_.replay)

  private def sources(s: ClientStateSnapshot): Seq[(String, String)] =
    s.cookies.map(c => (s"cookie '${c.name}'", c.value)) ++
      s.localStorage.toSeq.map((k, v) => (s"localStorage '$k'", v)) ++
      s.sessionStorage.toSeq.map((k, v) => (s"sessionStorage '$k'", v))

  /** Findings for one candidate token (empty if not a JWT / no weakness). */
  def analyze(source: String, token: String): Seq[Finding] = algOf(token) match
    case None => Seq.empty
    case Some(alg) =>
      val none =
        if alg.equalsIgnoreCase("none") then Seq(noneFinding(source)) else Seq.empty
      val weak = weakSecretOf(token, alg)
        .map(_ => weakSecretFinding(source, alg)).toSeq
      none ++ weak

  /** The `alg` from a token's header, if it decodes to a JSON object with one
    * (also the JWT-shape gate: non-tokens decode to nothing).
    */
  private def algOf(token: String): Option[String] =
    token.split("\\.", -1) match
      case Array(h, _, _*) => b64json(h).flatMap(_.obj.get("alg"))
          .flatMap(_.strOpt)
      case _ => None

  /** The first weak secret whose HMAC signature matches, if the alg is HMAC. */
  private def weakSecretOf(token: String, alg: String): Option[String] =
    hmacAlg(alg).flatMap { javaAlg =>
      token.split("\\.", -1) match
        case Array(h, p, sig, _*) =>
          val signingInput = s"$h.$p"
          weakSecrets.find(secret =>
            sign(signingInput, secret, javaAlg).contains(sig),
          )
        case _ => None
    }

  private def hmacAlg(alg: String): Option[String] = alg.toUpperCase match
    case "HS256" => Some("HmacSHA256")
    case "HS384" => Some("HmacSHA384")
    case "HS512" => Some("HmacSHA512")
    case _ => None

  private def sign(
      signingInput: String,
      secret: String,
      javaAlg: String,
  ): Option[String] = Try {
    val mac = Mac.getInstance(javaAlg)
    mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), javaAlg))
    java.util.Base64.getUrlEncoder.withoutPadding
      .encodeToString(mac.doFinal(signingInput.getBytes("UTF-8")))
  }.toOption

  private def b64json(seg: String): Option[ujson.Value] = Try {
    val padded = seg + "=" * ((4 - seg.length % 4) % 4)
    ujson.read(new String(java.util.Base64.getUrlDecoder.decode(padded), "UTF-8"))
  }.toOption

  private def noneFinding(source: String): Finding = Finding(
    kind = FindingKind.JwtWeakness,
    severity = Severity.High,
    evidence =
      s"a JWT in $source uses alg 'none' — its signature is not verified, so " +
        "the token can be forged",
    reproducible = true,
    replay = s"jwt $source alg=none",
  )

  private def weakSecretFinding(source: String, alg: String): Finding = Finding(
    kind = FindingKind.JwtWeakness,
    severity = Severity.Critical,
    evidence =
      s"a JWT in $source is signed with $alg using a weak, guessable secret — " +
        "any token (including an elevated one) can be forged",
    reproducible = true,
    replay = s"jwt $source alg=$alg weak-secret",
  )
