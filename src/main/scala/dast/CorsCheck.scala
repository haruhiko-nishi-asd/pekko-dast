package dast

/** Pure logic for the CORS misconfiguration probe.
  *
  * A request is sent carrying a forged `Origin`; the response's
  * `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials`
  * (ACAC) headers are then judged here. The dangerous shape is a server that
  * **reflects an arbitrary origin (or `null`) AND allows credentials** — any
  * site can then make authenticated cross-origin reads (account takeover). A
  * bare `*` is weaker (browsers refuse to send credentials with it), so it is
  * only flagged when credentials are also allowed (a non-compliant combo) or as
  * info otherwise. Deterministic from the two header values; no guessing.
  */
object CorsCheck:

  /** A reserved sentinel origin used to detect arbitrary-origin reflection. */
  val probeOrigin = "https://dast-cors-probe.example"

  /** Origins to send per target. Beyond the bare sentinel (arbitrary-origin
    * reflection), `forHost` derives two that an attacker controls yet a naive
    * allow-list accepts: `<host>.<sentinel>` trips `origin.startsWith(host)` /
    * substring checks, and `<sentinel-with-host-suffix>` trips
    * `origin.endsWith(host)` checks. Reflecting either is a real misconfig.
    */
  def probeOrigins(targetHost: Option[String]): Seq[String] =
    val sentinel = "dast-cors-probe.example"
    probeOrigin +:
      targetHost.toSeq
        .flatMap(h => Seq(s"https://$h.$sentinel", s"https://$sentinel.$h"))

  /** Origins compared up to case and a trailing slash, so a server that
    * lowercases or re-serializes the reflected origin is not missed.
    */
  private def sameOrigin(a: String, b: String): Boolean =
    def norm(s: String) = s.trim.toLowerCase.stripSuffix("/")
    norm(a) == norm(b)

  /** Judge a CORS response. `acao` / `acac` are the response header values (if
    * present); `requestOrigin` is the forged `Origin` we sent.
    */
  def analyze(
      requestOrigin: String,
      acao: Option[String],
      acac: Option[String],
  ): Option[Finding] =
    val allowsCreds = acac.exists(_.trim.equalsIgnoreCase("true"))
    acao.map(_.trim) match
      case Some(o) if sameOrigin(o, requestOrigin) && allowsCreds =>
        Some(finding(
          Severity.High,
          s"reflects an arbitrary Origin ($o) AND allows credentials — any " +
            "site can make authenticated cross-origin reads",
          s"reflected-origin+creds origin=$requestOrigin",
        ))
      case Some(o) if o.equalsIgnoreCase("null") && allowsCreds =>
        Some(finding(
          Severity.High,
          "trusts the 'null' Origin AND allows credentials — a sandboxed " +
            "document can make authenticated cross-origin reads",
          "null-origin+creds",
        ))
      case Some(o) if sameOrigin(o, requestOrigin) =>
        Some(finding(
          Severity.Medium,
          s"reflects an arbitrary Origin ($o) — any site can read non-credentialed responses",
          s"reflected-origin origin=$requestOrigin",
        ))
      case Some("*") if allowsCreds =>
        Some(finding(
          Severity.Medium,
          "returns '*' with credentials allowed — a non-compliant, risky CORS policy",
          "wildcard+creds",
        ))
      case _ => None

  private def finding(sev: Severity, detail: String, replay: String): Finding =
    Finding(
      kind = FindingKind.Cors,
      severity = sev,
      evidence = s"CORS misconfiguration: the server $detail",
      reproducible = true,
      replay = s"cors $replay",
    )
