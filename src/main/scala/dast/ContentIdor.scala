package dast

/** Pure logic for content-harvested IDOR (README).
  *
  * The model is the navigator/harvester: shown the authenticated pages the
  * browser visited, it finds the real object-reference IDs present in the
  * content (campaign/order/user ids, including non-enumerable ULIDs/UUIDs) and
  * proposes tests as a request template with a `{id}` placeholder -- covering a
  * query param, a path segment, or a POST body field -- plus the caller's own
  * id (baseline) and candidate ids it actually observed (never invented).
  *
  * Determinism confirms: requesting a candidate id returns a 2xx whose
  * discriminator field differs from the caller's own baseline (cross-user
  * data). Building/confirming here is pure; the HTTP lives in
  * [[ContentIdorProbe]].
  */
object ContentIdor:

  /** Most candidate ids tried per proposal. The model proposes candidates and
    * the probe sends one request each; this bound stops an over-enumerating (or
    * prompt-injected) model from turning a confirmation into a high-volume scan
    * against the authorized host (the throttle caps concurrency, not total).
    */
  val MaxCandidates = 25

  /** A model-proposed IDOR test. `urlTemplate` (and optional `bodyTemplate` for
    * a POST) contain `{id}`, substituted with `ownValue` (baseline) then each
    * candidate. The model supplies only these parameters, never code.
    */
  final case class Proposal(
      method: String,
      urlTemplate: String,
      bodyTemplate: Option[String],
      ownValue: String,
      candidates: Seq[String],
      discriminatorField: String,
      // A distinctive string from the OTHER account's content (a name, domain,
      // email, title). If it appears in the response to a candidate id, that
      // account's data leaked — works on HTML and JSON alike, and only fires on
      // the victim's real content, so a wrong candidate id can't false-confirm.
      leak: Option[String] = None,
  ):
    def isPost: Boolean = method.equalsIgnoreCase("POST")

  /** Substitute the `{id}` placeholder. */
  def fill(template: String, id: String): String = template.replace("{id}", id)

  /** Cross-account leak confirmation for ANY content type: the victim's marker
    * appears in the response to a candidate id, and was NOT in the caller's own
    * baseline (so it is not a generic token the caller also sees). Pure.
    */
  def confirmsLeak(
      ownBaselineBody: String,
      candidateBody: String,
      leak: String,
  ): Boolean = leak.nonEmpty && candidateBody.contains(leak) &&
    !ownBaselineBody.contains(leak)

  /** The leak marker IFF it is real DATA, not one of the ids in play. An id
    * (ownValue or a candidate) echoes into the response regardless of any real
    * leak — confirming on it is the echo trap — so a marker equal to an id is
    * rejected, leaving the proposal to the JSON-field path instead.
    */
  def dataLeak(p: Proposal): Option[String] = p.leak
    .filter(m => m.nonEmpty && m != p.ownValue && !p.candidates.contains(m))

  // Emails and domain-shaped tokens — high-signal, low-noise pieces of content.
  private val tokenRe =
    """(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"""
      .r

  /** Distinctive data tokens (emails, domains) present in the OTHER account's
    * content but NOT in the caller's own — model-free leak markers. If one of
    * these appears in the response to a candidate id (and not in the caller's
    * baseline), that account's data leaked. Shared tokens (CDN/script domains
    * on both pages) drop out, so they cannot false-confirm. Pure.
    */
  def markersFrom(otherContent: String, ownContent: String): Seq[String] =
    val ownTokens = tokenRe.findAllIn(ownContent).map(_.toLowerCase).toSet
    tokenRe.findAllIn(otherContent).toSeq.map(_.trim).filter(_.length >= 5)
      .filterNot(t => ownTokens.contains(t.toLowerCase)).distinct.take(30)

  /** A finding for a confirmed content leak (the marker that came back). */
  def leakFinding(p: Proposal, candidate: String, marker: String): Finding =
    Finding(
      kind = FindingKind.BrokenAccessControl,
      severity = Severity.High,
      evidence = s"${p.method} ${fill(p.urlTemplate, candidate)} returned " +
        s"another account's data ('$marker') to the authenticated caller (IDOR)",
      reproducible = true,
      replay = s"idor ${p.method} ${p.urlTemplate} id=$candidate leak=$marker",
    )

  def toFinding(p: Proposal, candidate: String, leaked: String): Finding =
    Finding(
      kind = FindingKind.BrokenAccessControl,
      severity = Severity.High,
      evidence = s"${p.method} ${fill(
          p.urlTemplate,
          candidate,
        )} returned another caller's '${p.discriminatorField}' ($leaked) (IDOR)",
      reproducible = true,
      replay = s"idor ${p.method} ${p.urlTemplate} id=$candidate field=${p
          .discriminatorField}",
    )

  /** Parse the tool's `proposals` array, dropping malformed/empty entries.
    * Requires a `{id}` placeholder somewhere in the url or body template.
    */
  def parseProposals(proposals: ujson.Value): Seq[Proposal] = proposals.arrOpt
    .getOrElse(Nil).flatMap { p =>
      val field = p.obj.get("discriminatorField").flatMap(_.strOpt)
        .filter(_.nonEmpty).getOrElse("")
      val leak = p.obj.get("leak").flatMap(_.strOpt).filter(_.nonEmpty)
      for
        urlT <- p.obj.get("urlTemplate").flatMap(_.strOpt).filter(_.nonEmpty)
        own <- p.obj.get("ownValue").flatMap(strOrNum)
        method = p.obj.get("method").flatMap(_.strOpt).getOrElse("GET")
        body = p.obj.get("bodyTemplate").flatMap(_.strOpt).filter(_.nonEmpty)
        cands = p.obj.get("candidates").flatMap(_.arrOpt).getOrElse(Nil)
          .flatMap(strOrNum).filter(_.nonEmpty).distinct.take(MaxCandidates)
        // Need a confirmation signal: a JSON field to diff, OR a leak marker.
        if cands.nonEmpty && (field.nonEmpty || leak.isDefined) &&
          (urlT.contains("{id}") || body.exists(_.contains("{id}")))
      yield Proposal(method, urlT, body, own, cands.toSeq, field, leak)
    }.toSeq

  private def strOrNum(v: ujson.Value): Option[String] = v.strOpt.orElse(
    v.numOpt.map(n => if n.isWhole then n.toLong.toString else n.toString),
  )
