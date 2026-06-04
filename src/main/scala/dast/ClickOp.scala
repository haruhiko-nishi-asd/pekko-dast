package dast

import crawler.BrowserResource

/** Active op: click an enumerated control the model chose, on the live nav page
  * where the matching [[ClickTargetScanOp]] enumeration stamped its
  * `data-dast-id`.
  *
  * Active testing, so it is gated by [[ConsentGate]] and screened by
  * [[ClickGuard]] and fails closed: both run in [[precheck]] before any browser
  * work, so a denied or destructive click never fires. The model supplied only
  * the element id (validated upstream by `DecisionParser` and bounded by the
  * enumerated set); it never authored a selector.
  *
  * [[precheck]] is pure and unit tested. The browser-driving [[click]] is
  * exercised only against a live, consenting target (stated, not unit tested).
  */
object ClickOp:

  /** Authorize and screen before any browser work. `Left` means do not click
    * (denied by the gate, or refused by the destructive floor). Pure.
    */
  def precheck(
      auth: Authorization,
      currentUrl: String,
      target: ClickTarget,
  ): Either[String, Unit] =
    ConsentGate.decide(auth, ActionClass.Active, currentUrl) match
      case GateDecision.Deny(reason) => Left(reason)
      case GateDecision.Permit => ClickGuard.allow(target)

  /** Browser-side click on the pinned thread. Composes [[precheck]] (fail
    * closed) with the click on the live nav page; the loop reads `navUrl` /
    * `navHtml` afterwards to observe the reached state. `Left` is a refusal
    * reason or a missing element; `Right(())` means the control was clicked.
    * Not unit tested (needs a live page); precheck is.
    */
  def click(
      resource: BrowserResource,
      auth: Authorization,
      currentUrl: String,
      target: ClickTarget,
      navTimeoutMs: Int = 15000,
  ): Either[String, Unit] = precheck(auth, currentUrl, target).flatMap { _ =>
    if resource.navClick(target.id, navTimeoutMs) then Right(())
    else Left(s"no element with data-dast-id=${target.id} on the page")
  }
