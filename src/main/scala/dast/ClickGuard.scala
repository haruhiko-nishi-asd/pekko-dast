package dast

/** The deterministic safety floor for LLM-directed clicking — the click
  * analogue of [[ActionGuard]].
  *
  * A click reaches new application state without the model authoring how, but
  * clicking the wrong control can delete, pay, or log out. So the model's
  * choice is necessary, never sufficient: a control whose accessible name or
  * role matches the destructive deny-list is refused, as is a disabled control.
  * The deny-list is the hard floor, so a model misjudgement still cannot fire a
  * destructive action. It shares [[ActionGuard]]'s destructive vocabulary and,
  * like it, matches on substrings — so it errs toward refusal (a "Display"
  * button can be skipped because it contains "pay"); skipping a safe control is
  * the acceptable cost of never firing a destructive one. Pure and unit tested.
  */
object ClickGuard:

  /** Substrings that mark a likely state-changing or destructive control. */
  private val denyPatterns: Seq[String] = Seq(
    "delete",
    "remove",
    "destroy",
    "drop",
    "pay",
    "payment",
    "checkout",
    "purchase",
    "buy",
    "transfer",
    "withdraw",
    "logout",
    "log out",
    "signout",
    "sign out",
    "sign-out",
    "password",
    "confirm",
    "cancel",
    "deactivate",
    "unsubscribe",
    "subscribe",
  )

  // Whole-word match (lowercased), so "pay" blocks "Pay now" but not "Display",
  // and "cancel" blocks "Cancel order" but the word must stand alone. Hyphen /
  // space inside a pattern (`sign-out`, `log out`) is matched literally.
  private val denyRegex: scala.util.matching.Regex =
    ("(?i)\\b(" + denyPatterns.map(java.util.regex.Pattern.quote)
      .mkString("|") + ")\\b").r

  private def denyHit(target: ClickTarget): Option[String] =
    val haystack = (target.name + " " + target.role).toLowerCase
    denyRegex.findFirstIn(haystack)

  /** `Right` to click, `Left(reason)` to refuse. */
  def allow(target: ClickTarget): Either[String, Unit] =
    if target.disabled then Left("control is disabled")
    else
      denyHit(target) match
        case Some(p) => Left(s"matches destructive pattern '$p'")
        case None => Right(())
