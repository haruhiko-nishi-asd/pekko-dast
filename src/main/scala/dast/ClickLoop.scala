package dast

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.slf4j.LoggerFactory

/** Browser-driven, LLM-directed click exploration: from a live page, repeatedly
  * enumerate the clickable controls, ask the planner for ONE to click, gate and
  * screen it, click it, and harvest the state it reveals — extending coverage to
  * content behind JS buttons that a link/form crawl never reaches.
  *
  * This is the click analogue of [[NavLoop]], but its core is pure and unit
  * tested: the browser is injected as [[Effects]], so the budget / cycle / dry
  * guards and the [[ClickOp.precheck]] gating are exercised without a real page.
  * Termination is guaranteed three ways, as in [[NavLoop]]: a click budget (each
  * iteration spends one), a cycle guard (re-picking the SAME control — by
  * identity, not its re-stamped id — on the same page ends the loop), and a dry
  * counter (clicks that reveal no new url+DOM state). Every click clears
  * [[ConsentGate]] and the [[ClickGuard]] destructive floor; a denied, off-menu,
  * or not-found choice is skipped (counted dry), never fired.
  */
object ClickLoop:

  private val log = LoggerFactory.getLogger("dast.ClickLoop")

  private val DryLimit = 2

  /** A planner: (current url, enumerated controls, history of reached urls,
    * identity keys `role/name` of controls already clicked on this page) -> one
    * [[ClickStep]]. The last argument lets the planner avoid re-picking a
    * control it already clicked (an in-page reveal keeps the same url).
    */
  type Planner =
    (String, Seq[ClickTarget], Seq[String], Seq[String]) => Future[ClickStep]

  /** The live-browser effects the loop drives (run-only). Implemented over a
    * [[crawler.BrowserResource]] nav session; faked in tests.
    */
  trait Effects:
    /** Enumerate the clickable controls on the live page (fresh ids per call,
      * since the DOM mutates after every click).
      */
    def enumerate(): Future[Seq[ClickTarget]]

    /** Click the control with `elementId`; `Some((url, html))` is the state it
      * revealed, `None` means the element was absent or the click did nothing.
      */
    def click(elementId: Int): Future[Option[(String, String)]]

  /** The result of exploring one live page: every distinct page reached
    * (including the seed) and how many real clicks were spent — the latter lets
    * a caller share one click budget across several pages.
    */
  final case class Outcome(pages: Vector[(String, String)], clicksPerformed: Int)

  /** Explore from a live page. `maxClicks` bounds the iterations (an upper bound
    * on clicks). `history0` seeds the reached-page set, so a caller can thread
    * it across pages to keep the set distinct.
    */
  def explore(
      seedUrl: String,
      seedHtml: String,
      auth: Authorization,
      planner: Planner,
      effects: Effects,
      maxClicks: Int,
      history0: Vector[(String, String)] = Vector.empty,
  )(using ExecutionContext): Future[Outcome] =

    def loop(
        url: String,
        html: String,
        visited: Set[String],
        seenControls: Set[String],
        seenUrls: Set[String],
        clicksLeft: Int,
        dry: Int,
        performed: Int,
        acc: Vector[(String, String)],
    ): Future[Outcome] =
      // Dedup by the (url, html) PAIR, not the url alone: an in-page reveal
      // keeps the url but changes the DOM, and that richer state carries object
      // ids the planner needs, so it must reach the reached-pages set.
      val acc2 = if acc.contains((url, html)) then acc else acc :+ (url -> html)
      if clicksLeft <= 0 then Future.successful(Outcome(acc2, performed))
      else
        effects.enumerate().flatMap { targets =>
          log.info("Enumerated {} clickable(s) on {}", targets.size, url)
          // Progress = a control identity we have not seen, or a url we have not
          // reached. Keyed on identity/url, not the full HTML, so cosmetic DOM
          // churn (timestamps, nonces) does not read as progress and stall the
          // dry counter; a genuine reveal (new controls) or a navigation does.
          val keys = targets.map(_.key).toSet
          val advanced = (keys -- seenControls).nonEmpty || !seenUrls.contains(url)
          val dry2 = if advanced then 0 else dry + 1
          if dry2 >= DryLimit then Future.successful(Outcome(acc2, performed))
          else
            val seenControls2 = seenControls ++ keys
            val seenUrls2 = seenUrls + url
            val clickedHere = targets.collect {
              case t if visited.contains(s"click:${t.key}@$url") => t.key
            }
            planner(url, targets, acc2.map(_._1).distinct, clickedHere).flatMap {
              step =>
                step match
                  case ClickStep.Done =>
                    Future.successful(Outcome(acc2, performed))
                  case ClickStep.Click(id) =>
                    targets.find(_.id == id) match
                      case None =>
                        log.info("Click {} off the menu on {}; skipping", id, url)
                        loop(url, html, visited, seenControls2, seenUrls2, clicksLeft - 1, dry2, performed, acc2)
                      case Some(t) =>
                        // Signature by the control's stable identity key
                        // (role/name/hint), NOT its data-dast-id (re-stamped per
                        // enumeration). Re-picking the SAME control on the SAME
                        // page ends the loop; the hint keeps a list of same-named
                        // controls (one "View" per row) distinct, so each is
                        // explored.
                        val sig = s"click:${t.key}@$url"
                        if visited.contains(sig) then
                          Future.successful(Outcome(acc2, performed))
                        else
                          ClickOp.precheck(auth, url, t) match
                            case Left(reason) =>
                              log.info("Click '{}' on {} refused: {}", t.describe, url, reason)
                              loop(url, html, visited + sig, seenControls2, seenUrls2, clicksLeft - 1, dry2, performed, acc2)
                            case Right(_) =>
                              effects.click(id).flatMap { reached =>
                                val (nu, nh) = reached.getOrElse((url, html))
                                loop(nu, nh, visited + sig, seenControls2, seenUrls2, clicksLeft - 1, dry2, performed + 1, acc2)
                              }
            }
        }

    loop(seedUrl, seedHtml, Set.empty, Set.empty, Set.empty, maxClicks, 0, 0, history0)
