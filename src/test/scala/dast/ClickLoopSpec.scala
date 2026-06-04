package dast

import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration.*

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ClickLoopSpec extends AnyWordSpec with Matchers {

  private val seed = "https://app.example/seed"
  private val authed = Authorization.active("app.example")
  private def benign(id: Int) =
    ClickTarget(id, "button", "Open menu", disabled = false)

  /** A fake live page: fixed enumerated controls; `onClick` decides the reached
    * state. Counts how many times the browser was actually clicked.
    */
  private class FakeEffects(
      targets: Seq[ClickTarget],
      onClick: Int => Option[(String, String)],
  ) extends ClickLoop.Effects {
    var clicks = 0
    def enumerate(): Future[Seq[ClickTarget]] = Future.successful(targets)
    def click(elementId: Int): Future[Option[(String, String)]] =
      clicks += 1; Future.successful(onClick(elementId))
  }

  private def run(
      planner: ClickLoop.Planner,
      effects: ClickLoop.Effects,
      auth: Authorization = authed,
      maxClicks: Int = 5,
  ): ClickLoop.Outcome = Await.result(
    ClickLoop.explore(seed, "<html/>", auth, planner, effects, maxClicks),
    5.seconds,
  )

  private val alwaysClick0: ClickLoop.Planner =
    (_, _, _, _) => Future.successful(ClickStep.Click(0))

  "ClickLoop.explore" should {

    "return only the seed when the planner is immediately done" in {
      val eff = new FakeEffects(Seq(benign(0)), _ => Some((seed, "h")))
      val out = run((_, _, _, _) => Future.successful(ClickStep.Done), eff)
      out.pages.map(_._1) shouldBe Vector(seed)
      out.clicksPerformed shouldBe 0
      eff.clicks shouldBe 0
    }

    "spend at most the click budget and collect each new page reached" in {
      var n = 0
      val eff = new FakeEffects(
        Seq(benign(0)),
        _ => { n += 1; Some((s"https://app.example/u$n", "h")) },
      )
      val out = run(alwaysClick0, eff, maxClicks = 3)
      eff.clicks shouldBe 3
      out.clicksPerformed shouldBe 3
      out.pages.map(_._1) shouldBe Vector(
        seed,
        "https://app.example/u1",
        "https://app.example/u2",
        "https://app.example/u3",
      )
    }

    "stop on the cycle guard when a click reveals nothing new" in {
      // Clicking lands back on the identical seed state (same url + html): the
      // same control on the same page is a repeat, so the loop converges after
      // one click.
      val eff = new FakeEffects(Seq(benign(0)), _ => Some((seed, "<html/>")))
      val out = run(alwaysClick0, eff)
      eff.clicks shouldBe 1
      out.clicksPerformed shouldBe 1
      out.pages.map(_._1) shouldBe Vector(seed)
    }

    "never click under observe-only authorization (gate denies)" in {
      val eff = new FakeEffects(Seq(benign(0)), _ => Some((seed, "h")))
      val out = run(alwaysClick0, eff, auth = Authorization.ObserveOnly)
      eff.clicks shouldBe 0
      out.clicksPerformed shouldBe 0
      out.pages.map(_._1) shouldBe Vector(seed)
    }

    "never click a destructive control even when authorized" in {
      val destructive =
        ClickTarget(0, "button", "Delete account", disabled = false)
      val eff = new FakeEffects(Seq(destructive), _ => Some((seed, "h")))
      val out = run(alwaysClick0, eff)
      eff.clicks shouldBe 0
      out.clicksPerformed shouldBe 0
      out.pages.map(_._1) shouldBe Vector(seed)
    }

    "never click an id the model invented off the enumerated menu" in {
      val eff = new FakeEffects(Seq(benign(0)), _ => Some((seed, "h")))
      val out = run((_, _, _, _) => Future.successful(ClickStep.Click(99)), eff)
      eff.clicks shouldBe 0
      out.clicksPerformed shouldBe 0
      out.pages.map(_._1) shouldBe Vector(seed)
    }

    "tell the planner which controls were already clicked so it advances" in {
      // Two controls; clicking changes the DOM but not the url (an in-page
      // reveal). The planner picks the first control it has NOT been told it
      // clicked, so it should click A then B then finish — not loop on A.
      val targets = Seq(
        ClickTarget(0, "button", "A", false),
        ClickTarget(1, "button", "B", false),
      )
      var clickedArgs = List.empty[Seq[String]]
      var n = 0
      val eff = new FakeEffects(targets, _ => { n += 1; Some((seed, s"h$n")) })
      val planner: ClickLoop.Planner = (_, ts, _, clicked) =>
        clickedArgs = clickedArgs :+ clicked
        Future.successful(
          ts.find(t => !clicked.contains(s"${t.role}/${t.name}"))
            .map(t => ClickStep.Click(t.id)).getOrElse(ClickStep.Done),
        )
      val out = run(planner, eff)
      out.clicksPerformed shouldBe 2
      clickedArgs.head shouldBe Seq.empty
      clickedArgs.exists(_.contains("button/A")) shouldBe true
    }

    "scroll to load more rows, surfacing new controls, then stop when exhausted" in {
      // Each scroll loads one more row (a new control), until three rows exist;
      // then scroll returns None and the dry counter stops the loop.
      var rows = 1
      var scrolls = 0
      val effects = new ClickLoop.Effects {
        def enumerate(): Future[Seq[ClickTarget]] = Future
          .successful((0 until rows).map(i =>
            ClickTarget(i, "button", "View", disabled = false, hint = s"row-$i"),
          ))
        def click(elementId: Int): Future[Option[(String, String)]] = Future
          .successful(None)
        override def scroll(): Future[Option[(String, String)]] =
          scrolls += 1
          if rows < 3 then
            rows += 1
            Future.successful(Some((seed, s"rows-$rows")))
          else Future.successful(None)
      }
      val out = run((_, _, _, _) => Future.successful(ClickStep.Scroll), effects)
      out.clicksPerformed shouldBe 0 // scrolling is not a click
      scrolls should be >= 3
      // the seed plus the two loaded states were captured for the planner
      out.pages.map(_._2).distinct.size shouldBe 3
    }
  }
}
