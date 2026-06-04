package dast

import scala.jdk.CollectionConverters.*

import crawler.BrowserResource

/** One interactive element the model may be offered as a click candidate.
  *
  * Plain data (README): produced by enumerating the live DOM, consumed by an
  * LLM planner that returns only an `id` from this audited menu. `id` is the
  * `data-dast-id` attribute the enumeration stamped onto the element, so the
  * deterministic click side can re-resolve it with `[data-dast-id="id"]`
  * without trusting any selector the model authored. `hint` is a stable
  * contextual tag (the control's own id / href, else the nearest ancestor id /
  * `data-id`) that distinguishes otherwise-identically-named controls — e.g.
  * one "View" button per row, each carrying a different object id.
  */
final case class ClickTarget(
    id: Int,
    role: String,
    name: String,
    disabled: Boolean,
    hint: String = "",
):
  /** Stable identity across re-enumerations (the positional `id` is not): used
    * to dedup and cycle-guard a control. Two same-named controls with different
    * `hint`s are distinct, so each gets explored.
    */
  def key: String =
    if hint.isEmpty then s"$role/$name" else s"$role/$name/$hint"

  /** A compact, model-facing description: `#3 button "Add to cart"`. */
  def describe: String =
    val label = if name.isEmpty then "(no name)" else s"\"$name\""
    val flag = if disabled then " [disabled]" else ""
    val ctx = if hint.isEmpty then "" else s" ($hint)"
    s"#$id $role $label$ctx$flag"

/** Enumerate the clickable elements on a page so a planner can pick where to
  * click next (the browser-nav coverage slice discussed in README navigation).
  *
  * This is the click analogue of [[CaptureOp]] / [[SinkScanOp]]: a pre-written
  * template — no model input — gathers the interactive controls, and a pure
  * parser turns the readback into [[ClickTarget]]s. The model never authors the
  * query or a selector; it selects an `id` the parser validated, and the click
  * op resolves that id by the `data-dast-id` attribute this op stamped on.
  *
  * Unlike [[CaptureOp]], enumeration writes a benign `data-dast-id` attribute
  * to each candidate, so it is a (read-mostly) mutation, not strictly
  * observe-only; the orchestrator should gate it like the other active browser
  * ops.
  *
  * It descends into open shadow roots (web components), and the matching
  * `navClick` resolves the stamped id through Playwright's shadow-piercing
  * selector engine. Cross-frame controls (iframes) are still out of scope: a
  * stamped id in a child frame is not reachable from the main frame's
  * `querySelector`. The parsing is pure and unit tested; the page-driving
  * [[scan]] is run-only (needs a live page).
  */
object ClickTargetScanOp:

  /** Installed by evaluating after load: collect visible, interactable controls
    * (piercing open shadow roots), stamp each with a stable `data-dast-id`, and
    * return a compact descriptor list. `checkVisibility` is
    * `position:fixed`-safe (unlike `offsetParent`) and honours display /
    * visibility / opacity / content-visibility.
    */
  val EnumerateJs: String =
    """() => {
      |  const sel = 'a[href],button,input[type=submit],input[type=button],' +
      |    'input[type=image],[role=button],[role=link],[role=tab],[role=menuitem],' +
      |    '[onclick],summary,[tabindex]:not([tabindex="-1"])';
      |  const nodes = [];
      |  const collect = (root) => {
      |    root.querySelectorAll(sel).forEach(el => nodes.push(el));
      |    root.querySelectorAll('*').forEach(el => { if (el.shadowRoot) collect(el.shadowRoot); });
      |  };
      |  collect(document);
      |  const out = []; let i = 0;
      |  for (const el of nodes) {
      |    if (typeof el.checkVisibility === 'function' &&
      |        !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) continue;
      |    const r = el.getBoundingClientRect();
      |    if (r.width === 0 || r.height === 0) continue;
      |    const name = (el.getAttribute('aria-label') || el.innerText || el.value ||
      |      el.title || el.getAttribute('alt') ||
      |      (el.querySelector('img') && el.querySelector('img').alt) || '')
      |      .trim().replace(/\s+/g, ' ').slice(0, 80);
      |    const idAnc = el.closest('[id]');
      |    const dataAnc = el.closest('[data-id]');
      |    const hint = (el.id || el.getAttribute('href') ||
      |      (idAnc && idAnc.id) || (dataAnc && dataAnc.getAttribute('data-id')) || '')
      |      .toString().trim().slice(0, 60);
      |    el.setAttribute('data-dast-id', String(i));
      |    out.push({
      |      id: i,
      |      role: el.getAttribute('role') || el.tagName.toLowerCase(),
      |      name: name,
      |      disabled: el.disabled === true || el.getAttribute('aria-disabled') === 'true',
      |      hint: hint
      |    });
      |    i++;
      |  }
      |  return out;
      |}""".stripMargin

  /** Pure: turn the `EnumerateJs` readback (a JS array of objects, surfaced by
    * Playwright as a `java.util.List` of `java.util.Map`) into
    * [[ClickTarget]]s. Tolerant by construction — a non-list, a non-map row, or
    * a row missing a usable integer `id` is skipped rather than throwing, so a
    * hostile or unusual page cannot break enumeration.
    */
  def parseTargets(raw: Any): Seq[ClickTarget] = raw match
    case l: java.util.List[?] => l.asScala.iterator
        .collect { case m: java.util.Map[?, ?] => m }.flatMap(rowToTarget).toSeq
    case _ => Seq.empty

  private def rowToTarget(row: java.util.Map[?, ?]): Option[ClickTarget] =
    val m = row.asScala.iterator
      .collect { case (k, v) if k != null => k.toString -> (v: Any) }.toMap
    asInt(m.get("id")).map { id =>
      ClickTarget(
        id = id,
        role = asString(m.get("role")).getOrElse("").trim,
        name = asString(m.get("name")).getOrElse("").trim,
        disabled = asBool(m.get("disabled")),
        hint = asString(m.get("hint")).getOrElse("").trim,
      )
    }

  // JS numbers arrive as Integer, Long, or Double depending on the bridge;
  // accept any whole number, reject anything else.
  private def asInt(v: Option[Any]): Option[Int] = v.collect {
    case n: java.lang.Integer => n.intValue()
    case n: java.lang.Long => n.intValue()
    case n: java.lang.Double if n == Math.floor(n) && !n.isInfinite =>
      n.intValue()
  }

  private def asString(v: Option[Any]): Option[String] = v
    .collect { case s if s != null => s.toString }

  private def asBool(v: Option[Any]): Boolean = v.exists {
    case b: java.lang.Boolean => b.booleanValue()
    case s: String => s == "true"
    case _ => false
  }

  /** Run on the pinned thread: load `url`, enumerate the clickable controls.
    * Not unit tested (needs a live page); the parsing it delegates to is.
    */
  def scan(resource: BrowserResource, url: String): Seq[ClickTarget] = resource
    .withPage(url)((page, _) => parseTargets(page.evaluate(EnumerateJs)))
