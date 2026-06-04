package dast

import scala.util.Try

/** Pure logic for the server-side template injection (SSTI) probe.
  *
  * SSTI is when user input is concatenated into a server-side template, so an
  * attacker-supplied expression is *evaluated* (often a path to RCE). The
  * deterministic tell, with no body guessing: inject a distinctive arithmetic
  * expression in each common engine's syntax and confirm only when the
  * **product appears in the response while the raw expression does not** — proof
  * the server evaluated it, not merely reflected it (the reflection trap that
  * makes naive checks false-positive, as with XSS). The product is also required
  * to be absent from the baseline, so a page that happens to contain the number
  * is not a false positive.
  *
  * The browser-free HTTP requests live in [[SstiProbe]]; the payloads and the
  * confirm decision here are pure and unit tested.
  */
object SstiCheck:

  // Two factors whose product is distinctive enough not to occur by chance.
  private val factorA = 1337
  private val factorB = 7331

  /** The evaluated result a vulnerable engine returns (e.g. "9802147"). */
  val product: String = (factorA.toLong * factorB).toString

  /** The raw expression; its presence in the response means reflection (the
    * engine did NOT evaluate), so a confirm requires it to be absent.
    */
  val expr: String = s"$factorA*$factorB"

  /** The same expression in the syntaxes of the common template engines. */
  val payloads: Seq[String] = Seq(
    "{{" + expr + "}}", // Jinja2, Twig, Nunjucks, Handlebars
    "${" + expr + "}", // FreeMarker, JSP EL, Spring, Thymeleaf ${}
    "#{" + expr + "}", // Ruby, JSF EL
    "*{" + expr + "}", // Thymeleaf
    "<%= " + expr + " %>", // ERB
    "{" + expr + "}", // a few minimal engines
  )

  /** Query-parameter names of a URL: the surfaces probed. Pure. */
  def paramNames(url: String): Seq[String] = Try(
    new java.net.URI(url).getRawQuery,
  ).toOption.flatMap(Option(_))
    .map(_.split("&").toSeq.filter(_.nonEmpty).map(_.split("=", 2)(0)).distinct)
    .getOrElse(Seq.empty)

  /** Confirmed when the evaluated product appears (and was not already in the
    * baseline) while the raw expression does not — server-side evaluation, not
    * reflection.
    */
  def confirms(baselineBody: String, injectedBody: String): Boolean =
    injectedBody.contains(product) && !baselineBody.contains(product) &&
      !injectedBody.contains(expr)

  def toFinding(point: InjectionPoint, payload: String): Finding = Finding(
    kind = FindingKind.Ssti,
    severity = Severity.High,
    evidence =
      s"${point.describe} evaluates a template expression server-side " +
        s"(payload '$payload' returned $product) — server-side template injection",
    reproducible = true,
    replay = s"ssti ${point.describe} payload=$payload",
  )
