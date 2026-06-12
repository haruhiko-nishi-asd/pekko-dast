package dast.scan

/** Renders a scan's findings as a remediation brief: a Markdown document that
  * doubles as an instruction set for a coding agent tasked with patching them.
  *
  * Input is the parsed [[FindingsReport]] JSON — either the single-target shape
  * `{target, findingCount, findings}` or the site shape `{seed, findingCount,
  * pages}`. Each confirmed finding becomes a numbered task carrying the dynamic
  * evidence and the model-free replay handle the scanner captured, plus the
  * [[Remediation]] guidance (CWE/OWASP, root cause, where to look, how to fix,
  * how to verify). The agent supplies the source-code knowledge the scanner
  * lacks. All rendering is pure and unit tested; the file write lives in
  * [[ScanMain]].
  */
object RemediationReport:

  private case class Item(
      url: Option[String],
      kind: String,
      severity: String,
      evidence: String,
      reproducible: Boolean,
      replay: String,
  )

  /** Render the whole report as a Markdown remediation brief. */
  def render(report: ujson.Value): String =
    val o = report.objOpt
      .getOrElse(scala.collection.mutable.LinkedHashMap.empty[String, ujson.Value])
    val target = o.get("seed").orElse(o.get("target")).flatMap(_.strOpt)
      .getOrElse("the application")
    val items = collect(o).sortBy(i => severityRank(i.severity))

    val header = preamble(target, items)
    val tasks =
      if items.isEmpty then
        "No confirmed findings — there is nothing to patch.\n"
      else items.zipWithIndex.map((it, i) => task(it, i + 1)).mkString("\n")
    s"$header\n$tasks"

  /** Flatten findings from either report shape, attaching the page URL when the
    * report is a multi-URL site scan.
    */
  private def collect(
      o: scala.collection.Map[String, ujson.Value],
  ): Seq[Item] =
    o.get("pages").flatMap(_.arrOpt) match
      case Some(pages) => pages.toSeq.flatMap { p =>
          val po = p.objOpt.getOrElse(
            scala.collection.mutable.LinkedHashMap.empty[String, ujson.Value],
          )
          val url = po.get("url").flatMap(_.strOpt)
          po.get("findings").flatMap(_.arrOpt).map(_.toSeq).getOrElse(Nil)
            .map(item(_, url))
        }
      case None => o.get("findings").flatMap(_.arrOpt).map(_.toSeq)
          .getOrElse(Nil).map(item(_, None))

  private def item(f: ujson.Value, url: Option[String]): Item =
    val fo = f.objOpt
      .getOrElse(scala.collection.mutable.LinkedHashMap.empty[String, ujson.Value])
    def str(k: String) = fo.get(k).flatMap(_.strOpt).getOrElse("")
    Item(
      url = url,
      kind = str("kind"),
      severity = fo.get("severity").flatMap(_.strOpt).getOrElse("Info"),
      evidence = str("evidence"),
      reproducible = fo.get("reproducible").flatMap(_.boolOpt).getOrElse(false),
      replay = str("replay"),
    )

  private def preamble(target: String, items: Seq[Item]): String =
    val counts = Seq("Critical", "High", "Medium", "Low", "Info")
      .map(s => s -> items.count(_.severity == s)).filter(_._2 > 0)
      .map((s, n) => s"$n $s").mkString(", ")
    val summary =
      if items.isEmpty then "0" else s"${items.size} ($counts)"
    s"""# Security remediation brief — $target
       |
       |You are a security engineer with access to the source code of the
       |application that was tested. A dynamic scan (DAST) against the *running*
       |app produced the findings below. Your job: for each one, locate the
       |responsible code, apply the fix, and verify it.
       |
       |How to use this document:
       |- Every finding here was **deterministically confirmed** — reproduced
       |  against the live app, not guessed. Treat each as a real bug, in
       |  severity order (most severe first).
       |- The scanner has **no source access**, so no file paths are given. Use
       |  the evidence and the reproduction handle to find the responsible code.
       |- Make the **smallest correct fix** for each finding. Do not weaken or
       |  delete existing tests; add a regression test where the stack allows.
       |- Treat each fix as complete only when its **Verify** condition holds
       |  (re-running the scanner's probe should no longer confirm the finding).
       |
       |Confirmed findings: $summary
       |""".stripMargin

  private def task(it: Item, n: Int): String =
    val g = Remediation.forKind(it.kind)
    val loc = it.url.map(u => s"\n**Endpoint:** $u").getOrElse("")
    val unconfirmed =
      if it.reproducible then ""
      else
        "\n> Note: this finding was not deterministically confirmed — validate " +
          "it before changing code.\n"
    s"""## ${n}. [${it.severity.toUpperCase}] ${g.title} — ${g.cwe} (${g.owasp})
       |$unconfirmed
       |**Where it was found (live evidence):** ${it.evidence}$loc
       |
       |**Reproduce:**
       |```
       |${it.replay}
       |```
       |
       |**Root cause:** ${g.rootCause}
       |
       |**Locate in code:** ${g.locate}
       |
       |**Fix:** ${g.fix}
       |
       |**Verify:** ${g.verify}
       |""".stripMargin

  private def severityRank(severity: String): Int = severity match
    case "Critical" => 0
    case "High" => 1
    case "Medium" => 2
    case "Low" => 3
    case _ => 4
