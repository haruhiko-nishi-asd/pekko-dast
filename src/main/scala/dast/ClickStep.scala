package dast

/** One model-chosen click move (closed ADT, the click analogue of [[NavStep]]).
  * The model selects an enumerated control by its `data-dast-id`; it never
  * invents a selector. Parsing is the boundary and fails closed to [[Done]].
  */
enum ClickStep:
  case Click(elementId: Int)
  case Done

object ClickStep:

  /** Parse the planner's tool input into one step; anything off-menu (unknown
    * action, missing/negative/non-integer id) becomes [[Done]], which ends the
    * loop.
    */
  def parse(input: ujson.Value): ClickStep = input.objOpt
    .flatMap(_.get("action")).flatMap(_.strOpt).map(_.toLowerCase) match
    case Some("click") => intField(input, "elementId")
        .filter(_ >= 0).map(ClickStep.Click(_)).getOrElse(ClickStep.Done)
    case _ => ClickStep.Done

  /** Render the current page (indexed clickable controls) and history for the
    * planner. `history` lists URLs already reached; `clicked` lists the
    * `role/name` identity keys of controls already clicked on THIS page, which
    * are marked so the model picks a fresh one (an in-page reveal does not
    * change the URL, so without this the model re-picks the same control).
    */
  def render(
      url: String,
      targets: Seq[ClickTarget],
      history: Seq[String],
      clicked: Seq[String],
  ): String =
    val clickedSet = clicked.toSet
    val ts = targets.map { t =>
      val mark = if clickedSet.contains(t.key) then "  (already clicked)" else ""
      s"  ${t.describe}$mark"
    }.mkString("\n")
    s"""Current page: $url
       |Clickable controls:
       |${if targets.isEmpty then "  (none)" else ts}
       |Already reached: ${
        if history.isEmpty then "(nothing yet)" else history.mkString(", ")
      }
       |
       |Choose ONE control you have NOT already clicked, by its id, to reveal new
       |application state (open a menu, tab, accordion, or detail view), or done.
       |Never choose a control that creates, updates, deletes, pays, or logs out.
       |Choose done when nothing new remains.""".stripMargin

  private def intField(v: ujson.Value, name: String): Option[Int] = v.objOpt
    .flatMap(_.get(name))
    .flatMap(x => x.numOpt.map(_.toInt).orElse(x.strOpt.flatMap(_.toIntOption)))
