package dast.analyzer

import scala.concurrent.ExecutionContext
import scala.concurrent.Future

import org.apache.pekko.actor.typed.ActorSystem
import org.slf4j.LoggerFactory

import dast.ContentIdor
import dast.ContentIdor.Proposal

/** LLM planner that harvests real object IDs from the authenticated pages the
  * browser visited and proposes IDOR tests via the forced tool ([[LlmClient]],
  * the §0.2 boundary). The model finds the ids present in the content (incl.
  * non-enumerable ULIDs/UUIDs), decides which are object references, and where
  * to inject them (query / path / POST body) via a `{id}` template. It uses
  * only ids it actually observed and supplies only parameters; deterministic
  * code confirms.
  *
  * [[renderContext]] / [[renderCross]] / [[inputToProposals]] are pure and unit
  * tested; the transport lives in [[LlmClient]].
  */
object ContentIdorPlanner:

  private val log = LoggerFactory.getLogger("dast.analyzer.ContentIdorPlanner")

  val ToolName = "propose_idor_tests"
  val MaxTokens = 1500
  private val MaxPages = 8
  private val MaxCharsPerPage = 12000

  private val SystemPrompt = "You are the IDOR planning step of a consented scan. You are shown the " +
    "authenticated pages a browser visited and the requests it made. Find the " +
    "object-reference IDs actually present in that content (campaign, order, " +
    "user, account ids, etc., including random ULIDs/UUIDs). Propose IDOR " +
    "tests by calling the tool: a request template with a {id} placeholder " +
    "where the reference goes (a query parameter, a path segment, or a POST " +
    "body field), the caller's OWN id (baseline), candidate ids to try (other " +
    "real ids you saw that may belong to someone else), and the response " +
    "field that is per-user and would reveal another caller's record if it " +
    "differed. Use ONLY ids present in the content; never invent one. Propose " +
    "an empty list if there is no object reference to test. You never write " +
    "code; you only fill the tool's fields."

  private val CrossPrompt = "You are the IDOR planning step of a consented two-account test. You are " +
    "shown YOUR pages (authenticated as the attacker) and ANOTHER account's " +
    "pages (a different user). Propose IDOR tests by calling the tool: a " +
    "request template with a {id} placeholder for the object reference (query " +
    "param, path segment, or POST body field), `ownValue` = an object id from " +
    "YOUR pages (baseline), and `candidates` = object ids from the OTHER " +
    "account's pages (objects that belong to them, not you). The candidates " +
    "MUST be real ids seen in the OTHER account's pages, and MUST NOT be ids " +
    "from your own pages; never invent. Then give `leak`: a SHORT distinctive " +
    "piece of the OTHER account's DATA copied verbatim (a creative name, brand, " +
    "domain, email, or title) that belongs to them and would NOT appear on your " +
    "own pages. CRITICAL: `leak` must be human-readable DATA, NEVER an id, " +
    "ULID, UUID, or the campaignId itself — ids echo into the page and prove " +
    "nothing. We confirm IDOR when that exact data string appears in the " +
    "response to a candidate id. Prefer `leak` (it works for HTML pages too); " +
    "use `discriminatorField` only for a JSON API field. We request the " +
    "candidates AS YOU; if their data comes back, that is IDOR. Empty list if " +
    "there is no object reference to test. You never write code."

  private val schema: ujson.Value = ujson.Obj(
    "type" -> "object",
    "properties" -> ujson.Obj(
      "proposals" -> ujson.Obj(
        "type" -> "array",
        "items" -> ujson.Obj(
          "type" -> "object",
          "properties" -> ujson.Obj(
            "method" ->
              ujson.Obj("type" -> "string", "enum" -> ujson.Arr("GET", "POST")),
            "urlTemplate" -> ujson.Obj("type" -> "string"),
            "bodyTemplate" -> ujson.Obj("type" -> "string"),
            "ownValue" -> ujson.Obj("type" -> "string"),
            "candidates" ->
              ujson
                .Obj("type" -> "array", "items" -> ujson.Obj("type" -> "string")),
            "discriminatorField" -> ujson.Obj("type" -> "string"),
            "leak" -> ujson.Obj("type" -> "string"),
          ),
          "required" -> ujson.Arr("urlTemplate", "ownValue", "candidates"),
        ),
      ),
    ),
    "required" -> ujson.Arr("proposals"),
  )

  val Tool: ToolSpec = ToolSpec(
    ToolName,
    "Propose IDOR tests from observed ids (or an empty list).",
    schema,
  )

  /** Render the visited pages (capped) + observed request URLs for the model.
    */
  def renderContext(
      pages: Seq[(String, String)],
      requests: Seq[String],
  ): String =
    val pageBlocks = pages.take(MaxPages)
      .map((url, html) => s"PAGE $url\n${html.take(MaxCharsPerPage)}")
      .mkString("\n\n")
    s"""Observed requests:
       |${requests.distinct.take(40).mkString("\n")}
       |
       |Authenticated pages:
       |$pageBlocks""".stripMargin

  /** Render two labelled sets -- each with its observed request URLs (where ids
    * reliably appear in query params) and page HTML. The other account's ids
    * are the candidates.
    */
  def renderCross(
      ownPages: Seq[(String, String)],
      ownRequests: Seq[String],
      otherPages: Seq[(String, String)],
      otherRequests: Seq[String],
  ): String =
    def pageBlock(ps: Seq[(String, String)]) = ps.take(MaxPages)
      .map((url, html) => s"PAGE $url\n${html.take(MaxCharsPerPage)}")
      .mkString("\n\n")
    def reqBlock(rs: Seq[String]) = rs.distinct.take(60).mkString("\n")
    s"""=== YOUR account (attacker) ===
       |Requests:
       |${reqBlock(ownRequests)}
       |Pages:
       |${pageBlock(ownPages)}
       |
       |=== OTHER account (use THEIR ids as candidates) ===
       |Requests:
       |${reqBlock(otherRequests)}
       |Pages:
       |${pageBlock(otherPages)}""".stripMargin

  /** Pull the tool input's `proposals` and validate, failing closed. */
  def inputToProposals(input: ujson.Value): Seq[Proposal] = input.objOpt
    .flatMap(_.get("proposals")).map(ContentIdor.parseProposals)
    .getOrElse(Seq.empty)

  def plan(pages: Seq[(String, String)], requests: Seq[String])(using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Seq[Proposal]] = call(SystemPrompt, renderContext(pages, requests))

  /** Two-identity plan: candidates come from the other account's ids. */
  def planCross(
      ownPages: Seq[(String, String)],
      ownRequests: Seq[String],
      otherPages: Seq[(String, String)],
      otherRequests: Seq[String],
  )(using ActorSystem[?], ExecutionContext): Future[Seq[Proposal]] = call(
    CrossPrompt,
    renderCross(ownPages, ownRequests, otherPages, otherRequests),
  )

  private def call(system: String, user: String)(using
      ActorSystem[?],
      ExecutionContext,
  ): Future[Seq[Proposal]] =
    val idLike = "(?i)\\b[0-9A-HJKMNP-TV-Z]{26}\\b".r.findAllIn(user).toSet.size
    log.info(
      "Content-IDOR context: {} chars, ~{} ULID-like id(s) present",
      user.length,
      idLike,
    )
    LlmClient.fromConfig.callTool(system, user, Tool, MaxTokens)
      .map(_.map(inputToProposals).getOrElse(Seq.empty))
