package dast

import scala.util.Try
import scala.util.matching.Regex

/** Pure logic for the path-traversal / local-file-inclusion probe.
  *
  * When a parameter is used to build a filesystem path without sanitisation, a
  * `../`-laden value escapes the intended directory and reads arbitrary files.
  * The deterministic tell, no body guessing: inject traversal sequences toward
  * well-known OS files and confirm only when a **signature unique to that file**
  * appears in the response and was **absent from the baseline** (so a page that
  * always contains the text is not a false positive).
  *
  * Sound but recall-limited by design: it confirms only files it has a
  * signature for (`/etc/passwd`, `win.ini`). The HTTP requests live in
  * [[PathTraversalProbe]]; the payloads and confirm decision are pure and tested.
  */
object PathTraversalCheck:

  /** Traversal payloads toward a known file, in several encodings that defeat
    * naive `../` stripping. Each is paired with the file it targets.
    */
  val payloads: Seq[String] = Seq(
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
  )

  // Signatures that only appear in the contents of those files.
  private val passwd: Regex = """root:.*:0:0:""".r
  private val winIni: Regex = """(?i)\[(fonts|extensions|mci extensions)\]""".r

  /** The file implicated by a signature in `body`, if any. */
  def detect(body: String): Option[String] =
    if passwd.findFirstIn(body).isDefined then Some("/etc/passwd")
    else if winIni.findFirstIn(body).isDefined then Some("win.ini")
    else None

  /** Confirmed when a known-file signature appears that the baseline lacked. */
  def confirms(baselineBody: String, injectedBody: String): Option[String] =
    detect(injectedBody).filter(_ => detect(baselineBody).isEmpty)

  /** Query-parameter names of a URL: the surfaces probed. Pure. */
  def paramNames(url: String): Seq[String] = Try(
    new java.net.URI(url).getRawQuery,
  ).toOption.flatMap(Option(_))
    .map(_.split("&").toSeq.filter(_.nonEmpty).map(_.split("=", 2)(0)).distinct)
    .getOrElse(Seq.empty)

  def toFinding(point: InjectionPoint, file: String, payload: String): Finding =
    Finding(
      kind = FindingKind.PathTraversal,
      severity = Severity.High,
      evidence =
        s"${point.describe} reads arbitrary files: payload '$payload' returned " +
          s"the contents of '$file' (path traversal / LFI)",
      reproducible = true,
      replay = s"path-traversal ${point.describe} file=$file payload=$payload",
    )
