package dast

import java.util.concurrent.ConcurrentLinkedQueue

import scala.jdk.CollectionConverters.*

/** Opt-in, process-global evidence transcript.
  *
  * When `DAST_EVIDENCE_FILE` is set, every target HTTP request the probes make
  * (and each LLM-directed verdict) is recorded as a JSON line, so a scan's work
  * is provable and replayable after the fact: coverage (what was tested), the
  * act (the exact request + response status/headers/timing this run), and the
  * positive/negative verdict. Off by default — no records kept, no file.
  *
  * One transcript per process/run (a `SiteScanner` run appends every URL). The
  * record/render logic is pure and unit tested; `flush` writes the file.
  */
object EvidenceLog:

  private val records = new ConcurrentLinkedQueue[ujson.Obj]()
  @volatile private var on: Boolean =
    DastConfig.get("DAST_EVIDENCE_FILE").exists(_.nonEmpty)

  /** Whether recording is active (the cheap guard probes check first). */
  def enabled: Boolean = on

  /** Toggle recording and clear the buffer (used by tests; production reads the
    * env at startup).
    */
  def setEnabled(value: Boolean): Unit =
    on = value
    records.clear()

  def record(entry: ujson.Obj): Unit = if on then records.add(entry)

  /** Record one target HTTP request and its response status / headers / timing.
    */
  def http(
      check: String,
      method: String,
      url: String,
      status: Int,
      ms: Long,
      responseHeaders: Seq[(String, String)],
  ): Unit =
    val hdrs = ujson.Obj()
    responseHeaders.foreach((k, v) => hdrs(k) = ujson.Str(v))
    record(ujson.Obj(
      "kind" -> ujson.Str("http"),
      "check" -> ujson.Str(check),
      "method" -> ujson.Str(method),
      "url" -> ujson.Str(url),
      "status" -> ujson.Num(status),
      "ms" -> ujson.Num(ms.toDouble),
      "responseHeaders" -> hdrs,
    ))

  /** Record an LLM-directed choice and the deterministic verdict it led to. */
  def decision(
      check: String,
      point: String,
      choice: String,
      confirmed: Boolean,
  ): Unit = record(ujson.Obj(
    "kind" -> ujson.Str("decision"),
    "check" -> ujson.Str(check),
    "point" -> ujson.Str(point),
    "choice" -> ujson.Str(choice),
    "confirmed" -> ujson.Bool(confirmed),
  ))

  /** The transcript as JSON Lines (one record per line). Pure. */
  def render(): String = records.asScala.map(ujson.write(_)).mkString("\n")

  /** How many records are buffered. */
  def size: Int = records.size

  /** Write the transcript to `DAST_EVIDENCE_FILE` if set. Best-effort. */
  def flush(): Unit = DastConfig.get("DAST_EVIDENCE_FILE").filter(_.nonEmpty)
    .foreach { path =>
      try java.nio.file.Files
        .writeString(java.nio.file.Paths.get(path), render() + "\n")
      catch { case _: Exception => () }
    }
