package dast.scan

/** Curated, source-free remediation knowledge per finding kind: the CWE/OWASP
  * mapping plus agent-oriented guidance (root cause, where to look in code, how
  * to fix, how to verify).
  *
  * DAST has no access to the target's source, so this guidance is written for a
  * coding agent that DOES have the repository: it pairs the vulnerability class
  * with the dynamic evidence the scanner already captured so the agent can find
  * the responsible code, fix it, and verify by re-running the probe. Pure and
  * unit tested.
  */
object Remediation:

  /** Remediation guidance for one finding kind. Each field is one short,
    * actionable paragraph aimed at a coding agent operating in the target repo.
    */
  final case class Guidance(
      title: String,
      cwe: String,
      owasp: String,
      rootCause: String,
      locate: String,
      fix: String,
      verify: String,
  )

  /** Guidance for a finding `kind` (the `FindingKind` enum name). Unknown kinds
    * fall back to a generic, still-actionable template.
    */
  def forKind(kind: String): Guidance = byKind
    .getOrElse(kind, generic.copy(title = kind))

  private val generic = Guidance(
    title = "Security finding",
    cwe = "CWE-noinfo",
    owasp = "OWASP Top 10",
    rootCause = "See the evidence and reproduction below.",
    locate =
      "Trace the request in the reproduction to the handler that serves it.",
    fix = "Apply the standard mitigation for this vulnerability class.",
    verify =
      "Re-run the scanner's probe (the replay handle) and confirm it no longer " +
        "fires.",
  )

  private val byKind: Map[String, Guidance] = Map(
    "SqlInjection" -> Guidance(
      title = "SQL injection",
      cwe = "CWE-89",
      owasp = "A03:2021 Injection",
      rootCause =
        "User-controlled input is concatenated into a SQL query instead of " +
          "being passed as a bound parameter, so the input can change the " +
          "query's structure.",
      locate =
        "Find the request handler for the endpoint and parameter named in the " +
          "evidence, then trace that parameter to where it builds a SQL " +
          "statement — string concatenation/interpolation into a query, or an " +
          "ORM raw/literal call.",
      fix =
        "Use parameterized queries / prepared statements (bound parameters) " +
          "for every user input; never assemble SQL by string concatenation. " +
          "For an unavoidable dynamic identifier (table/column), validate it " +
          "against an allow-list. Run the app's DB account with least privilege.",
      verify =
        "The injected single quote no longer produces a DB error, and the " +
          "time-based payloads no longer delay the response.",
    ),
    "Xss" -> Guidance(
      title = "Cross-site scripting (XSS)",
      cwe = "CWE-79",
      owasp = "A03:2021 Injection",
      rootCause =
        "Attacker-controlled input reaches the page (server-rendered or via " +
          "the DOM) without contextual output encoding, so it executes as " +
          "script.",
      locate =
        "For reflected XSS, find where the parameter in the evidence is " +
          "written into the response. For DOM XSS, find the sink the injected " +
          "marker reached (innerHTML, outerHTML, document.write, eval, " +
          "insertAdjacentHTML, a framework's raw-HTML escape hatch).",
      fix =
        "Encode output for its context (HTML / attribute / JS / URL) and rely " +
          "on framework auto-escaping; never feed untrusted data to innerHTML " +
          "or dangerouslySetInnerHTML — use textContent, or sanitize HTML with " +
          "a vetted library (e.g. DOMPurify). Add a strict Content-Security-" +
          "Policy as defense in depth.",
      verify =
        "The payload marker no longer executes in the browser and no longer " +
          "reaches a dangerous DOM sink.",
    ),
    "Ssti" -> Guidance(
      title = "Server-side template injection",
      cwe = "CWE-1336",
      owasp = "A03:2021 Injection",
      rootCause =
        "User input is concatenated into a server-side template that the " +
          "engine then evaluates, so an attacker expression runs on the " +
          "server (frequently a path to remote code execution).",
      locate =
        "Find where the parameter is rendered and look for a template built " +
          "from user input — render_template_string, new Template(userInput), " +
          "string concatenation into a template, or an eval-like helper.",
      fix =
        "Never compile a template from user input; pass user data as template " +
          "context/variables, never as template source. Prefer a logic-less or " +
          "sandboxed engine.",
      verify =
        "The arithmetic payload is no longer evaluated (the product value no " +
          "longer appears in the response).",
    ),
    "PathTraversal" -> Guidance(
      title = "Path traversal / local file inclusion",
      cwe = "CWE-22",
      owasp = "A01:2021 Broken Access Control",
      rootCause =
        "A user-controlled value is used to build a filesystem path without " +
          "normalization, so '../' sequences escape the intended directory.",
      locate =
        "Find the handler for the parameter in the evidence that opens or " +
          "reads a file, and look for a path join using user input.",
      fix =
        "Canonicalize the resolved path and verify it stays within an allow-" +
          "listed base directory (resolve, then check the prefix); reject '..', " +
          "absolute paths, and null bytes. Prefer mapping user input to an " +
          "internal id rather than accepting a filename at all.",
      verify = "The traversal payloads no longer return file contents.",
    ),
    "Ssrf" -> Guidance(
      title = "Server-side request forgery",
      cwe = "CWE-918",
      owasp = "A10:2021 Server-Side Request Forgery",
      rootCause =
        "The server makes an outbound request to a URL derived from user input " +
          "without restricting the destination.",
      locate =
        "Find where the parameter feeds an HTTP/URL fetch — an image or " +
          "webhook fetch, a URL preview, a proxy, or an import-from-URL feature.",
      fix =
        "Allow-list permitted hosts and schemes; resolve the destination and " +
          "block private, loopback, link-local, and cloud-metadata IP ranges, " +
          "re-validating the resolved IP at connect time to defeat DNS " +
          "rebinding; disable unneeded redirects; route egress through a " +
          "restricted proxy.",
      verify = "The out-of-band callback to the listener no longer fires.",
    ),
    "OpenRedirect" -> Guidance(
      title = "Open redirect",
      cwe = "CWE-601",
      owasp = "A01:2021 Broken Access Control",
      rootCause =
        "A redirect target is taken from a request parameter and the app " +
          "redirects off-site without checking it stays on-origin.",
      locate =
        "Find where the parameter (next, url, returnTo, redirect, and similar) " +
          "is used to build a redirect or Location header.",
      fix =
        "Only redirect to relative paths or an allow-list of trusted hosts; " +
          "reject absolute URLs and scheme-relative ('//host') targets; map " +
          "user input to internal keys rather than raw URLs.",
      verify = "The sentinel host no longer appears in the Location header.",
    ),
    "Cors" -> Guidance(
      title = "CORS misconfiguration",
      cwe = "CWE-942",
      owasp = "A05:2021 Security Misconfiguration",
      rootCause =
        "The CORS policy reflects an arbitrary Origin (and may allow " +
          "credentials), letting any site read authenticated responses.",
      locate =
        "Find the CORS configuration or middleware that sets Access-Control-" +
          "Allow-Origin — often by echoing back the request's Origin header.",
      fix =
        "Reflect only an explicit allow-list of trusted origins; never pair " +
          "Access-Control-Allow-Credentials: true with a reflected or wildcard " +
          "origin; do not trust the 'null' origin.",
      verify = "A forged Origin is no longer reflected in the ACAO header.",
    ),
    "JwtWeakness" -> Guidance(
      title = "JWT weakness",
      cwe = "CWE-347",
      owasp = "A02:2021 Cryptographic Failures",
      rootCause =
        "Tokens are forgeable: either 'alg: none' is accepted (no signature is " +
          "verified) or the HMAC signing secret is weak and guessable.",
      locate =
        "Find the JWT verification setup — the library configuration, the set " +
          "of accepted algorithms, and where the signing secret comes from.",
      fix =
        "Pin the expected algorithm and reject 'none' and algorithm-confusion " +
          "(RS/HS) attacks; use a long, random, secret-managed signing key (or " +
          "asymmetric keys); always verify the signature plus exp and iss/aud.",
      verify =
        "A token using 'alg: none', or signed with the old weak secret, is now " +
          "rejected.",
    ),
    "BrokenAccessControl" -> Guidance(
      title = "Broken access control (IDOR)",
      cwe = "CWE-639",
      owasp = "A01:2021 Broken Access Control",
      rootCause =
        "An object is fetched by a client-supplied id without checking that " +
          "the authenticated caller is authorized for that object, so changing " +
          "the id returns another user's data.",
      locate =
        "Find the handler for the endpoint in the evidence and look for a " +
          "lookup by id (from the path, query, or body) that has no ownership " +
          "or role check.",
      fix =
        "Enforce an authorization check on every object access — the caller " +
          "owns the object, or holds a role that grants it; scope the query to " +
          "the caller's user/tenant. Unguessable ids are only defense in depth, " +
          "not the access control itself.",
      verify =
        "Requesting a neighbour's id now returns 403/404 and the discriminator " +
          "field no longer leaks another caller's data.",
    ),
    "InsecureCookie" -> Guidance(
      title = "Insecure cookie flags",
      cwe = "CWE-1004",
      owasp = "A05:2021 Security Misconfiguration",
      rootCause =
        "A session cookie is missing HttpOnly, Secure, or SameSite, exposing " +
          "it to theft by script, leakage over plaintext, or cross-site sending.",
      locate =
        "Find where the session cookie is set — the auth middleware or the " +
          "framework's session configuration.",
      fix =
        "Set HttpOnly, Secure, and SameSite (Lax or Strict) on session " +
          "cookies, and serve them only over HTTPS.",
      verify = "The cookie now carries the missing flag(s).",
    ),
    "SecretInStorage" -> Guidance(
      title = "Secret in web storage",
      cwe = "CWE-922",
      owasp = "A02:2021 Cryptographic Failures",
      rootCause =
        "A secret (JWT, API key, or access token) is kept in localStorage or " +
          "sessionStorage, where any script on the page can read it — one XSS " +
          "exfiltrates it.",
      locate =
        "Find the client code that writes the token to web storage after login.",
      fix =
        "Hold session tokens in HttpOnly, Secure cookies instead of web " +
          "storage; if a token must live in JS, keep it in memory only and " +
          "keep its lifetime short.",
      verify = "No secret-shaped value remains in web storage.",
    ),
    "MissingSecurityHeader" -> Guidance(
      title = "Missing security header",
      cwe = "CWE-693",
      owasp = "A05:2021 Security Misconfiguration",
      rootCause =
        "A standard hardening response header is absent, removing a layer of " +
          "defense in depth.",
      locate =
        "Find the response/header middleware, or the web-server / CDN " +
          "configuration that sets response headers.",
      fix =
        "Add the missing header(s): Content-Security-Policy, Strict-Transport-" +
          "Security, X-Content-Type-Options: nosniff, Referrer-Policy, and an " +
          "anti-framing control (CSP frame-ancestors or X-Frame-Options).",
      verify = "The header is now present on responses.",
    ),
  )
