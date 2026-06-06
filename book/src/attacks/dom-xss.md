# DOM-based XSS

**In one sentence:** same outcome as reflected XSS - attacker script running in your
browser - but the bug lives entirely in the page's *own* JavaScript, so the server never
sees it and server-side filters can't catch it.

**This chapter will cover:** the **source → sink** model - a *source* is attacker-
influenceable input (the URL `#fragment`, the query string, `postMessage`); a *sink* is a
dangerous function (`innerHTML`, `eval`, `document.write`, string `setTimeout`,
`location`); DOM XSS is when the page's JS carries data from one to the other without
sanitizing it. We'll see why the `#fragment` never even leaves the browser (so WAFs and
server logs are blind to it), and why this is the chapter where **severity honesty**
matters most: the scanner detects it by **taint observation** - it sends a *harmless*
marker and watches whether it *reaches* a sink - which proves the dangerous *path exists*
but **not** that a real payload would execute. That's why a sink-reach is reported as
**Medium** (reachability), while a payload that actually fires is **High**. Plus the fix
(safe sinks like `textContent`, and sanitizers).

**Try it yourself:**

> ⚠️ **Lab gap.** The bundled demo target is server-rendered; its one JS page writes to
> the *safe* sink `textContent`, so there's no DOM-XSS exercise yet. Planned fix: add a
> tiny `/dom` route whose script reads `location.hash` and assigns it to `innerHTML`,
> giving this chapter a real, observable source-to-sink flow to scan. Until then, this
> chapter is explanation-only.
