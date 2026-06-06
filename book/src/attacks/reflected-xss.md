# Reflected XSS

**In one sentence:** the site takes something from your request and paints it straight
into the page, so a crafted link makes the *victim's* browser run the *attacker's*
script.

The analogy: you write a message on a whiteboard that everyone in the building reads -
but instead of words, you write an instruction, and everyone who reads it obeys it.

**This chapter will cover:** what "cross-site scripting" means and why "reflected" refers
to a payload that travels in the request (a link the victim clicks) rather than one
stored on the server; what an attacker's script can do once it runs in your origin (steal
cookies and tokens, act as you, rewrite the page); how the scanner confirms it the honest
way - it injects a payload carrying a **unique marker**, navigates a real browser, and
only reports a finding if that marker *actually executed* (`High`, because it truly
fired); and the fix (context-aware output encoding, plus CSP as a backstop). This is the
contrast case for the next chapter's **DOM XSS**, where nothing fires.

**Try it yourself:** the demo home page reflects `q` into the HTML with no escaping.

```bash
python3 scripts/vuln-target.py
# Open in a browser - the <img> runs its onerror handler:
open 'http://localhost:8123/?q=<img src=x onerror=alert(1)>'
```
