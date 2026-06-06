# Server-side template injection

**In one sentence:** template engines turn `{{name}}` into your data - unless your name
*is* `{{7*7}}` and the server helpfully does the math, which means it's running *your*
expressions, not just displaying them.

**This chapter will cover:** what a template engine is and the difference between input
that's *shown* (reflection - harmless) and input that's *evaluated* (injection -
dangerous, often a path to running code on the server); the arithmetic tell the scanner
relies on - send `{{N*M}}` and check whether the *product* comes back instead of the
literal text, which proves server-side evaluation rather than mere reflection - and why
that distinction is the whole game; plus how this escalates to full remote code execution
in real engines, and the fix (never evaluate user input as a template).

**Try it yourself:** the demo `/greet` endpoint evaluates `N*M`.

```bash
python3 scripts/vuln-target.py
curl -s 'http://localhost:8123/greet?name=7*7'   # → "Hello, 49"  (evaluated, not echoed)
```
