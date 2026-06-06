# Missing security headers

**In one sentence:** security headers are the seatbelts of a web response - missing
ones don't cause a crash by themselves, but they remove the protection that would have
saved you when something *else* goes wrong.

**This chapter will cover:** what the big ones actually do - `Content-Security-Policy`
(limits what scripts can run, blunting XSS), `Strict-Transport-Security` (forces HTTPS),
`X-Content-Type-Options` (stops the browser from guessing a file's type), `Referrer-Policy`
(controls what URLs leak in the `Referer`), and anti-framing protection (stops
clickjacking) - why these are *defense in depth* rather than fixes for a specific bug,
and why the scanner only flags a header that's **fully absent** (the lowest-false-positive
signal) rather than judging the contents of one that's present.

**Try it yourself:** the demo target's home page sends none of them.

```bash
python3 scripts/vuln-target.py
curl -i http://localhost:8123/ | grep -iE 'content-security|strict-transport|x-content-type|referrer-policy'
#   (no output - every one is missing)
```
