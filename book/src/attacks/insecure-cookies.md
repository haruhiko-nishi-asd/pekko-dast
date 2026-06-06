# Insecure cookies

**In one sentence:** a cookie is the wristband your browser flashes on every request,
and three little flags decide whether someone can copy it, sniff it off the wire, or
get it used at the wrong door.

**This chapter will cover:** what each flag protects against - `HttpOnly` (so page
scripts can't read the cookie, which is what stops an XSS from stealing your session),
`Secure` (so it's never sent over plain HTTP where it could be intercepted), and
`SameSite` (so it doesn't ride along on cross-site requests, a [CSRF](./security-headers.md)
enabler) - why a *session* cookie missing any of them is a genuine risk, and how the
scanner reads the flags straight off the browser over CDP without guessing.

**Try it yourself:** the demo target's home page sets a cookie with **none** of the
three flags.

```bash
python3 scripts/vuln-target.py
# in another terminal:
curl -i http://localhost:8123/ | grep -i set-cookie
#   Set-Cookie: jwt=...; Path=/      ← no HttpOnly, no Secure, no SameSite
```
