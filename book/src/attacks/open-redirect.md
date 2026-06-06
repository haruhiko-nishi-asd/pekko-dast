# Open redirect

**In one sentence:** an open redirect is a link that *starts* on a site you trust and
*lands* on the attacker's - perfect bait, because the part the victim reads looks
completely legitimate.

**This chapter will cover:** how a "where should we send you after login?" parameter
(`?next=`, `?url=`, `?returnTo=`) becomes an attacker tool when the app doesn't check
the destination stays on-site; why it powers convincing phishing and can leak OAuth
tokens through a tampered `redirect_uri`; the two payload shapes the scanner tries -
an absolute `https://evil/` and a scheme-relative `//evil/` (the second defeats naive
`startsWith("/")` checks) - using a non-resolving sentinel host so the probe never
actually leaves the target; why it rates `Medium` (a stepping stone, not a direct
compromise); and the fix (allow-list redirect targets).

**Try it yourself:** the demo `/redirect` endpoint uses `next` as the `Location`
verbatim.

```bash
python3 scripts/vuln-target.py
curl -i 'http://localhost:8123/redirect?next=https://example.com/'   # → 302 Location: https://example.com/
```
