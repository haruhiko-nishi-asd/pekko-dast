# CORS misconfiguration

**In one sentence:** CORS is the browser's rulebook for *which other websites may read
your responses* - get it wrong and any site on the internet can read a logged-in user's
private data.

**This chapter will cover:** what the same-origin policy protects and how CORS
deliberately pokes holes in it for APIs that need cross-site access; the dangerous
combination the scanner looks for - a server that **reflects whatever `Origin` you send
back** in `Access-Control-Allow-Origin` *and* sets `Access-Control-Allow-Credentials:
true`, which together let `evil.com` make authenticated reads as the victim; why
reflecting the Origin is so much worse than a static wildcard; and the fix (an explicit
allow-list of trusted origins, never a reflection).

**Try it yourself:** the demo `/api/data` endpoint reflects any Origin and allows
credentials.

```bash
python3 scripts/vuln-target.py
curl -i -H 'Origin: https://evil.example' http://localhost:8123/api/data | grep -i access-control
#   Access-Control-Allow-Origin: https://evil.example
#   Access-Control-Allow-Credentials: true
```
