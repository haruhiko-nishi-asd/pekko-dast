# IDOR, the hard way

**In one sentence:** the same ownership bug as the previous chapter, but in the setting
where simple tools give up - ids you can't guess (random UUIDs, not `123`→`124`) on API
endpoints no link ever points to - so finding it means logging in, *navigating like a
real user*, and confirming a genuine cross-account read.

**This chapter will cover:** why IDOR is the [#1 risk on the OWASP API Security Top
10](https://owasp.org/www-project-api-security/) and the hardest class to automate - a
vulnerable response is a clean `200 OK` that looks *exactly* like a legitimate one, so
only the *meaning* ("this record isn't the caller's") distinguishes it; the three stages
the scanner uses - **reach** (crawl, plus an AI navigator that follows links, submits
forms, and clicks SPA buttons to discover the hidden `fetch` endpoints), **plan** (propose
tests from ids it *actually observed*, never invented), and **confirm** (deterministic
code re-requests another user's id *as the attacker* and checks a per-user discriminator
or data-fingerprint leaks across the boundary); why the model proposes but never decides;
and the guardrails (a destructive-action deny-list) that keep navigation safe.

**Try it yourself:** the demo's SPA path hides the account API behind JavaScript and a
search form - exactly the "crawler can't see it" shape.

```bash
python3 scripts/vuln-target.py
curl -s -c jar.txt -d 'username=alice&password=secret' http://localhost:8123/login
# The /app page's JS fetches /api/account - a link crawl never sees this endpoint:
curl -s -b jar.txt 'http://localhost:8123/api/account?id=1002'   # another user's record via the hidden API
```

The full browser-driven version (the AI navigator clicking through the SPA) is the
`SpaIdorScannerMain` flow - covered in [Running the lab](../using/running-the-lab.md).
