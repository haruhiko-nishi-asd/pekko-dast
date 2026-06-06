# Server-side request forgery

**In one sentence:** SSRF is tricking the *server* into fetching a URL that *you* choose,
so its requests reach places you can't - internal admin panels, databases, and cloud
metadata that hands out credentials.

The analogy: you can't walk into the staff-only back office, but you can phone the front
desk and ask them to go fetch a document from it. The server is the front desk; it has
access you don't, and it'll go where you point it.

**This chapter will cover:** why the danger is *where the server sits* (behind the
firewall, able to reach `localhost` services and `169.254.169.254` cloud metadata); why
most SSRF is **blind** - the server makes the request but shows you nothing - so reading
the response body is useless; and the one honest signal: **out-of-band confirmation**,
where you hand the server a URL pointing at a listener *you* control and watch it get
hit. We'll cover how the scanner mints a unique token per parameter, binds a listener,
and polls for the callback, plus the fix (allow-list outbound destinations).

**Try it yourself:** the demo `/fetch` endpoint fetches whatever `url` you give it.

```bash
python3 scripts/vuln-target.py
# Start a one-line listener, then make the SERVER call it:
python3 -m http.server 9000 &
curl -s 'http://localhost:8123/fetch?url=http://localhost:9000/ping'   # the listener logs a hit
```
