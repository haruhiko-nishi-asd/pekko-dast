# IDOR, the spec-driven way

**In one sentence:** change an id in a request - `/account?id=123` → `124` - and get
*someone else's* data, because the app checked that you're *logged in* but forgot to
check that the record is *yours*.

The analogy: a hotel that checks you have *a* room key at the elevator, but every key
opens *every* room.

**This chapter will cover:** what "broken access control" means and why IDOR (Insecure
Direct Object Reference) is its most common form; the related shapes - a normal user
reaching an `/admin` URL, an unauthenticated request reaching a protected page; why a
scanner *can't* know on its own what *should* be restricted, so this check is **assisted**
- you give it a small spec of identities and "this request as this user must NOT return
that data"; how it confirms a finding only on a `2xx` whose body contains the forbidden
marker, with redirects disabled so a bounce to login reads as *denied*; and the fix
(authorize every object access against the caller).

**Try it yourself:** the demo `/account` endpoint requires a session but never checks
ownership, and `/admin` has no auth at all.

```bash
python3 scripts/vuln-target.py
# Log in as anyone (password is "secret"), then read someone else's account:
curl -s -c jar.txt -d 'username=alice&password=secret' http://localhost:8123/login
curl -s -b jar.txt 'http://localhost:8123/account?id=1002'   # reads user 1002's record
curl -s 'http://localhost:8123/admin'                        # admin panel, no login at all
```
