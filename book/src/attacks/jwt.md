# JWT weaknesses

**In one sentence:** a JWT is a signed ticket that says "I'm Alice" - and if the
signature can be removed or guessed, anyone can print a ticket that says "I'm Alice"
(or "I'm admin").

**This chapter will cover:** the three parts of a JWT (header, payload, signature) and
what the signature is *for*; the two classic breaks the scanner checks - `alg:none`,
where the server is fooled into accepting a token with the signature stripped off, and a
**weak HMAC secret** that can be cracked offline so the attacker can forge valid tokens
at will; why "it's signed" means nothing if the key is `secret` or `your-256-bit-secret`;
and the fix (strong keys, pinned algorithms, short lifetimes).

**Try it yourself:** the demo home page hands out a token signed with the well-known weak
secret `your-256-bit-secret`.

```bash
python3 scripts/vuln-target.py
curl -i http://localhost:8123/ | grep -i set-cookie
#   Set-Cookie: jwt=eyJhbGciOiJIUzI1Ni...   ← paste into jwt.io; it verifies with "your-256-bit-secret"
```
