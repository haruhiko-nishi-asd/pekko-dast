# SQL injection

**In one sentence:** when your input is glued straight into a database query, you can
stop being the person *answering* the form and start *rewriting the question* the
database is asked.

The analogy: you fill in a form that says "find the customer named ___", but the blank
also lets you edit the instruction itself - so you write "find the customer named nobody,
**and also list every password**."

**This chapter will cover:** how string-concatenated queries let an attacker read other
rows, dump tables, or bypass a login; the two tells the scanner uses without ever seeing
the data - a stray quote that breaks the query into a **database error**, and an injected
`SLEEP()` that makes the response measurably **slower** - and why the scanner compares
against a baseline and re-tests a slow hit (one slow response is noise; two is a payload),
plus the real fix: parameterized queries.

**Try it yourself:** the demo `/item` endpoint errors on an unbalanced quote and sleeps
on a `SLEEP(n)` payload.

```bash
python3 scripts/vuln-target.py
curl -s 'http://localhost:8123/item?id=1%27' | grep -i 'database error'   # error-based
time curl -s 'http://localhost:8123/item?id=SLEEP(3)' >/dev/null          # time-based: ~3s
```
