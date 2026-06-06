# Reading the results

**In one sentence:** a scan's output is a short, structured list of findings - each one
says *what* it found, *how sure* it is, *the evidence*, and *exactly how to reproduce it*
without any AI in the loop.

**This chapter will cover:** the JSON report each scanner prints (`target`,
`findingCount`, and a `findings` array) and the five fields every finding carries -
`kind`, `severity`, one line of `evidence`, a `reproducible` flag, and a `replay` handle
that re-locates the bug deterministically; how to read a `replay` string (e.g.
`header:content-security-policy@<url>`); why `"findingCount": 0` is a real, honest result
(for the IDOR scanners it means the app *enforced* ownership); and the optional
self-contained HTML report (`DAST_REPORT_FILE`) you can open in a browser or hand to
someone else.
