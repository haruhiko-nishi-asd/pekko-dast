# Running the lab

**In one sentence:** start the deliberately-broken target, point the scanner at
`localhost`, and watch it confirm - end to end - the bugs you poked by hand in the
earlier chapters.

**This chapter will cover:** the prerequisites (JDK 21+, sbt; an API key only if you want
the AI-directed steps); the one-command path - `./scripts/demo.sh` starts
`scripts/vuln-target.py`, runs every scanner against the authorized `localhost` scope,
and stops it; running a single scanner directly (`ScannerMain` for the per-URL battery,
`SpaIdorScannerMain` for the browser-driven IDOR); and the safety wiring that makes this
fine to run - `localhost` is the only authorized host, so nothing touches anything you
don't own.

```bash
# Everything, hands-off:
./scripts/demo.sh

# Or one scanner against one URL (localhost is the authorized active scope):
DAST_AUTHORIZED_HOSTS=localhost \
  sbt 'runMain dast.scan.ScannerMain http://localhost:8123/?q=hello'
```
