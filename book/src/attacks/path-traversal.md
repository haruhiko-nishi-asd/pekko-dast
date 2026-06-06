# Path traversal & LFI

**In one sentence:** you ask the app for a file by name, then sneak `../../` into that
name to climb out of the folder it meant to keep you in and read files it never intended
to share - like `/etc/passwd`.

**This chapter will cover:** how a feature as innocent as "download this report by
filename" becomes a way to read arbitrary system files when the name isn't sanitized;
what the `../` ("dot-dot-slash") sequence does and the common encodings attackers use to
slip it past naive filters; how the scanner confirms it by asking for a *known* OS file
and checking a signature unique to it (`root:x:0:0` for `/etc/passwd`, `[fonts]` for
`win.ini`) that was **absent from the baseline**; the relationship to Local File Inclusion
(LFI); and the fix - resolve and contain paths, never trust the name.

**Try it yourself:** the demo `/download` endpoint serves system-file contents for a
traversal-shaped name.

```bash
python3 scripts/vuln-target.py
curl -s 'http://localhost:8123/download?file=../../etc/passwd'   # → root:x:0:0:...
```
