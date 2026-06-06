# Severity, honestly

**In one sentence:** not every finding is an emergency, and a good scanner is careful
to say how *sure* it is - proving a door is unlocked is not the same as proving someone
walked through it.

Severity inflation is how security tools lose trust. If everything is "Critical,"
nothing is. This book (and the scanner) draw a hard line between *confirmed exploitation*
and *reachability* - evidence that a bug is probably there but not yet weaponized.

**This chapter will cover:** what `High` / `Medium` / `Low` / `Info` actually mean here;
the running example we'll return to in the [DOM XSS](../attacks/dom-xss.md) chapter -
a marker that *reaches* a dangerous function proves a path exists, but not that a real
payload would execute, so it's reported as **Medium**, while a payload that *actually
fires* in the browser is **High**; and why keeping that distinction in the data (not
just the prose) is what lets a reader sort real exploits from leads worth chasing.
