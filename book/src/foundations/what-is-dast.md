# What is DAST?

**In one sentence:** DAST (Dynamic Application Security Testing) means looking for
security bugs by *poking the running app from the outside* - the way an attacker
would - instead of reading its source code.

The analogy: a doctor can study your DNA in a lab (that's *static* analysis - reading
the code), or they can put you on a treadmill and watch your heart (that's *dynamic*
analysis - observing the system while it actually runs). Both find problems; they find
*different* problems. DAST is the treadmill.

**This chapter will cover:** the difference between static and dynamic testing and why
you need both; what "black-box" testing means (the scanner sees only what any visitor
sees); why some bugs are *only* visible at runtime (a misconfigured header, a server
that fetches any URL you hand it); and the honest limits - DAST can prove a bug is
there, but a clean result never proves the app is safe, only that this set of probes
didn't find anything.
