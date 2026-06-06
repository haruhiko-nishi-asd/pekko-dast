# The one rule: authorization

**In one sentence:** only ever test systems you own or have explicit, written
permission to test - everything else in this book is downstream of that rule.

Sending crafted input to someone else's server without permission isn't "research,"
it's an intrusion, and in most places it's a crime. The reason the lab in this book is
safe is simple: the target runs on *your* machine, and it's broken on purpose. The
moment you point a scanner at something you don't own, you've crossed a line no tool
can uncross for you.

**This chapter will cover:** the difference between **observe-only** (just reading what
any normal visit already exposes - cookies, headers, page content) and **active
probing** (sending payloads designed to trigger a bug); how pekko-dast enforces this
with an allow-list (`DAST_AUTHORIZED_HOSTS`) so it *refuses* to probe by default and
stays observe-only until you explicitly name a host; and a short, practical note on
what "permission" really means - bug-bounty scope, a signed engagement, or your own
laptop.
