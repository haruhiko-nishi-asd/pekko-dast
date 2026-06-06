# How a finding is made

**In one sentence:** a result only becomes a "finding" when the tool *actually
reproduced the bug*, not when something merely looked suspicious.

This is the idea that separates a trustworthy scanner from a noisy one. Many tools
guess: "this parameter is named `url`, it's *probably* SSRF." pekko-dast instead
*confirms*: it makes the server call back to a listener it controls, and only then does
SSRF exist. An AI model may help *decide what to try*, but it never gets to declare a
finding - deterministic code does that, by observing a concrete effect.

**This chapter will cover:** the "propose, then confirm" split (a model can suggest a
move from a fixed menu, but confirmation is plain code watching for a real signal -
a marker that executed, a callback that arrived, a record that leaked); why this design
drives false positives toward zero; what every finding carries (a kind, a severity,
one line of evidence, and a **replay handle** that re-locates the bug with no model
involved); and why "zero findings" is a real, honest result rather than a failure.
