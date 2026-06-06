# Introduction

> **Status: outline.** This page and every chapter below is currently a one-paragraph
> stub. The structure and chapter list are what we're agreeing on first; the full
> chapters get written next.

Most explanations of web vulnerabilities assume you already know the jargon. This
book doesn't. It starts each attack from zero, explains it the way you'd explain it
to a smart friend who isn't a security person, and then lets you **watch it happen
on a real (deliberately broken) app you run on your own machine**.

It accompanies [pekko-dast](https://github.com/hanishi/pekko-dast), a scanner that
finds these bugs automatically - but you don't need to care about the scanner to get
value here. Read it as a guided tour of how web apps break, with a hands-on lab at
the end of every chapter.

## Who this is for

New developers, students, QA and platform engineers, and anyone curious about how
"a website got hacked" actually works under the hood. If you can run one command in a
terminal, you can do every exercise.

## The chapter template

Every attack chapter follows the same seven beats, so once you've read one you know
how to read them all:

1. **In one sentence** - the plainest possible statement of the bug.
2. **An analogy** - the same idea in the physical world.
3. **What actually happens** - the mechanism, with one tiny vulnerable example.
4. **Why it's dangerous** - what an attacker actually gains.
5. **Try it yourself** - step-by-step against the bundled demo target.
6. **How the scanner finds it** - what pekko-dast does, in plain terms.
7. **How to fix it** - and how to know a finding is real.

## The lab

One small Python file, `scripts/vuln-target.py`, is a web app that is broken *on
purpose* - a different vulnerability behind each URL. You run it on `localhost`, poke
it by hand, then point the scanner at it. Nothing leaves your machine.

> ⚠️ **The golden rule, stated once and meant always:** only ever test systems you own
> or have explicit written permission to test. The lab is safe because it's yours and
> it's local. See [The one rule: authorization](./foundations/authorization.md).
