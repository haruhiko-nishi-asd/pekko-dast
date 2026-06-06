# Pointing it at your own target

**In one sentence:** the same scanner works against real applications - but only ones you
own or are explicitly authorized to test, and only once you've understood what each probe
actually sends.

**This chapter will cover:** the authorization gate in practice (set
`DAST_AUTHORIZED_HOSTS` to the real host, or leave it empty to stay safely observe-only);
choosing a seed URL (and, for the IDOR flows, the post-login page where your objects
live); supplying an identity spec so the scanner can act *as someone* (a copied `cookie`
header or a `login` form); the data-handling note - the AI-directed paths send page HTML
and observed URLs to your chosen model provider, so treat that as a privacy decision; and
a final restatement of the golden rule from [authorization](../foundations/authorization.md):
permission first, every time.

> ⚠️ Nothing in this chapter should be run against a system you don't own or have written
> permission to test. When in doubt, don't.
