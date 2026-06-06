# Secrets in storage

**In one sentence:** `localStorage` is a notebook that *any* script on the page can
read, so a token kept there is one cross-site scripting bug away from being stolen.

**This chapter will cover:** the difference between an `HttpOnly` cookie (invisible to
JavaScript) and browser storage (wide open to it); why apps put JWTs, API keys, and
access tokens in storage anyway (convenience) and what that trade costs; how the scanner
classifies a stored value as *likely secret* by its shape - JWT structure, high entropy,
known token prefixes - so it flags the dangerous strings without crying wolf over every
base64 blob; and the safer alternatives.

**Try it yourself:**

> ⚠️ **Lab gap.** The bundled demo target is server-rendered and doesn't currently write
> anything to `localStorage`, so there's no hands-on step here yet. Planned fix: add a
> small `/profile` route that stashes a fake token in `localStorage` on load, giving this
> chapter a real exercise. Until then, this chapter is explanation-only.
