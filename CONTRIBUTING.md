# Contributing

Thanks for looking. One principle governs everything here.

## A false positive is worse than a missed finding

This tool tells people which of their endpoints are unprotected. If it is wrong
once, the other nineteen findings stop being read. So:

- **Every finding names the chain that was resolved and the line it came from.**
  No exceptions. "No guard found in `requireAuth → nothing`, at
  `src/routes/projects.ts:27`" is a claim someone can check in one click.
- **Never emit a verdict.** The wording is "no guard was found", not "this is
  vulnerable". A gateway, a proxy, a platform policy or an unusual guard are all
  invisible to a static reader. The finding is about what was found.
- **A new rule needs a test that fires and a test that does not.** The second is
  the important one. See `test_login_route_is_not_an_unauthenticated_mutation`,
  `test_scoped_query_is_not_reported_as_idor`,
  `test_role_gated_route_is_not_reported_as_idor`,
  `test_guarded_server_action_is_not_reported`,
  `test_session_read_and_ignored_does_not_count`.
- **The corrected example must stay at zero.** `examples/project-api/after`
  audits clean and CI fails if it ever does not. A rule that fires on it is a
  rule flagging correct code.
- **Guard attribution must be framework-correct.** An Express `app.use` mount
  does not protect a Next.js route handler. Crediting a guard that does not
  apply is the worst bug this tool can have, because it hides a real hole.

## The shape of the thing

- `scripts/routes.py` finds routes and resolves guard chains. Nothing in here
  judges anything.
- `scripts/audit.py` judges. Every rule is a function taking `(doc, out)`.
- `scripts/render.py` draws the matrix. It must never change a finding.
- Standard library only, Python 3.9+. No dependencies, ever — it is why this
  installs in one command inside someone else's agent.

## Adding a framework

Write a `parse_<name>(rel, lines)` that returns `route(...)` dicts, add it to the
dispatch in `build()`, and add a discovery test. Keep the parser line-oriented:
a half-understood AST is worse than an honest regex, because it fails silently
on the file it does not understand.

## Running it

```bash
python3 -m unittest discover -s tests -v
python3 scripts/audit.py examples/project-api/before
python3 scripts/audit.py examples/project-api/after --strict
python3 scripts/render.py examples/project-api/before --text
```

## Reporting a false positive

Open an issue with the smallest route that triggers it and where the guard
actually lives. That is the most useful issue this project can get, and it will
be treated as a bug rather than a preference.
