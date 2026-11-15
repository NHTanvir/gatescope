---
name: gatescope
description: Resolve every route in a codebase to the guards that actually protect it and report the access control that is missing. Use when the user asks who can access what, about authorization, auth middleware, protected routes, admin access, IDOR, BOLA, broken access control, multi-tenant leakage, or a route or permission audit - or right after you have added an endpoint, a server action, or a middleware chain. Finds mutating routes with no guard, server actions with no identity check, authenticated routes that never tie a record to its owner, admin paths behind only a login check, guards that run after the write, and mass assignment, then prints the route by role matrix.
---

# gatescope

Find every route, resolve what guards it, print who can reach what, and report
what nothing is guarding.

## When to use this

- the user asks who can reach an endpoint, or about auth, authorization, roles,
  permissions, protected routes, IDOR/BOLA, or multi-tenant isolation
- the user is about to ship, and wants to know what is exposed
- **immediately after you add a route, a server action, or a middleware chain** —
  check your own work before saying it is done
- when you change a guard, to see which routes the change actually moved

## How to run it

The scripts live in `scripts/` next to this file. Python 3.9+, nothing else.
Resolve `<skill>` to this skill's directory.

```bash
# 1. the audit -- always run this first
python3 <skill>/scripts/audit.py <path>

# 2. the matrix
python3 <skill>/scripts/render.py <path> --matrix     # Markdown, for a README or PR
python3 <skill>/scripts/render.py <path> --text       # for the terminal

# 3. one shareable HTML file with both
python3 <skill>/scripts/render.py <path> --out=access-review.html
```

`<path>` is the repo root. Point it at the whole project: the chain for a route
often lives in a different file from the route, and narrowing the path is how
you lose the mount that resolves it.

Other flags: `--markdown`, `--json`, `--strict` (exit 1 on any critical),
`--no-fix`.

## How to report the result

1. **Lead with the levels.** "13 routes: 7 public, 4 authed, 2 owner-scoped, 0
   role-gated."
2. **Show the matrix.** It is the output that makes the problem legible, and the
   one the user will send to someone else. Do not summarise it in prose instead.
3. **Show the criticals in full**, each with its file and line and the chain
   that was resolved. The chain is the evidence; never report "unprotected"
   without it.
4. **Summarise the rest by rule.** "Four routes take an id and never scope the
   query" beats four near-identical paragraphs.
5. **Say what you could not resolve.** If the project has a gateway, a custom
   framework, or a dynamically assembled router, say that the `public` rows may
   be wrong and that the cited lines need a human.

## Rules that matter

**Phrase every finding as what was found, never as a verdict.** Say "no guard
was found in the resolved chain", not "this endpoint is vulnerable". You cannot
see a reverse proxy, an API gateway, a platform policy or a WAF. Being wrong
about a missing guard is recoverable; telling someone their code is vulnerable
when it is not costs you the other nineteen findings.

**Fix order, when the user asks you to fix:**

1. Put identity on the router, not on each handler —
   `app.use("/api", requireAuth)` — so the next handler cannot be added without
   it. Per-handler guards are how the gaps appear.
2. Add the ownership predicate inside the query, not as an `if` after the fetch:
   `where: { id, userId: session.user.id }`. Return **404**, not 403 — a 403
   confirms the row exists.
3. Put role checks on admin routers as a second, separate middleware. Identity
   and authority are different questions.
4. Replace body spreads with an explicit field list or a schema parse before
   touching anything else, because mass assignment can re-introduce privilege
   escalation through a field you already fixed elsewhere.
5. Never read a role, plan or permission from the request. If the client needs
   to change one, that is its own endpoint behind its own role gate.

**Do not apply a fix without being asked.** Adding `requireAuth` to a route that
a mobile client calls unauthenticated is an outage. Show the finding, name the
fix, let the user decide.

A finding is a judgement, not a fact:

- `public` on a route behind a gateway is this tool's blind spot, not a bug in
  the code. Ask whether one exists before escalating.
- `id_param_no_owner_check` on a deliberately public resource — a published
  post, a share link — is correct behaviour. Say so.
- `debug_route_exposed` in a dev-only file guarded by an environment check is
  noise.

## Reference

- [`references/audit-rules.md`](references/audit-rules.md) — all 14 rules, each with rationale, fix and failure case
- [`references/access-control-design.md`](references/access-control-design.md) — how to structure guards so the gaps cannot open
