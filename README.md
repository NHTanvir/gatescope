# gatescope

**Point your coding agent at a codebase. Get the matrix of who can reach what — every guard chain resolved, every endpoint nothing is guarding named out loud.**

Your agent generated forty endpoints. Each handler looks correct on its own, which is the problem: `DELETE /api/projects/:id` has no middleware, `GET /api/projects/:id` is authenticated but never ties the id to the caller, the admin router checks that you are logged in and never checks who you are, and the server action is a POST endpoint that trusts whoever calls it.

Broken access control is OWASP #1 and the one category an LLM reading files is worst at, because catching it means enumerating every route and resolving every middleware chain. That is mechanical work. Here it is, done mechanically.

| Route | anon | user | guard chain |
|---|---|---|---|
| `POST /#deleteAccount` | 🔴 | ✓ | `—` |
| `POST /#updatePlan` | 🔴 | ✓ | `—` |
| `POST /api/billing` | 🔴 | ✓ | `—` |
| `DELETE /api/projects/:id` | 🔴 | ✓ | `—` |
| `GET /api/billing` | ✓ | ✓ | `—` |
| `GET /debug/dump` | ✓ | ✓ | `—` |
| `POST /login` | ✓ | ✓ | `—` |
| `GET /api/admin/users` | · | ✓ | `requireAuth` |
| `POST /api/admin/users/:id/promote` | · | ✓ | `requireAuth` |
| `GET /api/projects` | · | own | `requireAuth` |
| `POST /api/projects` | · | own | `requireAuth` |
| `GET /api/projects/:id` | · | ✓ | `requireAuth` |
| `PATCH /api/projects/:id` | · | ✓ | `getServerSession` |

<sub>🔴 reachable by anyone and it writes · ✓ reachable · `own` scoped to the caller's own rows · `·` blocked. Two columns because this codebase has no role guard anywhere — that is the finding, not an omission in the table.</sub>

```
  ACCESS AUDIT   examples/project-api/before
  13 routes · express, next · 5 files

  7 public · 4 authed · 2 owner · 0 role

  critical    8  █████████████████████████
  high        9  ████████████████████████████
  medium      3  █████████

  20 findings across 13 routes


  CRITICAL  (8)
  ──────────────────────────────────────────────────────────
  DELETE /api/projects/:id
    DELETE /api/projects/:id changes data and no guard was found on it.
    unauthenticated_mutation — The guard chain resolved to nothing: no middleware
    on the route, none on the router it is mounted in, and no identity check
    inside the handler. Anyone who can reach the host can call it.
      src/routes/projects.ts:27  DELETE /api/projects/:id

  GET /api/projects/:id
    GET /api/projects/:id is authenticated but never ties id to the caller.
    id_param_no_owner_check — Being logged in is not being the owner. The handler
    looks the row up by the id in the URL, so any authenticated user reaches any
    row by changing one number.
      src/routes/projects.ts:13  GET /api/projects/:id
```

The same API with identity on the router and ownership in the query drops to
**0 findings** — the full before/after is in
[`examples/project-api/`](examples/project-api).

![license](https://img.shields.io/badge/license-MIT-blue) ![python](https://img.shields.io/badge/python-3.9%2B-blue) ![deps](https://img.shields.io/badge/dependencies-none-success) ![tests](https://img.shields.io/badge/tests-60%20passing-success)

---

## Install

Paste this to your agent:

```
Install gatescope for me by reading
https://raw.githubusercontent.com/NHTanvir/gatescope/master/llms.txt
```

Or place it yourself:

```bash
git clone https://github.com/NHTanvir/gatescope ~/.claude/skills/gatescope
```

Claude Code can also add it as a plugin:

```
/plugin marketplace add NHTanvir/gatescope
```

Works in Claude Code, Cursor, Codex, OpenClaw and anything else that reads a
`SKILL.md`. Plain Python 3.9+ with **no dependencies**, so it also runs on its
own without any agent at all.

---

## Use it without an agent

```bash
# the audit
python3 scripts/audit.py .

# the matrix, ready to paste into a README or a PR
python3 scripts/render.py . --matrix

# the matrix in the terminal
python3 scripts/render.py . --text

# one self-contained HTML file: matrix, findings, fixes, light and dark
python3 scripts/render.py . --out=access-review.html

# other shapes
python3 scripts/audit.py . --markdown    # for a PR comment
python3 scripts/audit.py . --json        # for tooling
python3 scripts/audit.py . --strict      # exit 1 on any critical, for CI
python3 scripts/routes.py .              # just the resolved routes
```

Nothing phones home. No source ever leaves your machine. It reads files and
never sends a request to the application, so it is safe to run against
production code without being a scan of production.

---

## What it reads

| Framework | Routes from | Guards from |
|---|---|---|
| Express / Fastify / Koa-style | `app.get`, `router.post`, … | inline middleware, `app.use`, the mount in another file |
| Next.js App Router | `app/**/route.ts` exports | `auth()` / `getServerSession()` in the handler |
| Next.js server actions | exported functions in a `"use server"` file | the identity check inside the action |
| FastAPI | `@app.get`, `@router.post` | decorators and `Depends(...)` |
| Flask | `@app.route(..., methods=[…])` | decorators such as `@login_required` |
| Laravel | `Route::get`, `Route::resource` | `->middleware('auth')`, `Route::middleware([...])->group` |

Router mounts are resolved across files: a route written as `/:id` in
`routes/projects.ts` and mounted with `app.use("/api/projects", projects)` in
`server.ts` is reported as `/api/projects/:id`, and a guard applied at the mount
is credited to every route inside it. An Express mount is **not** credited to a
Next.js route handler, because it does not protect one.

Each route resolves to one of four levels:

- **public** — no guard was found anywhere in the chain
- **authed** — identity is established
- **owner** — the query is constrained to the caller's own rows
- **role** — authority is asserted, and the role is named

---

## What it finds

14 rules. Every finding names the chain that was resolved and the line it came
from.

### Critical

| Rule | Catches |
|---|---|
| `unauthenticated_mutation` | a route that writes and resolves to no guard at all |
| `server_action_unguarded` | a Next.js server action with no identity check — a POST endpoint either way |
| `caller_supplied_identity` | a handler that takes `userId` from the caller and never reads the session |
| `id_param_no_owner_check` | authenticated, and any user reaches any row by changing one number |

### High

| Rule | Catches |
|---|---|
| `admin_path_without_role_guard` | an admin surface that only checks that you are logged in |
| `inconsistent_sibling_guards` | the one handler under a prefix that somebody forgot |
| `guard_after_side_effect` | the identity check runs after the write it was meant to prevent |
| `mass_assignment` | `...req.body` into a create, so `role` is whatever the client sends |
| `public_read_of_sensitive_data` | an unguarded read on a path that names people, money or credentials |

### Medium

| Rule | Catches |
|---|---|
| `role_from_client` | a privilege read out of the request body |
| `auth_route_no_rate_limit` | a credential endpoint with nothing bounding attempts |
| `debug_route_exposed` | `/debug`, `/internal`, `/seed` — written during an incident, outlived it |
| `no_identity_guard_anywhere` | not one route in the codebase checks anything |

### Low

`guard_vocabulary_drift` — several names for the same guard, which will not agree for long.

Each is documented with its rationale and its fix in
[`references/audit-rules.md`](references/audit-rules.md).

---

## It says "no guard found", not "vulnerable"

That distinction is the whole design. A static tool cannot see a gateway, a
proxy, a platform policy, or a guard written in a way its heuristics do not
recognise. So every finding reports **the chain it resolved** and the line it
read, and the claim is about what was found rather than about what exists.

An evidence-shaped claim survives being wrong. A verdict does not — one bad
"vulnerable" and nobody believes the other nineteen findings.

Known limits, stated rather than hidden:

- Express chains are resolved through imports and mounts in the files it can
  see. A router assembled dynamically, or mounted from an array, is not followed.
- A guard enforced in a framework layer this tool does not parse shows up as
  `public`. Check the cited line before acting.
- `owner` requires the query to be constrained by a session value. An ownership
  check done in application code after the fetch is not recognised, and will
  read as `authed`.
- It never sends a request anywhere, so it cannot confirm that a guard works —
  only that one is there.

---

## Related

[statescope](https://github.com/NHTanvir/statescope) does the same job for the
state machine your code implements, and
[schemascope](https://github.com/NHTanvir/schemascope) for the schema
underneath both.

## Contributing

A false positive is worse than a missed finding. See
[CONTRIBUTING.md](CONTRIBUTING.md).

MIT.
