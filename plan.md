# gatescope — research, analysis, and build plan

Date: 2026-11-15. Method inherited from `schemascope/plan.md`: short queries,
`in:name`, `--topic=`. Long descriptive queries return empty on GitHub
regardless of the truth, so no conclusion here rests on one.

## 1. Objective

The third repo in the `*scope` family, and the one with the highest ceiling:
access control is the most embarrassing thing to get wrong, so the artifact
travels furthest. It is also the one that most needs discipline, because the
neighbourhood is crowded with tools that overclaim.

## 2. The structural pattern

schemascope exists because `drawdb-io/drawdb` has 40,323 stars for making humans
draw schemas **by hand**. The same shape, verified 2026-11-15:

| Incumbent | Stars | What it makes you do |
|---|---|---|
| `akto-api-security/akto` | 1,548 | run an API security platform against live traffic |
| `y1nglamore/IDOR_detect_tool` | 767 | fuzz a running app |
| `SecurityInnovation/AuthMatrix` | **648** | **build the matrix by hand, in Burp** |
| `hahwul/authz0` | 429 | drive a black-box authorization test from URLs |
| `errorfiathck/IDOR-Forge` | 243 | fuzz IDOR from the outside |
| `secdec/attack-surface-detector-burp` | 113 | static route parsing — in a Burp plugin, dead since 2023 |
| `JoyGhoshs/AuthMatrix-Reloaded` | 6 | the same matrix, still by hand |
| `caido-community/authmatrix` | 10 | the same matrix, in Caido |

**AuthMatrix has 648 stars for a grid you populate yourself**, by configuring
users, capturing requests and pressing play. Every tool in this space is
dynamic: it needs a running application, credentials for each role, and a proxy.
None of them reads source. None is agent-native.

## 3. Verification

### 3.1 The static slice is empty

| Query | Total | Top result | Verdict |
|---|---|---|---|
| `permission-matrix in:name` | 47 | 4★ | empty |
| `broken-access-control in:name` | 198 | 89★ Tampermonkey demo — labs and PoCs only | no tool |
| `missing-auth in:name` | 37 | nothing relevant | empty |
| `endpoint-map in:name` | 53 | 12★ | empty |
| `api-surface in:name` | 67 | 19★ F# API consistency | different job |
| `rbac-audit in:name` | 82 | 1,112★ `audit2rbac` — Kubernetes | different domain |
| `auth topic:claude-skill` | 29 | 28★, none about authorization | empty |
| `unauthenticated endpoint in:name,description scanner` | 8 | 1★ | empty |

`capy-zhiao/PERMSCOPE_` (24★) is an academic artifact: "detecting missing
permission controls in mini-program APIs via static and dynamic analysis". A
paper proving the technique works, and no product.

### 3.2 The real risk, stated plainly

The *neighbourhood* is crowded even though the slice is empty:

| Repo | Stars | What it is |
|---|---|---|
| `utkusen/sast-skills` | 1,375 | agent skills to find vulns in web/mobile apps |
| `raroque/vibe-security-skill` | 1,234 | audits vibe-coded apps for AI-introduced vulns |
| `SunWeb3Sec/llm-sast-scanner` | 292 | SAST skill, 34 vulnerability classes |
| `firetix/vibe-coding-penetration-tester` | 179 | pentest agent for vibe-coded apps |
| `astoj/vibe-security` | 165 | checklist |
| `benavlabs/vibe-check` | 153 | checklist plus audit |
| `Armur-Ai/Trishul` | 97 | SAST, DAST and exploit simulation |
| `italamrii/vibeguard` | 1 | the generic version, shipped, scored 1 |

These are broad and shallow: 34 categories, checklists, lists of findings. **None
produces the matrix.** So the positioning is surgical — not "a security
scanner", which is a fight already lost at 1,375★, but *one picture of who can
reach what, with the chain resolved and cited*. Depth in one vertical plus a
postable artifact is how schemascope coexists with general code-review skills.

Second mitigation, non-negotiable: the tool reports **"no guard found"**, never
"vulnerable". An evidence-shaped claim survives a false positive; a verdict does
not, and one bad verdict costs the other nineteen findings.

### 3.3 Name availability

| | GitHub | npm | PyPI |
|---|---|---|---|
| `gatescope` | **3 repos, max 2★, all unrelated** | free | free |
| `guardscope` | 3 repos, max 1★ — one adjacent (LLM agent action paths) | free | free |
| `authscope` | 28 repos — one is an API authz tester from Oct 2026 | — | — |
| `authmatrix` | **648★ Burp extension** — avoided | — | — |

`gatescope` selected: clean across all three registries.

### 3.4 Domain authority

Not a guess from outside. The existing repos — `Idorra` (authorized IDOR and
broken-access-control testing), `role-ui-diff` (diffs two roles into a BFLA test
plan), `hidden-ui-revealer`, `request-tamper` — attack this problem
dynamically. gatescope is that expertise turned static and agent-native.

## 4. Product

### 4.1 Inputs

Routes from Express-style routers, the Next.js App Router, Next.js server
actions, FastAPI, Flask and Laravel. Guard chains resolved across files,
including router mounts: a route written `/:id` and mounted at
`/api/projects` is reported as `/api/projects/:id`, and a guard at the mount is
credited to everything inside it.

### 4.2 Outputs

- the route × caller matrix: Markdown for a README, plain text for a terminal,
  HTML for sharing
- ranked findings, each naming the resolved chain and the line it came from
- the fix for each, as a diff where a diff says it best

### 4.3 The design decisions that matter

**Guard attribution must be framework-correct.** The first draft credited an
Express `app.use("/api", requireAuth)` to a Next.js route handler under
`/api/billing`. That is the worst possible bug for this tool: it hides a real
hole behind a guard that does not apply. Prefix guards are now scoped to
`kind == "express"`.

**Identity read is not identity enforced.** A handler that calls `auth()` and
ignores the result is not protected. Promotion from `public` to `authed` on an
in-handler session read requires an enforcement signal — a 401, a 403, a throw,
a redirect — in the same body.

**Ownership must be session-derived.** `where: { id: userId }` where `userId` is
a function parameter is not an ownership check, it is the IDOR. Ownership
requires an owner field constrained by a session value, and the caller-supplied
case is its own critical rule.

**A credential endpoint is public on purpose.** `POST /login` is neither an
unauthenticated mutation nor an alarm cell in the matrix.

## 5. Launch

1. README hero is the matrix from the broken example, rendered by GitHub as a
   plain Markdown table — no image, no build step, same trick as the schemascope
   ER diagram.
2. The install line is one paste to an agent, via `llms.txt`.
3. Cross-link the family: schemascope for the schema, statescope for the
   lifecycle, gatescope for the access. Each sells the other two.
