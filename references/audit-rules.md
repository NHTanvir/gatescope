# The 14 rules

Each rule states what it looks for, why it earns a finding, the fix, and — where
one exists — the case where the finding is wrong.

Every rule reports **what was resolved**, never a verdict. The wording matters:
"no guard was found in the chain" is checkable, "this endpoint is vulnerable" is
a claim this tool is not in a position to make.

---

## Critical

### `unauthenticated_mutation`

**Fires when** a route whose method writes (`POST`, `PUT`, `PATCH`, `DELETE`)
resolves to level `public`, and the path is not a credential endpoint.

**Why.** The chain resolved to nothing: no middleware on the route, none on the
router it is mounted in, no identity check in the handler. On a read this is a
disclosure; on a write it is a write. Anyone who can reach the host can call it.

**Fix.** Put identity on the router rather than the handler, so the next handler
cannot be added without it:

```js
app.use("/api", requireAuth);
```

**When it is wrong.** A gateway, proxy or platform policy enforces auth before
the application sees the request. This tool cannot see any of those. The finding
cites the route, so one look settles it.

### `server_action_unguarded`

**Fires when** an exported function in a `"use server"` file has no identity
check in its body.

**Why.** A server action is an HTTP POST endpoint with a generated URL. The page
that imports it does not protect it, and neither does anything in the component
tree — the client calls it directly. Whether the user can see the button is
unrelated to whether they can invoke the action. This is the most commonly
missed endpoint class in modern Next.js code, because it does not look like an
endpoint.

**Fix.**

```ts
export async function deleteAccount() {
  const session = await auth();
  if (!session?.user) throw new Error("unauthorised");
  …
}
```

### `caller_supplied_identity`

**Fires when** a handler takes a parameter named like `userId`, `accountId`,
`ownerId`, `tenantId` and never reads the session.

**Why.** The handler acts on whichever account the caller names. There is no
authorisation step to get wrong, because there is no authorisation step.
Identity has to come from the session; an id in the arguments is a request, not
a claim.

**Fix.** Take the subject from the session and drop the parameter entirely. If
one user genuinely acts on another — an admin — that is a role-gated endpoint
where the id is deliberate and checked.

### `id_param_no_owner_check`

**Fires when** a route has a path parameter, resolves to `authed` (not `role`),
is mutating or on a sensitive path, and no query in the handler is constrained
by a session value.

**Why.** Being logged in is not being the owner. The handler looks the row up by
the id in the URL, so any authenticated user reaches any row by changing one
number. This is the most common serious bug in generated CRUD precisely because
each handler is correct in isolation — the missing part is a relationship
between two things the handler never compares.

**Fix.**

```diff
- const row = await db.project.findUnique({ where: { id: req.params.id } });
+ const row = await db.project.findFirst({
+   where: { id: req.params.id, userId: req.user.id },
+ });
+ if (!row) return res.status(404).end();
```

404 rather than 403: a 403 confirms the row exists, which is the disclosure the
check was meant to prevent.

**When it is wrong.** A deliberately public resource — a published post, a share
link, a public profile. Role-gated routes are already excluded, because a role
gate is a deliberate answer to "who may touch any row".

---

## High

### `admin_path_without_role_guard`

**Fires when** the path contains `admin`, `staff`, `internal`, `manage` or
`backoffice` and the chain resolves to anything other than `role`.

**Why.** Every logged-in user reaches it. The chain establishes who you are and
then never asks what you may do. Admin surfaces are usually hidden in the UI
instead, which protects the menu rather than the route.

**Fix.** A second middleware, separate from identity, on the admin router:
`router.use(requireRole("admin"))`.

### `inconsistent_sibling_guards`

**Fires when** routes sharing a path prefix disagree, and at least one is
`public` while others are guarded.

**Why.** This is how the hole appears: the guard is on the handlers somebody
remembered. It survives review because the handlers above it are correct, and
the exception is the one nobody reads twice.

**Fix.** Make the chain the router's property, not each handler's.

### `guard_after_side_effect`

**Fires when** the first mutating call in a handler appears before the first
identity check.

**Why.** The check runs after the damage. Returning 401 afterwards tells the
caller they were not allowed to do the thing they just did; every unauthorised
request still writes, and only the response changes.

**Fix.** Move the check above the first write and return before it.

### `mass_assignment`

**Fires when** the request body is spread into a create or update —
`...req.body`, `**request.json()`, `$request->all()`.

**Why.** Whatever the client sends becomes the record. Fields the form never
showed — `role`, `plan`, `ownerId`, `isVerified`, `balance` — are writable by
anyone who reads the schema, and the schema is usually in the same repository as
the client.

**Fix.** An explicit field list, or a schema parse that strips unknown keys.

### `public_read_of_sensitive_data`

**Fires when** a non-mutating public route is on a path naming people, money or
credentials, or its handler reads such a table.

**Why.** Enumeration does not need a vulnerability here, only a loop. The
response is also usually the whole row, including columns the UI never renders.

**Fix.** Guard it, scope it to the caller, and select only the fields the caller
is allowed to see.

---

## Medium

### `role_from_client`

**Fires when** a role, permission, scope or plan is read from the request body,
query, params or headers.

**Why.** A privilege taken from the request is a privilege the request can
choose. Even where the value is only persisted rather than enforced, it becomes
the value some later check reads — which turns a storage bug into an escalation.

**Fix.** Role changes are their own endpoint behind their own role gate.

### `auth_route_no_rate_limit`

**Fires when** a mutating route on a credential path (`login`, `signup`,
`password`, `reset`, `otp`, `verify`, `token`, `2fa`) has no rate limiter found
in its chain or handler.

**Why.** Credential endpoints are the ones worth brute forcing and they are
public by necessity, so the limit is the only control. Without it, password
spraying and OTP guessing are bounded by bandwidth.

**Fix.** A limiter in front of the route, keyed by IP and by account.

### `debug_route_exposed`

**Fires when** the path matches `debug`, `test`, `internal`, `dev`, `dump`,
`seed`, `migrate`, `backup`, `graphiql` or `playground`. High if it is also
public.

**Why.** These are written during an incident and outlive it. They tend to dump
whole tables without pagination or field selection, because that was the point
at the time.

**Fix.** Delete it. If it must exist, put it behind an environment check *and* a
role gate.

### `no_identity_guard_anywhere`

**Fires when** no route in the codebase has any identity check.

**Why.** Either authentication lives somewhere this tool cannot see — a gateway,
a proxy, a platform layer — or the application has none. Both are worth knowing
and only one of them is fine.

**Fix.** If a gateway enforces it, write that down where the next reader will
look. If not, start with the mutating routes.

---

## Low

### `guard_vocabulary_drift`

**Fires when** three or more distinct identity guard names are in use.

**Why.** Several names for the same job means several implementations of it, and
they will not agree for long. The one that gets the fix is whichever the person
remembered; the others keep the old behaviour silently.

**Fix.** One guard, re-exported if it needs different names at the edges.
