# How to structure guards so the gaps cannot open

Notes for the agent. These are the decisions that determine whether the next
endpoint someone adds is protected by default or by memory.

## Put identity on the router, never on the handler

```js
app.use("/api", requireAuth);          // one line, every route inside it
```

Per-handler guards are a list that has to stay complete. Every new endpoint is
another chance to forget, and forgetting looks exactly like the correct code
until someone reads the middleware argument list. Make the default protected and
the exception explicit:

```js
app.use("/api/public", publicRouter);  // named so the exception is obvious
```

## Identity and authority are two different questions

`requireAuth` answers *who are you*. `requireRole("admin")` answers *what may
you do*. Collapsing them into one middleware means every call site that needs
one gets both, or neither, and admin surfaces end up guarded by a login check.

## Authorise in the query, not after it

```diff
- const row = await db.project.findUnique({ where: { id } });
- if (row.userId !== session.user.id) return res.status(403).end();
+ const row = await db.project.findFirst({ where: { id, userId: session.user.id } });
+ if (!row) return res.status(404).end();
```

Three reasons the second is better. The check cannot be forgotten in a later
refactor, because there is no separate check to forget. It cannot be bypassed by
an early return added above it. And it returns 404 instead of 403, so it does
not confirm that a row exists to someone who may not see it.

## Identity comes from the session, never from the arguments

A handler that takes `userId` acts on whoever the caller names. This is the
single most common shape of a serious bug in server actions and RPC-style
endpoints, because the function signature reads like ordinary code:

```ts
export async function deleteAccount(userId: string)   // a request, not a claim
export async function deleteAccount()                 // subject is the session
```

Where one user really does act on another, make it a role-gated endpoint, so the
id is deliberate and the authority is checked.

## Treat a server action as an endpoint

It is a POST with a generated URL. The button, the page, the component tree and
the router have nothing to do with whether it can be called. Every action starts
with its own identity check, exactly as a route handler would.

## Parse the body, never spread it

```diff
- data: { ...req.body, userId: req.user.id }
+ const { name, description } = CreateProject.parse(req.body);
+ data: { name, description, userId: req.user.id }
```

Spreading means your write schema is whatever the client decides to send. An
explicit list also documents the endpoint better than any comment.

## Never read a privilege from the request

Role, plan, tier, scope, `isAdmin`, `isVerified`: if the client can send it, the
client can choose it. Even storing it unvalidated is enough — the next feature
reads that column and enforces it.

## Name the levels, then check the matrix

Four levels are enough for most applications: public, authed, owner, role. The
useful question is not "is this route protected" but "which of the four is it,
and did anyone decide that". A matrix makes a wrong answer visible at a glance;
a list of middleware does not.

## Rate-limit what is public by necessity

Login, signup, password reset, OTP, token refresh. These cannot be guarded by
identity, so the limit is the only control there is.

## Delete the debug route

It was written at 2am during an incident, it dumps a whole table, and it has no
owner. It will still be there in two years.
