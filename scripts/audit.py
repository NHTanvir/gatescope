#!/usr/bin/env python3
"""Audit resolved routes for access control that is missing or in the wrong order.

Reads the JSON emitted by routes.py. Every finding names the guard chain that
was actually resolved and the line it came from, and says "no guard found"
rather than "vulnerable" -- an evidence-shaped claim survives a false positive
and a verdict does not.

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

AUTH_PATH = re.compile(
    r"/(login|signin|sign-?in|signup|sign-?up|register|password|reset|forgot|"
    r"otp|verify|token|refresh|magic-?link|2fa|mfa)\b", re.I
)
DEBUG_PATH = re.compile(
    r"/(debug|test|tests|__|internal|dev|dump|console|phpinfo|seed|migrate|"
    r"reset-?db|backup|export-?all|graphiql|playground)\b", re.I
)
ADMIN_PATH = re.compile(r"/(admin|administrator|staff|internal|manage|backoffice|root)\b", re.I)
SENSITIVE_PATH = re.compile(
    r"/(user|users|account|accounts|billing|payment|payments|invoice|invoices|"
    r"card|cards|subscription|subscriptions|customer|customers|member|members|"
    r"employee|patient|secret|credential|token|session|order|orders|export|"
    r"report|reports|audit)\b", re.I
)


def plural(n: int) -> str:
    return "" if n == 1 else "s"


def finding(sev, rule, where, msg, why, fix, evidence=None, routes=None) -> dict:
    return {
        "severity": sev,
        "rule": rule,
        "where": where,
        "message": msg,
        "why": why,
        "fix": fix,
        "evidence": evidence or [],
        "routes": routes or [],
    }


def label(r: dict) -> str:
    return f"{r['method']} {r['path']}"


def chain(r: dict) -> str:
    names = []
    for g in r["guards"]:
        tag = f"{g['name']} ({g['via']} {os.path.basename(g['file'])}:{g['line']})"
        if tag not in names:
            names.append(tag)
    return " -> ".join(names) if names else "nothing"


def at(r: dict, extra: dict = None) -> list:
    e = [{"file": r["file"], "line": r["line"], "snippet": label(r)}]
    if extra:
        e.append({
            "file": extra.get("file", r["file"]),
            "line": extra.get("line"),
            "snippet": extra.get("snippet", ""),
        })
    return [x for x in e if x.get("line")]


def parent(path: str) -> str:
    p = path.rsplit("/", 1)[0]
    return p or "/"


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

def rule_unauthenticated_mutation(doc, out) -> None:
    for r in doc["routes"]:
        if not r["mutating"] or r["level"] != "public" or r["kind"] == "server-action":
            continue
        if AUTH_PATH.search(r["path"]):
            continue  # a login endpoint is public on purpose
        out.append(finding(
            "critical", "unauthenticated_mutation", label(r),
            f"{label(r)} changes data and no guard was found on it.",
            "The guard chain resolved to nothing: no middleware on the route, none "
            "on the router it is mounted in, and no identity check inside the "
            "handler. Anyone who can reach the host can call it. Mutating endpoints "
            "are the ones where this is not a disclosure bug but a write.",
            f"// {r['file']}:{r['line']}\n"
            f"router.{r['method'].lower()}(\"{r['path'].split('/')[-1] or '/'}\", "
            f"requireAuth, async (req, res) => {{ … }});\n"
            f"//        ^ and assert ownership inside, see id_param_no_owner_check",
            at(r), [label(r)],
        ))


def rule_server_action_unguarded(doc, out) -> None:
    for r in doc["routes"]:
        if r["kind"] != "server-action":
            continue
        if r["session_source"] or r["level"] != "public":
            continue
        out.append(finding(
            "critical", "server_action_unguarded", label(r),
            f"Server action {r['handler']} has no identity check.",
            "A server action is an HTTP POST endpoint with a generated URL. It is "
            "not protected by the page that imports it, and it is not protected by "
            "anything that happens in the component tree: the client calls it "
            "directly. Whether the user can see the button is irrelevant to whether "
            "they can invoke the action.",
            f"// {r['file']}:{r['line']}\n"
            f"export async function {r['handler'] or 'action'}(…) {{\n"
            f"  const session = await auth();\n"
            f"  if (!session?.user) throw new Error(\"unauthorised\");\n"
            f"  // and never take the subject's id from the caller\n"
            f"}}",
            at(r), [label(r)],
        ))


def rule_caller_supplied_identity(doc, out) -> None:
    for r in doc["routes"]:
        if not r["caller_identity_param"] or r["session_source"]:
            continue
        out.append(finding(
            "critical", "caller_supplied_identity", label(r),
            f"{label(r)} takes the subject's id from the caller and never reads the session.",
            "The handler acts on whichever account the caller names. That is not an "
            "authorisation bug in the usual sense — there is no authorisation step "
            "to get wrong. Identity has to come from the session; an id in the "
            "arguments is a request, not a claim.",
            "- export async function deleteAccount(userId: string) {\n"
            "+ export async function deleteAccount() {\n"
            "+   const session = await auth();\n"
            "+   if (!session?.user) throw new Error(\"unauthorised\");\n"
            "+   const userId = session.user.id;",
            at(r), [label(r)],
        ))


def rule_id_param_no_owner_check(doc, out) -> None:
    for r in doc["routes"]:
        if not r["params"] or r["owner_check"] or r["level"] == "public":
            continue
        if r["level"] == "role":
            continue  # a role gate is a deliberate answer to "who may touch any row"
        if not (r["mutating"] or SENSITIVE_PATH.search(r["path"])):
            continue
        out.append(finding(
            "critical", "id_param_no_owner_check", label(r),
            f"{label(r)} is authenticated but never ties {', '.join(r['params'])} "
            f"to the caller.",
            "Being logged in is not being the owner. The handler looks the row up by "
            "the id in the URL, so any authenticated user reaches any row by "
            "changing one number. This is the most common serious bug in generated "
            "CRUD, because each handler looks correct on its own.",
            "- const row = await db.project.findUnique({ where: { id: req.params.id } });\n"
            "+ const row = await db.project.findFirst({\n"
            "+   where: { id: req.params.id, userId: req.user.id },\n"
            "+ });\n"
            "+ if (!row) return res.status(404).end();\n"
            "// 404 rather than 403: a 403 confirms the row exists",
            at(r), [label(r)],
        ))


def rule_admin_path_without_role_guard(doc, out) -> None:
    for r in doc["routes"]:
        if not ADMIN_PATH.search(r["path"]) or r["level"] == "role":
            continue
        out.append(finding(
            "high", "admin_path_without_role_guard", label(r),
            f"{label(r)} is an admin path and the chain is {r['level']}: {chain(r)}.",
            "Every logged-in user reaches it. The chain establishes who you are and "
            "then never asks what you are allowed to do. Admin surfaces are usually "
            "hidden in the UI instead, which protects the menu rather than the route.",
            "- router.get(\"/users\", requireAuth, handler);\n"
            "+ router.get(\"/users\", requireAuth, requireRole(\"admin\"), handler);",
            at(r), [label(r)],
        ))


def rule_inconsistent_sibling_guards(doc, out) -> None:
    groups: dict = {}
    for r in doc["routes"]:
        if r["kind"] == "server-action":
            continue
        groups.setdefault(parent(r["path"]), []).append(r)
    for prefix, rs in sorted(groups.items()):
        if len(rs) < 2:
            continue
        levels = {x["level"] for x in rs}
        if len(levels) < 2 or "public" not in levels:
            continue
        odd = [x for x in rs if x["level"] == "public"]
        guarded = [x for x in rs if x["level"] != "public"]
        if not guarded:
            continue
        out.append(finding(
            "high", "inconsistent_sibling_guards", prefix,
            f"{len(odd)} of {len(rs)} routes under {prefix} have no guard while the "
            f"rest do.",
            "Siblings that disagree are how this happens: the guard is on the "
            "handlers someone remembered, and the pattern looks right in review "
            "because the file above it is correct. The exception is the hole.",
            "// make the chain the router's property, not each handler's\n"
            f"app.use(\"{prefix}\", requireAuth);",
            [{"file": x["file"], "line": x["line"], "snippet": label(x)} for x in odd[:4]],
            [label(x) for x in odd],
        ))


def rule_guard_after_side_effect(doc, out) -> None:
    for r in doc["routes"]:
        if not r["guard_after_write"]:
            continue
        ev = r.get("guard_order_evidence", {})
        out.append(finding(
            "high", "guard_after_side_effect", label(r),
            f"{label(r)} writes at line {ev.get('write_line')} and checks identity "
            f"at line {ev.get('check_line')}.",
            "The check runs after the damage. Returning 401 afterwards tells the "
            "caller they were not allowed to do the thing they just did. Every "
            "unauthorised request still mutates the row; only the response changes.",
            "// move the check above the first write, and return before it\n"
            "const session = await getServerSession(req);\n"
            "if (!session) return res.status(401).end();\n"
            "await db.project.update({ … });",
            [{"file": r["file"], "line": ev.get("check_line") or r["line"],
              "snippet": f"identity checked here, after the write at :{ev.get('write_line')}"}],
            [label(r)],
        ))


def rule_mass_assignment(doc, out) -> None:
    for r in doc["routes"]:
        if not r["mass_assignment"]:
            continue
        out.append(finding(
            "high", "mass_assignment", label(r),
            f"{label(r)} spreads the request body straight into a write.",
            "Whatever the client sends becomes the record. Fields the form never "
            "showed — role, plan, ownerId, isVerified, balance — are writable by "
            "anyone who reads the schema, and the schema is usually in the same "
            "repository as the client.",
            "- data: { ...req.body, userId: req.user.id }\n"
            "+ const { name, description } = parse(CreateProject, req.body);\n"
            "+ data: { name, description, userId: req.user.id }",
            at(r, r.get("mass_evidence")), [label(r)],
        ))


def rule_public_read_of_sensitive_data(doc, out) -> None:
    for r in doc["routes"]:
        if r["level"] != "public" or r["mutating"]:
            continue
        if not (SENSITIVE_PATH.search(r["path"]) or r["touches_sensitive"]):
            continue
        if AUTH_PATH.search(r["path"]) or DEBUG_PATH.search(r["path"]):
            continue
        out.append(finding(
            "high", "public_read_of_sensitive_data", label(r),
            f"{label(r)} reads {r['path'].strip('/').split('/')[-1]} with no guard found.",
            "A read with no guard on a path that names people, money or credentials. "
            "Enumeration does not need a vulnerability here, only a loop. The "
            "response is also usually the whole row, including the columns the UI "
            "never renders.",
            "// guard it, and select only what the caller is allowed to see\n"
            "router.get(path, requireAuth, async (req, res) => {\n"
            "  const rows = await db.invoice.findMany({\n"
            "    where: { userId: req.user.id },\n"
            "    select: { id: true, total: true, issuedAt: true },\n"
            "  });\n"
            "});",
            at(r), [label(r)],
        ))


def rule_role_from_client(doc, out) -> None:
    for r in doc["routes"]:
        if not r["client_role"]:
            continue
        out.append(finding(
            "medium", "role_from_client", label(r),
            f"{label(r)} reads a role or permission out of the request.",
            "A privilege taken from the request body is a privilege the request can "
            "choose. Even where the value is only persisted rather than enforced, it "
            "becomes the value some later check reads, which turns a storage bug into "
            "an escalation.",
            "- data: { role: req.body.role }\n"
            "+ // role changes are their own endpoint, behind their own role gate\n"
            "+ data: { role: \"member\" }",
            at(r, r.get("client_role_evidence")), [label(r)],
        ))


def rule_auth_route_no_rate_limit(doc, out) -> None:
    for r in doc["routes"]:
        if not AUTH_PATH.search(r["path"]) or r["rate_limited"] or not r["mutating"]:
            continue
        out.append(finding(
            "medium", "auth_route_no_rate_limit", label(r),
            f"{label(r)} is a credential endpoint with no rate limit found.",
            "Credential endpoints are the ones worth brute forcing, and they are "
            "public by necessity, so the limit is the only control there is. Without "
            "it, password spraying and OTP guessing are bounded by bandwidth.",
            "const limiter = rateLimit({ windowMs: 15 * 60_000, max: 10 });\n"
            f"app.post(\"{r['path']}\", limiter, handler);",
            at(r), [label(r)],
        ))


def rule_debug_route_exposed(doc, out) -> None:
    for r in doc["routes"]:
        if not DEBUG_PATH.search(r["path"]):
            continue
        out.append(finding(
            "medium" if r["level"] != "public" else "high", "debug_route_exposed",
            label(r),
            f"{label(r)} looks like a debug or maintenance route, and the chain is "
            f"{r['level']}.",
            "These are written during an incident and outlive it. They tend to dump "
            "whole tables without pagination or field selection, because that was "
            "the point at the time.",
            "// delete it, or put it behind an environment check and a role gate\n"
            "if (process.env.NODE_ENV === \"production\") return res.status(404).end();",
            at(r), [label(r)],
        ))


def rule_no_identity_guard_anywhere(doc, out) -> None:
    if not doc["routes"]:
        return
    if any(r["level"] != "public" or r["session_source"] for r in doc["routes"]):
        return
    out.append(finding(
        "medium", "no_identity_guard_anywhere", doc["source"],
        f"None of the {len(doc['routes'])} routes found has any identity check.",
        "No middleware, no decorator, no session read anywhere in the resolved "
        "chains. Either authentication lives somewhere this tool cannot see — a "
        "gateway, a proxy, a platform layer — or the application has none. Both are "
        "worth knowing, and only one of them is fine.",
        "// if a gateway enforces it, say so where the next reader will look\n"
        "// if not, start with the mutating routes",
        [], [],
    ))


def rule_guard_vocabulary_drift(doc, out) -> None:
    names = {}
    for r in doc["routes"]:
        for g in r["guards"]:
            if g["kind"] == "identity":
                names.setdefault(g["name"].lower(), []).append(r)
    if len(names) < 3:
        return
    out.append(finding(
        "low", "guard_vocabulary_drift", doc["source"],
        f"{len(names)} different identity guards are in use: "
        f"{', '.join(sorted(names)[:6])}.",
        "Several names for the same job means several implementations of it, and "
        "they will not agree for long. The one that gets the fix is whichever the "
        "person remembered; the others keep the old behaviour silently.",
        "// one guard, re-exported if it needs different names at the edges",
        [], [],
    ))


RULES = [
    rule_unauthenticated_mutation, rule_server_action_unguarded,
    rule_caller_supplied_identity, rule_id_param_no_owner_check,
    rule_admin_path_without_role_guard, rule_inconsistent_sibling_guards,
    rule_guard_after_side_effect, rule_mass_assignment,
    rule_public_read_of_sensitive_data, rule_role_from_client,
    rule_auth_route_no_rate_limit, rule_debug_route_exposed,
    rule_no_identity_guard_anywhere, rule_guard_vocabulary_drift,
]


def audit(doc: dict) -> dict:
    out: list = []
    for rule in RULES:
        rule(doc, out)
    out.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["where"], f["rule"]))
    counts: dict = {}
    for f in out:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    levels: dict = {}
    for r in doc["routes"]:
        levels[r["level"]] = levels.get(r["level"], 0) + 1
    return {
        "source": doc.get("source"),
        "frameworks": doc.get("frameworks", []),
        "route_count": doc.get("route_count", 0),
        "files_scanned": doc.get("files_scanned"),
        "roles": doc.get("roles", []),
        "levels": levels,
        "counts": counts,
        "findings": out,
        "routes": doc["routes"],
    }


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def render_text(report: dict, show_fix: bool = True) -> str:
    c = report["counts"]
    total = sum(c.values())
    lv = report["levels"]
    lines = [
        "",
        f"  ACCESS AUDIT   {report['source']}",
        f"  {report['route_count']} routes · "
        f"{', '.join(report['frameworks']) or 'no framework detected'} · "
        f"{report['files_scanned']} files",
        "",
        "  " + " · ".join(
            f"{lv.get(k, 0)} {k}" for k in ("public", "authed", "owner", "role")
        ),
        "",
    ]
    if not total:
        lines += ["  No findings. Every route resolves to a guard.", ""]
        return "\n".join(lines)

    widest = max(max(c.values()), 8)
    for sev in ("critical", "high", "medium", "low"):
        n = c.get(sev, 0)
        if not n:
            continue
        bar = "█" * max(1, round(n / widest * 28))
        lines.append(f"  {sev:<9} {n:>3}  {bar}")
    lines += ["", f"  {total} finding{plural(total)} across "
                  f"{report['route_count']} routes", ""]

    for sev in ("critical", "high", "medium", "low"):
        group = [f for f in report["findings"] if f["severity"] == sev]
        if not group:
            continue
        title = f"{sev.upper()}  ({len(group)})"
        lines += ["", f"  {title}", "  " + "─" * max(len(title), 58)]
        for f in group:
            lines.append(f"  {f['where']}")
            lines.append(f"    {f['message']}")
            lines.append(f"    {f['rule']} — {f['why']}")
            for e in f["evidence"]:
                lines.append(f"      {e['file']}:{e['line']}  {e['snippet']}")
            if show_fix and f["fix"]:
                lines.append("")
                for fl in f["fix"].splitlines():
                    lines.append(f"      {fl}")
            lines.append("")
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    c = report["counts"]
    out = [
        f"# Access audit — `{report['source']}`",
        "",
        f"**{report['route_count']} routes** · "
        + " · ".join(
            f"{c[s]} {s}" for s in ("critical", "high", "medium", "low") if c.get(s)
        ),
        "",
        "| Severity | Route | Rule | Finding |",
        "|---|---|---|---|",
    ]
    for f in report["findings"]:
        msg = f["message"].replace("|", "\\|")
        out.append(f"| {f['severity']} | `{f['where']}` | `{f['rule']}` | {msg} |")
    out += ["", "## Fixes", ""]
    seen = set()
    for f in report["findings"]:
        key = (f["rule"], f["fix"])
        if not f["fix"] or key in seen:
            continue
        seen.add(key)
        out += [f"### `{f['where']}` — {f['rule']}", "", f["why"], "",
                "```diff" if f["fix"].lstrip().startswith(("-", "+")) else "```",
                f["fix"], "```", ""]
    return "\n".join(out)


def main(argv: list) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}
    if not args:
        print(
            "usage: audit.py <path-to-codebase|routes.json> "
            "[--json|--markdown] [--strict] [--no-fix]",
            file=sys.stderr,
        )
        return 2
    path = args[0]
    if path.endswith(".json"):
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    else:
        import routes
        doc = routes.build(path)

    report = audit(doc)
    if "--json" in flags:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif "--markdown" in flags:
        print(render_markdown(report))
    else:
        print(render_text(report, show_fix="--no-fix" not in flags))
    crit = report["counts"].get("critical", 0)
    return 1 if crit and "--strict" in flags else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
