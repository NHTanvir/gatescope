#!/usr/bin/env python3
"""Find every route a codebase exposes, and resolve what guards it.

Reads route definitions for Express-style routers, the Next.js App Router
(including server actions), FastAPI, Flask and Laravel, then resolves each
route's guard chain to one of four levels: public, authed, role, owner.

Nothing is asserted that is not shown: every guard carries the file and line it
was resolved from, and a route with no guard is reported as "no guard found"
rather than as a vulnerability.

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import sys

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".nuxt",
    "__pycache__", ".venv", "venv", "env", ".tox", "coverage", ".cache",
    "target", ".idea", ".vscode", "bower_components", ".svelte-kit",
    "storage", "migrations", "tests", "test", "__tests__", "spec",
}
JS_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
PY_EXT = {".py"}
PHP_EXT = {".php"}
CODE_EXT = JS_EXT | PY_EXT | PHP_EXT
MAX_BYTES = 1_500_000

METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "all")
MUTATING = {"POST", "PUT", "PATCH", "DELETE", "ALL"}

# ---- guard vocabularies -------------------------------------------------

IDENTITY = re.compile(
    r"\b(require_?auth\w*|requires_?login|is_?authenticated|authenticate\w*|"
    r"ensure_?logged_?in|login_?required|auth_?required|with_?auth|"
    r"get_?server_?session|current_?user|get_?current_?user|verify_?token|"
    r"verify_?jwt|check_?auth|auth_?middleware|protect\w*|passport|"
    r"session_?required|jwt_?required|token_?required|must_?be_?logged_?in|"
    r"clerk_?middleware|get_?session|auth_?guard|signed_?in)\b", re.I
)
ROLE = re.compile(
    r"\b(require_?admin|is_?admin|has_?role|require_?role|roles?_?required|"
    r"authorize\w*|authorise\w*|can_?access|has_?permission|require_?permission|"
    r"permission_?required|check_?role|admin_?only|ensure_?admin|gate|ability|"
    r"restrict_?to)\b", re.I
)
ROLE_ARG = re.compile(
    r"(?:role|roles|permission|ability|can|authorize|restrict_?to|middleware)"
    r"\s*[:(\[]?\s*['\"]([\w.:|-]+)['\"]", re.I
)
RATE_LIMIT = re.compile(
    r"(\brate_?limit\w*|\w*throttle\w*|\w*limiter\b|\bslow_?down\b|"
    r"\bratelimit\w*|\btoken_?bucket\b)", re.I
)
CSRF = re.compile(r"\b(csrf|xsrf|same_?site|double_?submit)\b", re.I)

# Middleware declared as a string: Laravel's ->middleware('auth'), Flask-style
# lists, FastAPI dependency names. Anchored, so a path never matches by accident.
# Not here on purpose: `web` (sessions and CSRF), `session`, `signed` (a URL
# signature) and `guest` (the opposite of a login check). None of them establishes
# who the caller is, and crediting one hides a route that nothing guards.
MW_IDENTITY = re.compile(
    r"^(auth|auth\.\w+|auth:[\w,.-]+|sanctum|jwt|jwt\.auth|jwt_?auth|verified|"
    r"authenticated|protected)$", re.I
)
MW_ROLE = re.compile(
    r"^(role|roles|admin|is_?admin|superuser|staff)(?::[\w,.|-]+)?$|"
    r"^(can|permission|permissions|ability|abilities|scope|scopes)"
    r"(?::[\w,.|-]+)?$", re.I
)

# Where identity comes from. A value the caller passed in is not identity.
SESSION_SOURCE = re.compile(
    r"\b(?:req|request|ctx|context|locals|event)\.user\b|"
    r"\bsession\s*[.?\[]|\bsession\.user\b|\bgetServerSession\b|"
    r"\bcurrent_?user\b|\bauth\s*\(\s*\)|\bauth\.user\b|"
    r"\bgetUser\s*\(|\buseUser\s*\(|\bme\.id\b|\bclerk\w*\b|"
    r"\brequest\.user\b|\$request->user\s*\(|\bauth\(\)->", re.I
)
# An ownership check compares the row's owner against the session identity.
OWNER_FIELD = re.compile(
    r"\b(?:user|owner|author|account|creator|tenant|org|organisation|organization)"
    r"_?id\b|\bbelongs_?to\b|\bscoped_?to_?user\b|\bfor_?user\b", re.I
)


def _owner_check(line: str) -> bool:
    """True only when an owner field is constrained by a session identity."""
    if not SESSION_SOURCE.search(line):
        return False
    if OWNER_FIELD.search(line):
        return True
    # filter(user=request.user) / ->where('user_id', auth()->id())
    if re.search(
        r"\bfilter\s*\([^)]{0,120}\buser\s*=|"
        r"->where\s*\(\s*['\"](?:user_?id|owner_?id)['\"]", line, re.I
    ):
        return True
    # where: { id: session.user.id } -- the row is addressed by the caller's own id
    return bool(re.search(
        r"\b(?:where|filter)\b[^;]{0,160}:\s*[\w.$>-]*"
        r"(?:session|req\.user|request\.user|current_?user|auth\(\))[\w.$>-]*",
        line, re.I,
    ))
MUTATOR_CALL = re.compile(
    r"\.(create|createMany|update|updateMany|upsert|delete|deleteMany|destroy|"
    r"save|insert|remove|bulkWrite|findOneAndUpdate|findOneAndDelete)\s*\(|"
    r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.I
)
BODY_SPREAD = re.compile(
    r"\.{3}\s*(?:req|request)\.(?:body|data|json)|"
    r"\.{3}\s*(?:body|data|input)\b|"
    r"\*\*\s*(?:request\.|req\.)?(?:json|data|body|payload)\b|"
    r"\$request->all\(\)|\$request->except\(|Object\.assign\s*\([^,]+,\s*"
    r"(?:req|request)\.body", re.I
)
CLIENT_ROLE = re.compile(
    r"(?:req|request)\.(?:body|query|params|headers|args|form|get_json\(\))"
    r"[\[.]{1,2}['\"]?(role|roles|is_?admin|admin|permission|scope|tier|plan)\b|"
    r"\$request->(?:input|get|query)\s*\(\s*['\"](role|is_?admin|admin|permission)",
    re.I,
)
SENSITIVE = re.compile(
    r"\b(user|users|account|accounts|payment|payments|invoice|invoices|card|"
    r"subscription|credential|secret|token|session|order|orders|customer|"
    r"customers|member|members|employee|patient|ssn|salary)\b", re.I
)
DEBUG_PATH = re.compile(
    r"/(debug|test|tests|__|internal|dev|dump|console|admin-?tools|phpinfo|"
    r"seed|migrate|reset|backup|export-?all|graphiql|playground)\b", re.I
)
AUTH_PATH = re.compile(
    r"/(login|signin|sign-?in|signup|sign-?up|register|password|reset|forgot|"
    r"otp|verify|token|refresh|magic-?link|2fa|mfa)\b", re.I
)


def walk(root: str) -> list:
    out = []
    if os.path.isfile(root):
        base = os.path.dirname(os.path.abspath(root)) or "."
        files = [(os.path.basename(root), os.path.abspath(root))]
    else:
        base = os.path.abspath(root)
        files = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(
                d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
            )
            for fn in sorted(filenames):
                if os.path.splitext(fn)[1].lower() in CODE_EXT:
                    full = os.path.join(dirpath, fn)
                    files.append((os.path.relpath(full, base), full))
    for rel, full in files:
        try:
            if os.path.getsize(full) > MAX_BYTES:
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        out.append((rel.replace(os.sep, "/"), full, lines))
    return out


def strip_comment(line: str) -> str:
    for marker in ("//", "#"):
        idx = line.find(marker)
        while idx != -1:
            before = line[:idx]
            if before.count("'") % 2 == 0 and before.count('"') % 2 == 0:
                return before
            idx = line.find(marker, idx + 1)
    return line


def body_of(lines: list, start: int, limit: int = 120) -> list:
    """Lines of the handler that begins at or just after `start`."""
    depth = 0
    parens = 0
    seen_open = False
    out = []
    for i in range(start, min(len(lines), start + limit)):
        line = strip_comment(lines[i])
        out.append((i, lines[i]))
        depth += line.count("{") - line.count("}")
        parens += line.count("(") - line.count(")")
        if "{" in line:
            seen_open = True
        if seen_open and depth <= 0 and i > start:
            break
        # `app.put(path, guard, namedHandler);` has no inline body. Reading on would
        # borrow the next route's handler and credit its checks to this one.
        if not seen_open and parens <= 0:
            break
    return out


def py_body(lines: list, start: int, limit: int = 120) -> list:
    """Lines of a Python function defined at or after `start`."""
    out = []
    indent = None
    for i in range(start, min(len(lines), start + limit)):
        line = lines[i]
        if indent is None:
            if re.match(r"\s*(async\s+)?def\s", line):
                indent = len(line) - len(line.lstrip())
                out.append((i, line))
            continue
        if not line.strip():
            out.append((i, line))
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break
        out.append((i, line))
    return out


def classify(tokens: list) -> tuple:
    """Turn guard tokens into (level, roles). Highest wins."""
    level, roles = "public", []
    for t in tokens:
        # guard_tokens already decided what this is; do not re-litigate the name
        if t.get("kind") == "role" or ROLE.search(t["name"]):
            level = "role"
            roles += t.get("roles", [])
        elif level != "role":
            level = "authed"
    return level, sorted(set(roles))


# Guard names that the plain vocabulary above misses, because its leading \b never
# fires inside a camelCase word (ensureAuthenticated, isLoggedIn, requireUser).
# Matched against the WHOLE identifier, snake_cased, so authController.register,
# auth.login and authService are not mistaken for guards.
EXTRA_IDENTITY = re.compile(
    r"^(?:authn|authed|auth_check|is_auth\w*|ensure_auth\w*|is_logged_?in|logged_?in|"
    r"ensure_logged_?in|require_login|require_user|require_session|require_token|"
    r"verify_(?:user|token|jwt|session|auth)\w*|check_(?:jwt|auth|token|session|user)\w*|"
    r"validate_(?:token|jwt|session|user)\w*|jwt_auth\w*|auth_jwt\w*|jwt_check|"
    r"with_user|with_session|get_current_\w+|oauth2_scheme|authenticate\w*|"
    r"authenticated\w*)$"
)


def _snake(word: str) -> str:
    """ensureAuthenticated -> ensure_authenticated"""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", word).replace("-", "_").lower()


def extra_identity(word: str) -> bool:
    parts = word.split(".")
    last = _snake(parts[-1])
    if len(parts) == 1 and last == "auth":
        return True  # `app.post(path, auth, handler)`; `auth.login` is a namespace
    return bool(EXTRA_IDENTITY.match(last))



def guard_tokens(text: str, file: str, line: int, via: str) -> list:
    """Every guard-looking identifier on a line, with what it is."""
    found = []
    for m in re.finditer(r"[A-Za-z_][\w.:\\-]*", text):
        word = m.group(0)
        if ROLE.search(word):
            roles = [r for r in ROLE_ARG.findall(text)]
            found.append({
                "name": word, "kind": "role", "roles": roles,
                "file": file, "line": line, "via": via,
            })
        elif IDENTITY.search(word) or (via != "body" and extra_identity(word)):
            found.append({
                "name": word, "kind": "identity", "roles": [],
                "file": file, "line": line, "via": via,
            })
    # `->middleware('auth')` and `middleware=['role:admin']` carry the guard in a string
    for lit in re.findall(r"['\"]([\w.:|,-]+)['\"]", text):
        is_role = bool(MW_ROLE.match(lit)) or bool(ROLE.search(lit))
        is_identity = bool(MW_IDENTITY.match(lit)) or bool(IDENTITY.search(lit))
        if not (is_role or is_identity):
            continue
        roles = []
        if ":" in lit:
            roles = [x for part in lit.split(":")[1:] for x in part.split(",") if x]
        elif is_role and lit.lower() in {"admin", "staff", "superuser"}:
            roles = [lit.lower()]
        found.append({
            "name": lit, "kind": "role" if is_role else "identity",
            "roles": roles, "file": file, "line": line, "via": via,
        })
    return found


RE_IMPORT = re.compile(
    r"import\s+(?:(\w+)|\{[^}]*\})\s*(?:,\s*\{[^}]*\}\s*)?from\s*['\"]([^'\"]+)['\"]"
)
RE_REQUIRE = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]")
RE_MOUNT = re.compile(
    r"\b\w+\s*\.\s*use\s*\(\s*[`'\"]([^`'\"]+)[`'\"]\s*,\s*([\w, ]+?)\s*\)"
)


def _resolve(spec: str, from_rel: str, known: set) -> str:
    """./routes/projects from src/server.ts -> src/routes/projects.ts"""
    if not spec.startswith("."):
        return ""
    base = os.path.normpath(os.path.join(os.path.dirname(from_rel), spec))
    base = base.replace(os.sep, "/")
    for cand in [base] + [base + e for e in sorted(JS_EXT)] + [
        base + "/index" + e for e in sorted(JS_EXT)
    ]:
        if cand in known:
            return cand
    return ""


def mount_map(files: list) -> dict:
    """{file: url prefix} for routers mounted with app.use('/prefix', router)."""
    known = {rel for rel, _f, _l in files}
    direct = {}
    for rel, _full, lines in files:
        if os.path.splitext(rel)[1].lower() not in JS_EXT:
            continue
        imports = {}
        for raw in lines:
            for m in list(RE_IMPORT.finditer(raw)) + list(RE_REQUIRE.finditer(raw)):
                if m.group(1):
                    imports[m.group(1)] = m.group(2)
        for raw in lines:
            for m in RE_MOUNT.finditer(strip_comment(raw)):
                prefix = m.group(1)
                for ident in [x.strip() for x in m.group(2).split(",")]:
                    spec = imports.get(ident)
                    if not spec:
                        continue
                    target = _resolve(spec, rel, known)
                    if target:
                        direct[target] = (prefix, rel)
    # a mounted router may itself be mounted; fold the chain in
    out = {}
    for target in direct:
        prefix, parent = direct[target], None
        chain, cur, seen = [], target, set()
        while cur in direct and cur not in seen:
            seen.add(cur)
            pfx, parent = direct[cur]
            chain.insert(0, pfx.strip("/"))
            cur = parent
        out[target] = "/" + "/".join(p for p in chain if p)
    return out


def route(method, path, file, line, handler="", guards=None, kind="route") -> dict:
    path = "/" + (path or "").strip("/")
    return {
        "method": method.upper(),
        "path": path or "/",
        "file": file,
        "line": line,
        "handler": handler,
        "kind": kind,
        "guards": guards or [],
        "params": re.findall(r"[:{\[](\w+)[}\]]?", path),
        "mutating": method.upper() in MUTATING,
        "owner_check": False,
        "session_source": False,
        "enforces": False,
        "caller_identity_param": False,
        "mass_assignment": False,
        "client_role": False,
        "touches_sensitive": False,
        "guard_after_write": False,
        "rate_limited": False,
        "body_lines": [],
    }


CALLER_IDENTITY = re.compile(
    r"\b(user_?id|account_?id|owner_?id|customer_?id|tenant_?id|org_?id|"
    r"member_?id|actor_?id)\b\s*[,:)=]", re.I
)


ENFORCE = re.compile(
    r"\b401\b|\b403\b|unauthorised|unauthorized|forbidden|\bthrow\b|"
    r"\bredirect\s*\(|\babort\s*\(|\bnotFound\s*\(|HTTPException|"
    r"\bdeny\b|\breject\b", re.I
)


def inspect_body(r: dict, body: list) -> None:
    """Read the handler for ownership checks, mass assignment and ordering."""
    first_write, first_identity = None, None
    if body:
        sig = " ".join(l for _, l in body[:3])
        if CALLER_IDENTITY.search(sig.split("{", 1)[0] if "{" in sig else sig):
            r["caller_identity_param"] = True
    for i, raw in body:
        line = strip_comment(raw)
        if not line.strip():
            continue
        if SESSION_SOURCE.search(line):
            r["session_source"] = True
        if ENFORCE.search(line):
            r["enforces"] = True
        if _owner_check(line):
            r["owner_check"] = True
            r.setdefault("owner_evidence", {"file": r["file"], "line": i + 1,
                                            "snippet": line.strip()[:140]})
        if BODY_SPREAD.search(line):
            r["mass_assignment"] = True
            r.setdefault("mass_evidence", {"file": r["file"], "line": i + 1,
                                           "snippet": line.strip()[:140]})
        if CLIENT_ROLE.search(line):
            r["client_role"] = True
            r.setdefault("client_role_evidence", {"file": r["file"], "line": i + 1,
                                                  "snippet": line.strip()[:140]})
        if SENSITIVE.search(line) and MUTATOR_CALL.search(line):
            r["touches_sensitive"] = True
        if RATE_LIMIT.search(line):
            r["rate_limited"] = True
        if MUTATOR_CALL.search(line) and first_write is None:
            first_write = i
        if IDENTITY.search(line) and first_identity is None:
            first_identity = i
            if not any(g["via"] == "body" for g in r["guards"]):
                r["guards"] += guard_tokens(line, r["file"], i + 1, "body")
        elif ROLE.search(line):
            r["guards"] += guard_tokens(line, r["file"], i + 1, "body")
    if first_write is not None and first_identity is not None and first_identity > first_write:
        r["guard_after_write"] = True
        r["guard_order_evidence"] = {
            "file": r["file"], "write_line": first_write + 1,
            "check_line": first_identity + 1,
        }
    if body:
        r["body_lines"] = [body[0][0] + 1, body[-1][0] + 1]


# --------------------------------------------------------------------------
# Express / Fastify / Koa-style routers
# --------------------------------------------------------------------------

RE_EXPRESS = re.compile(
    r"\b(\w+)\s*\.\s*(" + "|".join(METHODS) + r")\s*\(\s*[`'\"]([^`'\"]*)[`'\"]\s*(.*)$",
    re.I,
)
RE_USE = re.compile(
    r"\b(\w+)\s*\.\s*use\s*\(\s*(?:[`'\"]([^`'\"]*)[`'\"]\s*,)?\s*(.*)$", re.I
)


def parse_express(rel: str, lines: list, prefix: str = "") -> list:
    """Routes plus file-level middleware. Chains are resolved within the file."""
    uses = []
    for i, raw in enumerate(lines):
        line = strip_comment(raw)
        m = RE_USE.search(line)
        if m and not re.search(r"\buse(State|Effect|Memo|Callback|Ref|Router)\b", line):
            upath = m.group(2) or ""
            toks = guard_tokens(m.group(3), rel, i + 1, "middleware")
            if toks:
                uses.append((upath, toks))

    out = []
    for i, raw in enumerate(lines):
        line = strip_comment(raw)
        m = RE_EXPRESS.search(line)
        if not m:
            continue
        obj, method, path, rest = m.group(1), m.group(2), m.group(3), m.group(4)
        if obj.lower() in {"axios", "fetch", "http", "https", "client", "api", "supertest", "request"}:
            continue
        if not path.startswith("/"):
            continue
        guards = guard_tokens(rest, rel, i + 1, "inline")
        for upfx, toks in uses:
            here = (prefix.rstrip("/") + path) if prefix else path
            if not upfx or here.startswith(upfx.rstrip("/")) or path.startswith(upfx.rstrip("/")):
                guards = toks + guards
        handler = ""
        hm = re.search(r",\s*(\w+)\s*\)\s*;?\s*$", rest)
        if hm:
            handler = hm.group(1)
        full = (prefix.rstrip("/") + path) if prefix else path
        r = route(method, full, rel, i + 1, handler, guards, "express")
        if RATE_LIMIT.search(rest):
            r["rate_limited"] = True
        inspect_body(r, body_of(lines, i))
        out.append(r)
    return out


# --------------------------------------------------------------------------
# Next.js App Router + server actions
# --------------------------------------------------------------------------

RE_NEXT_HANDLER = re.compile(
    r"export\s+(?:async\s+)?(?:function|const)\s+(" + "|".join(m.upper() for m in METHODS) + r")\b"
)
RE_EXPORTED_FN = re.compile(r"export\s+(?:async\s+)?function\s+(\w+)")


def next_path(rel: str) -> str:
    parts = rel.split("/")
    try:
        idx = parts.index("app")
    except ValueError:
        idx = parts.index("src") if "src" in parts else -1
    segs = parts[idx + 1 : -1] if idx >= 0 else parts[:-1]
    keep = [s for s in segs if not (s.startswith("(") and s.endswith(")"))]
    return "/" + "/".join(keep)


def parse_next(rel: str, lines: list) -> list:
    base = os.path.basename(rel)
    text = "\n".join(lines)
    out = []
    if base.startswith("route."):
        path = next_path(rel)
        for i, raw in enumerate(lines):
            m = RE_NEXT_HANDLER.search(strip_comment(raw))
            if not m:
                continue
            r = route(m.group(1), path, rel, i + 1, m.group(1), [], "next-route")
            inspect_body(r, body_of(lines, i))
            out.append(r)
    is_action_file = bool(re.search(r"^\s*['\"]use server['\"]", text, re.M))
    if is_action_file:
        for i, raw in enumerate(lines):
            m = RE_EXPORTED_FN.search(strip_comment(raw))
            if not m:
                continue
            r = route("POST", f"{next_path(rel)}#{m.group(1)}", rel, i + 1,
                      m.group(1), [], "server-action")
            inspect_body(r, py_body(lines, i) or body_of(lines, i))
            out.append(r)
    return out


# --------------------------------------------------------------------------
# FastAPI / Flask
# --------------------------------------------------------------------------

RE_FASTAPI = re.compile(
    r"@\s*(\w+)\s*\.\s*(" + "|".join(METHODS) + r")\s*\(\s*[`'\"]([^`'\"]*)[`'\"](.*)$",
    re.I,
)
RE_FLASK = re.compile(
    r"@\s*(\w+)\s*\.\s*route\s*\(\s*[`'\"]([^`'\"]*)[`'\"](.*)$", re.I
)


def parse_python(rel: str, lines: list) -> list:
    out = []
    for i, raw in enumerate(lines):
        line = strip_comment(raw)
        methods, path, rest = None, None, ""
        m = RE_FASTAPI.search(line)
        if m:
            methods, path, rest = [m.group(2)], m.group(3), m.group(4)
        else:
            m = RE_FLASK.search(line)
            if m:
                path, rest = m.group(2), m.group(3)
                found = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", rest, re.I)
                methods = found or ["GET"]
        if not path or not path.startswith("/"):
            continue
        # decorators stack above the def, and extra args may wrap to later lines
        window = "\n".join(l for _, l in [(j, lines[j]) for j in range(i, min(len(lines), i + 6))])
        guards = guard_tokens(window.split("def ")[0], rel, i + 1, "decorator")
        for j in range(max(0, i - 6), i):
            if lines[j].lstrip().startswith("@"):
                guards += guard_tokens(lines[j], rel, j + 1, "decorator")
        body = py_body(lines, i)
        sig = " ".join(l for _, l in body[:4])
        guards += [
            g for g in guard_tokens(sig, rel, i + 1, "depends")
            if "depends" in sig.lower()
        ]
        for meth in methods:
            r = route(meth, path, rel, i + 1,
                      (re.search(r"def\s+(\w+)", sig).group(1) if re.search(r"def\s+(\w+)", sig) else ""),
                      list(guards), "python")
            if RATE_LIMIT.search(window):
                r["rate_limited"] = True
            inspect_body(r, body)
            out.append(r)
    return out


# --------------------------------------------------------------------------
# Laravel
# --------------------------------------------------------------------------

LARAVEL_VERBS = METHODS + ("any",)
RE_LARAVEL = re.compile(
    r"Route\s*::\s*(" + "|".join(LARAVEL_VERBS)
    + r"|resource|apiResource)\s*\(\s*['\"]([^'\"]*)['\"](.*)$",
    re.I,
)
# Route::middleware('auth')->get('/me', ...): a guard chained in front of one route
RE_LARAVEL_CHAINED = re.compile(
    r"->\s*(" + "|".join(LARAVEL_VERBS)
    + r"|resource|apiResource)\s*\(\s*['\"]([^'\"]*)['\"](.*)$",
    re.I,
)
RE_LARAVEL_HEAD = re.compile(
    r"Route\s*::\s*(?:middleware|group|prefix|name|domain|controller)\s*\(", re.I
)
# what Route::resource registers, minus the two HTML form pages
RESOURCE_ACTIONS = [
    ("index", "GET", ""), ("store", "POST", ""), ("show", "GET", "/{%s}"),
    ("update", "PUT", "/{%s}"), ("destroy", "DELETE", "/{%s}"),
]


def _call_args(text: str, open_idx: int) -> str:
    """The text between the parenthesis at `open_idx` and the one that closes it."""
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : j]
    return text[open_idx + 1 :]


def laravel_guards(text: str, file: str, line: int, via: str) -> list:
    """Guards a Laravel statement declares, read from its middleware and nowhere else.

    A prefix, a route name and a controller are not guards. Tokenising the whole
    line reads `->prefix('admin')` as a role and `->name('auth.login')` as a
    login check, which credits protection that is not there.
    """
    parts = []
    for m in re.finditer(r"(?<![A-Za-z])middleware\s*\(", text):
        parts.append(_call_args(text, m.end() - 1))
    for m in re.finditer(
        r"['\"]middleware['\"]\s*=>\s*(\[[^\]]*\]|['\"][^'\"]*['\"])", text
    ):
        parts.append(m.group(1))
    return guard_tokens(" ".join(parts), file, line, via) if parts else []


def _guard_key(name: str) -> str:
    """`App\\Http\\Middleware\\Authenticate::class` and `auth:sanctum` -> comparable names."""
    return name.replace("::class", "").split("\\")[-1].split(":")[0].lower()


def laravel_removed(text: str) -> set:
    """Names passed to withoutMiddleware(...), which undo an inherited guard."""
    names = set()
    for m in re.finditer(r"withoutMiddleware\s*\(", text):
        args = _call_args(text, m.end() - 1)
        for lit in re.findall(r"['\"]([\w.:|,\\-]+)['\"]", args):
            names.add(_guard_key(lit))
        for cls in re.findall(r"([A-Za-z_\\]+)::class", args):
            names.add(_guard_key(cls))
    return names


def laravel_prefix(text: str) -> str:
    m = re.search(r"prefix\s*\(\s*['\"]([^'\"]*)['\"]", text) or re.search(
        r"['\"]prefix['\"]\s*=>\s*['\"]([^'\"]*)['\"]", text
    )
    return m.group(1).strip("/") if m else ""


def _singular(word: str) -> str:
    """photos -> photo, categories -> category. Only used to name a route parameter."""
    word = word.replace("-", "_")
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("ses") and len(word) > 3:
        return word[:-2]
    if word.endswith("s") and not word.endswith("ss") and len(word) > 1:
        return word[:-1]
    return word


def parse_php(rel: str, lines: list) -> list:
    out = []
    stack = []      # groups whose closure is open
    pending = None  # a declaration spread over several lines that has not opened yet
    depth = 0
    for i, raw in enumerate(lines):
        line = strip_comment(raw)
        stripped = line.strip()
        before = depth
        depth += line.count("{") - line.count("}")

        direct = RE_LARAVEL.search(line)
        continuing = pending is not None and stripped.startswith("->")
        # anything in front of a route on the same line is a group opening around it
        head_text = line[: direct.start()] if direct else line
        head = RE_LARAVEL_HEAD.search(head_text) if stripped.startswith("Route") else None
        chained = None
        if not direct and (head or continuing):
            chained = RE_LARAVEL_CHAINED.search(line)

        if head and not chained:
            pending = {
                "guards": laravel_guards(head_text, rel, i + 1, "group"),
                "prefix": laravel_prefix(head_text),
                "throttle": bool(RATE_LIMIT.search(head_text)),
                "is_group": False,
            }
        elif continuing and not chained:
            pending["guards"] += laravel_guards(line, rel, i + 1, "group")
            more = laravel_prefix(line)
            if more:
                pending["prefix"] = "/".join(p for p in (pending["prefix"], more) if p)
            pending["throttle"] = pending["throttle"] or bool(RATE_LIMIT.search(line))

        if pending is not None and not chained:
            scope = head_text if head else line
            if re.search(r"\bgroup\s*\(", scope):
                pending["is_group"] = True
            if pending["is_group"] and "{" in scope:
                pending["depth"] = before
                stack.append(pending)
                pending = None
            elif stripped.endswith(";"):
                pending = None  # the statement ended without opening a closure

        m = direct or chained
        if m:
            verb, path, rest = m.group(1).lower(), m.group(2), m.group(3)
            # the statement: this line, plus any `->middleware(...)` lines chained under it
            stmt = line[m.start():] if direct else line
            j = i + 1
            while not stmt.rstrip().endswith(";") and j < min(len(lines), i + 8):
                nxt = strip_comment(lines[j])
                if not nxt.strip().startswith("->"):
                    break
                stmt += " " + nxt.strip()
                j += 1
            own = laravel_guards(stmt, rel, i + 1, "chain")
            inherited = [g for grp in stack for g in grp["guards"]]
            prefixes = [grp["prefix"] for grp in stack]
            throttled = any(grp["throttle"] for grp in stack)
            if chained and pending is not None:
                inherited += pending["guards"]
                prefixes.append(pending["prefix"])
                throttled = throttled or pending["throttle"]
            if chained:
                prefixes.append(laravel_prefix(line[: m.start()]))
            removed = laravel_removed(stmt)
            guards = [g for g in inherited if _guard_key(g["name"]) not in removed] + own
            base = "/".join(p for p in prefixes + [path.strip("/")] if p)

            if verb in {"resource", "apiresource"}:
                ident = _singular(path.strip("/").split("/")[-1].split(".")[-1]) or "id"
                keep = None
                om = re.search(r"->only\s*\(([^)]*)\)", stmt)
                em = re.search(r"->except\s*\(([^)]*)\)", stmt)
                if om:
                    keep = set(re.findall(r"['\"](\w+)['\"]", om.group(1)))
                specs = [
                    (meth, suffix % ident if "%s" in suffix else suffix)
                    for action, meth, suffix in RESOURCE_ACTIONS
                    if (keep is None or action in keep)
                    and not (em and action in re.findall(r"['\"](\w+)['\"]", em.group(1)))
                ]
            elif verb == "any":
                specs = [("ALL", "")]
            else:
                specs = [(verb, "")]

            for meth, suffix in specs:
                r = route(meth, "/" + base + suffix, rel, i + 1, "", list(guards), "laravel")
                if throttled or RATE_LIMIT.search(stmt):
                    r["rate_limited"] = True
                out.append(r)
            if chained and pending is not None and stripped.endswith(";"):
                pending = None

        while stack and depth <= stack[-1]["depth"]:
            stack.pop()
    return out


# --------------------------------------------------------------------------

def build(root: str) -> dict:
    files = walk(root)
    mounts = mount_map(files)
    routes, frameworks = [], set()
    for rel, _full, lines in files:
        ext = os.path.splitext(rel)[1].lower()
        if ext in JS_EXT:
            base = os.path.basename(rel)
            if base.startswith("route.") or "/app/" in f"/{rel}" or rel.startswith("app/"):
                found = parse_next(rel, lines)
                if found:
                    frameworks.add("next")
                    routes += found
            found = parse_express(rel, lines, mounts.get(rel, ""))
            if found:
                frameworks.add("express")
                routes += found
        elif ext in PY_EXT:
            found = parse_python(rel, lines)
            if found:
                frameworks.add("fastapi/flask")
                routes += found
        elif ext in PHP_EXT:
            found = parse_php(rel, lines)
            if found:
                frameworks.add("laravel")
                routes += found

    # guards declared where a router is mounted apply to everything inside it
    prefix_guards = []
    for rel, _full, lines in files:
        if os.path.splitext(rel)[1].lower() not in JS_EXT:
            continue
        for i, raw in enumerate(lines):
            m = RE_USE.search(strip_comment(raw))
            if not m or not m.group(2):
                continue
            toks = guard_tokens(m.group(3), rel, i + 1, "mounted-middleware")
            if toks:
                prefix_guards.append((m.group(2).rstrip("/"), toks))
    for r in routes:
        if r["kind"] != "express":
            continue  # a Next.js handler is not mounted in the Express app
        for pfx, toks in prefix_guards:
            if pfx and r["path"].startswith(pfx) and not any(
                g["name"] == t["name"] for g in r["guards"] for t in toks
            ):
                r["guards"] = toks + r["guards"]

    seen, uniq = set(), []
    for r in routes:
        key = (r["method"], r["path"], r["file"], r["line"])
        if key in seen:
            continue
        seen.add(key)
        level, roles = classify(r["guards"])
        # identity established inside the handler counts, but only if the handler
        # does something about it: a session that is read and ignored is not a guard
        if level == "public" and r["session_source"] and r["enforces"]:
            level = "authed"
        if level == "authed" and r["owner_check"]:
            level = "owner"
        r["level"] = level
        r["roles"] = roles
        uniq.append(r)

    uniq.sort(key=lambda r: (r["path"], r["method"]))
    all_roles = sorted({x for r in uniq for x in r["roles"]})
    return {
        "source": root,
        "files_scanned": len(files),
        "frameworks": sorted(frameworks),
        "route_count": len(uniq),
        "roles": all_roles,
        "routes": uniq,
    }


def main(argv: list) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print("usage: routes.py <path-to-codebase> [--json]", file=sys.stderr)
        return 2
    json.dump(build(args[0]), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
