#!/usr/bin/env python3
"""Draw the access control matrix.

`--matrix` emits a Markdown table that GitHub renders in a README: routes down,
callers across, one cell each. Otherwise this writes one self-contained HTML
file holding the matrix and every finding.

The matrix is derived, not asserted. A cell says what the resolved guard chain
implies, and the chain is printed next to it.

Standard library only.
"""
from __future__ import annotations

import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from routes import AUTH_PATH  # noqa: E402  (one source of truth for the pattern)

# yes / no / owner-scoped / reachable-and-should-not-be
GLYPH_MD = {"yes": "✓", "no": "·", "own": "own", "bad": "🔴"}
GLYPH_TXT = {"yes": "yes", "no": " · ", "own": "own", "bad": "!!!"}


def callers(report: dict) -> list:
    """The columns: anonymous, a plain user, then every role that was found."""
    roles = [r for r in report.get("roles", []) if r.lower() not in {"user", "auth", "authenticated"}]
    return ["anon", "user"] + roles


def cell(route: dict, who: str) -> str:
    level = route["level"]
    if level == "public":
        # a credential endpoint is public on purpose; that is not the alarm
        if AUTH_PATH.search(route["path"]):
            return "yes"
        if who == "anon" and (route["mutating"] or route["kind"] == "server-action"):
            return "bad"
        return "yes"
    if who == "anon":
        return "no"
    if level == "authed":
        return "yes"
    if level == "owner":
        return "own"
    if level == "role":
        return "yes" if who in route["roles"] else "no"
    return "no"


def matrix(report: dict) -> list:
    """[(route, {caller: state})] in a stable order, worst first."""
    cols = callers(report)
    rows = []
    for r in report["routes"]:
        states = {c: cell(r, c) for c in cols}
        rows.append((r, states))
    rank = {"bad": 0, "yes": 1, "own": 2, "no": 3}
    rows.sort(key=lambda x: (rank[x[1]["anon"]], x[0]["path"], x[0]["method"]))
    return rows


def chain_of(route: dict) -> str:
    seen, names = set(), []
    for g in route["guards"]:
        if g["name"].lower() in seen:
            continue
        seen.add(g["name"].lower())
        names.append(g["name"])
    return " → ".join(names) if names else "—"


def to_markdown_matrix(report: dict) -> str:
    cols = callers(report)
    rows = matrix(report)
    out = [
        f"| Route | {' | '.join(cols)} | guard chain |",
        "|" + "---|" * (len(cols) + 2),
    ]
    for r, states in rows:
        cells = " | ".join(GLYPH_MD[states[c]] for c in cols)
        out.append(
            f"| `{r['method']} {r['path']}` | {cells} | "
            f"`{chain_of(r)}` |"
        )
    out += [
        "",
        f"🔴 reachable by anyone and it writes · ✓ reachable · "
        f"own scoped to the caller's own rows · · blocked",
    ]
    return "\n".join(out)


def to_text_matrix(report: dict) -> str:
    cols = callers(report)
    rows = matrix(report)
    wide = max([len(f"{r['method']} {r['path']}") for r, _ in rows] + [20])
    head = "  " + "ROUTE".ljust(wide) + "  " + "  ".join(c.center(5) for c in cols)
    out = ["", head, "  " + "─" * (len(head) - 2)]
    for r, states in rows:
        line = "  " + f"{r['method']} {r['path']}".ljust(wide) + "  "
        line += "  ".join(GLYPH_TXT[states[c]].center(5) for c in cols)
        out.append(line)
    out += ["", "  !!! reachable by anyone and it writes    yes reachable",
            "  own scoped to the caller's own rows      ·  blocked", ""]
    return "\n".join(out)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_SEV_META = [
    ("critical", "#dc2626"),
    ("high", "#ea580c"),
    ("medium", "#ca8a04"),
    ("low", "#0891b2"),
]

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root {
    --bg: #ffffff; --panel: #f6f7f9; --border: #dfe3e8;
    --fg: #14171a; --muted: #5b6672; --accent: #2563eb; --code: #f0f2f5;
    --bad: #dc2626; --badbg: #fee2e2; --ok: #15803d; --own: #a16207;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0f1216; --panel: #161b21; --border: #262d36;
      --fg: #e6e9ed; --muted: #9aa4b0; --accent: #60a5fa; --code: #10141a;
      --bad: #f87171; --badbg: #3f1d1d; --ok: #4ade80; --own: #fbbf24;
    }
  }
  :root[data-theme="dark"] {
    --bg: #0f1216; --panel: #161b21; --border: #262d36;
    --fg: #e6e9ed; --muted: #9aa4b0; --accent: #60a5fa; --code: #10141a;
    --bad: #f87171; --badbg: #3f1d1d; --ok: #4ade80; --own: #fbbf24;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  header { padding: 28px 16px 20px; border-bottom: 1px solid var(--border); }
  .wrap, main, footer { max-width: 1240px; margin: 0 auto; }
  h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: -0.01em; }
  .sub { color: var(--muted); font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .bars { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 18px; }
  .bar { display: flex; align-items: center; gap: 8px; font-size: 13px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .bar b { font-variant-numeric: tabular-nums; }
  main { padding: 0 16px 64px; }
  .grid { display: grid; grid-template-columns: minmax(0,1.25fr) minmax(0,1fr); gap: 24px; margin-top: 24px; }
  @media (max-width: 1040px) { .grid { grid-template-columns: 1fr; } }
  section > h2 {
    font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--muted); margin: 0 0 12px; font-weight: 600;
  }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 4px; overflow: auto; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { padding: 7px 10px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }
  th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); font-weight: 600; }
  td.route { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  td.c { text-align: center; font-weight: 600; }
  td.chain { font-family: ui-monospace, monospace; font-size: 11.5px; color: var(--muted); }
  tr:last-child td { border-bottom: 0; }
  .yes { color: var(--ok); }
  .no { color: var(--muted); }
  .own { color: var(--own); font-size: 11px; }
  .bad { color: #fff; background: var(--bad); border-radius: 4px; }
  tr.row-bad { background: var(--badbg); }
  .legend { display: flex; gap: 18px; flex-wrap: wrap; margin-top: 12px; font-size: 12px; color: var(--muted); }
  details { border: 1px solid var(--border); border-radius: 8px; background: var(--panel); margin-bottom: 8px; }
  details[open] { background: var(--bg); }
  summary { cursor: pointer; padding: 10px 12px; display: flex; gap: 10px; align-items: baseline; list-style: none; }
  summary::-webkit-details-marker { display: none; }
  .tag {
    font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
    padding: 2px 6px; border-radius: 4px; color: #fff; flex: none;
  }
  .loc { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
  .msg { color: var(--muted); font-size: 13px; }
  .body { padding: 0 12px 12px; }
  .why { font-size: 13.5px; margin: 2px 0 10px; }
  .where { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); margin-bottom: 8px; }
  pre {
    background: var(--code); border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 12px; overflow: auto; margin: 0;
    font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  .rule { font-family: ui-monospace, monospace; font-size: 11.5px; color: var(--muted); margin-top: 8px; }
  footer { padding: 0 16px 48px; color: var(--muted); font-size: 12.5px; }
  footer a { color: var(--accent); }
  .empty { color: var(--muted); font-size: 14px; }
</style>
</head>
<body>
<header><div class="wrap">
  <h1>__HEADING__</h1>
  <div class="sub">__SOURCE__ · __ROUTES__ routes · __FRAMEWORKS__</div>
  <div class="bars">__BARS__</div>
</div></header>
<main>
  <div class="grid">
    <section>
      <h2>Who can reach what</h2>
      <div class="card">__MATRIX__</div>
      <div class="legend">
        <span><span class="bad" style="padding:1px 5px">&nbsp;!&nbsp;</span> reachable by anyone, and it writes</span>
        <span><span class="yes">✓</span> reachable</span>
        <span><span class="own">own</span> scoped to the caller's own rows</span>
        <span><span class="no">·</span> blocked</span>
      </div>
    </section>
    <section>
      <h2>Findings</h2>
      __FINDINGS__
    </section>
  </div>
</main>
<footer>
  Generated by <a href="https://github.com/NHTanvir/gatescope">gatescope</a>.
  Each cell is what the resolved guard chain implies. A chain this tool could not
  resolve is reported as "no guard found", which is not the same as "no guard".
</footer>
</body>
</html>
"""


def html_matrix(report: dict) -> str:
    cols = callers(report)
    rows = matrix(report)
    out = ["<table><thead><tr><th>Route</th>"]
    out += [f"<th style='text-align:center'>{html.escape(c)}</th>" for c in cols]
    out.append("<th>guard chain</th></tr></thead><tbody>")
    for r, states in rows:
        bad = states["anon"] == "bad"
        out.append(f"<tr class='{'row-bad' if bad else ''}'>")
        out.append(
            f"<td class='route'>{html.escape(r['method'])} "
            f"{html.escape(r['path'])}</td>"
        )
        for c in cols:
            s = states[c]
            glyph = {"yes": "✓", "no": "·", "own": "own", "bad": "!"}[s]
            out.append(f"<td class='c {s}'>{glyph}</td>")
        out.append(f"<td class='chain'>{html.escape(chain_of(r))}</td></tr>")
    out.append("</tbody></table>")
    return "".join(out)


def to_html(report: dict, title: str = None) -> str:
    counts = report.get("counts", {})
    total = sum(counts.values())
    bars = []
    for sev, color in _SEV_META:
        n = counts.get(sev, 0)
        if n:
            bars.append(
                f'<span class="bar"><span class="dot" style="background:{color}">'
                f"</span><b>{n}</b> {sev}</span>"
            )
    if not bars:
        bars.append('<span class="bar">No findings</span>')

    blocks = []
    if total:
        colors = dict(_SEV_META)
        for sev, _ in _SEV_META:
            for f in report["findings"]:
                if f["severity"] != sev:
                    continue
                wh = "".join(
                    f"<div>{html.escape(str(e['file']))}:{e['line']}  "
                    f"{html.escape(str(e.get('snippet') or ''))}</div>"
                    for e in f["evidence"]
                )
                blocks.append(
                    "<details>"
                    f'<summary><span class="tag" style="background:{colors[sev]}">{sev}</span>'
                    f'<span class="loc">{html.escape(f["where"])}</span>'
                    f'<span class="msg">{html.escape(f["message"])}</span></summary>'
                    f'<div class="body"><div class="why">{html.escape(f["why"])}</div>'
                    f'<div class="where">{wh}</div>'
                    + (f"<pre>{html.escape(f['fix'])}</pre>" if f.get("fix") else "")
                    + f'<div class="rule">{html.escape(f["rule"])}</div></div>'
                    "</details>"
                )
    else:
        blocks.append('<p class="empty">No findings. Every route resolves to a guard.</p>')

    out = HTML_TEMPLATE
    for needle, value in (
        ("__TITLE__", html.escape(f"Access review — {os.path.basename(str(report.get('source')))}")),
        ("__HEADING__", html.escape(title or "Access review")),
        ("__SOURCE__", html.escape(str(report.get("source")))),
        ("__ROUTES__", str(report.get("route_count", 0))),
        ("__FRAMEWORKS__", html.escape(", ".join(report.get("frameworks", [])) or "unknown")),
        ("__BARS__", "".join(bars)),
        ("__MATRIX__", html_matrix(report)),
        ("__FINDINGS__", "".join(blocks)),
    ):
        out = out.replace(needle, value)
    return out


def main(argv: list) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {
        a.split("=")[0]: (a.split("=", 1)[1] if "=" in a else True)
        for a in argv[1:] if a.startswith("--")
    }
    if not args:
        print(
            "usage: render.py <path-to-codebase|routes.json> "
            "[--matrix|--text] [--out=FILE]",
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

    import audit as audit_mod
    report = doc if "findings" in doc else audit_mod.audit(doc)

    if "--matrix" in flags:
        text = to_markdown_matrix(report)
    elif "--text" in flags:
        text = to_text_matrix(report)
    else:
        text = to_html(report)

    dest = flags.get("--out")
    if isinstance(dest, str):
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {dest}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
