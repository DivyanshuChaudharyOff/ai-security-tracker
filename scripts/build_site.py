#!/usr/bin/env python3
"""
Build a static dashboard site from reports/*.md -> site/.

Pure stdlib. Converts our known Markdown subset (headings, tables, lists,
blockquotes, hr, inline code/bold/italic/links) into styled HTML pages.
Run locally or in GitHub Actions (deploy-pages workflow).
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
SITE_DIR = ROOT / "site"
DATA_FILE = ROOT / "data" / "latest.json"

CSS = """
:root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3;
        --dim:#8b949e; --accent:#58a6ff; --good:#3fb950; --warn:#d29922;
        --bad:#f85149; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:16px/1.65 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif; }
main { max-width:960px; margin:0 auto; padding:24px 20px 64px; }
header.site { border-bottom:1px solid var(--border); background:var(--panel); }
header.site div { max-width:960px; margin:0 auto; padding:18px 20px; }
h1 { font-size:1.6rem; margin:0; }
h1 a { color:var(--fg); text-decoration:none; }
.tagline { color:var(--dim); margin:4px 0 0; font-size:.95rem; }
h2 { border-bottom:1px solid var(--border); padding-bottom:8px;
     margin-top:2em; font-size:1.25rem; }
h3 { margin:1.4em 0 .4em; font-size:1.05rem; }
a { color:var(--accent); }
blockquote { margin:1em 0; padding:10px 16px; border-left:3px solid var(--accent);
             background:var(--panel); color:var(--dim); border-radius:0 6px 6px 0; }
table { border-collapse:collapse; width:100%; margin:1em 0; font-size:.92rem; }
th,td { border:1px solid var(--border); padding:8px 10px; text-align:left;
        vertical-align:top; }
th { background:var(--panel); }
tr:nth-child(even) td { background:#11161d; }
code { background:var(--panel); border:1px solid var(--border); padding:1px 6px;
       border-radius:4px; font-size:.88em; }
hr { border:none; border-top:1px solid var(--border); margin:2.4em 0; }
.stats { display:flex; flex-wrap:wrap; gap:12px; margin:20px 0; }
.stat { flex:1 1 140px; background:var(--panel); border:1px solid var(--border);
        border-radius:8px; padding:14px 16px; }
.stat b { display:block; font-size:1.7rem; color:var(--accent); }
.stat span { color:var(--dim); font-size:.85rem; }
.report-list { list-style:none; padding:0; }
.report-list li { background:var(--panel); border:1px solid var(--border);
                  border-radius:8px; margin:10px 0; padding:12px 16px; }
.report-list a { text-decoration:none; font-weight:600; }
footer { color:var(--dim); text-align:center; padding:24px;
         border-top:1px solid var(--border); margin-top:48px; font-size:.85rem; }
.updated { color:var(--good); font-size:.9rem; }
.back { font-size:.9rem; }
"""


def esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))


def inline(text: str) -> str:
    out = esc(text)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", out)
    return out


def md_to_html(md_text: str) -> str:
    """Convert the report Markdown subset to HTML."""
    lines = md_text.splitlines()
    html, i, n = [], 0, len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("### "):
            html.append(f"<h3>{inline(stripped[4:])}</h3>")
            i += 1
        elif stripped.startswith("## "):
            html.append(f"<h2>{inline(stripped[3:])}</h2>")
            i += 1
        elif stripped.startswith("# "):
            i += 1  # report H1 duplicates the page title; skip
        elif stripped == "---":
            html.append("<hr>")
            i += 1
        elif stripped.startswith(">"):
            block = []
            while i < n and lines[i].strip().startswith(">"):
                block.append(lines[i].strip().lstrip(">").strip())
                i += 1
            html.append("<blockquote>" +
                        "<br>".join(inline(b) for b in block) +
                        "</blockquote>")
        elif stripped.startswith("|"):
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in
                         lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            if rows:
                head = "".join(f"<th>{inline(c)}</th>" for c in rows[0])
                body = "".join(
                    "<tr>" + "".join(f"<td>{inline(c)}</td>"
                                     for c in r) + "</tr>"
                    for r in rows[1:])
                html.append(f"<table><thead><tr>{head}</tr></thead>"
                            f"<tbody>{body}</tbody></table>")
        elif stripped.startswith("- "):
            items = []
            while i < n and lines[i].strip().startswith("- "):
                items.append(f"<li>{inline(lines[i].strip()[2:])}</li>")
                i += 1
            html.append("<ul>" + "".join(items) + "</ul>")
        else:
            para = []
            while (i < n and lines[i].strip()
                   and not lines[i].strip().startswith(("#", "|", "- ", ">"))
                   and lines[i].strip() != "---"):
                para.append(lines[i].strip())
                i += 1
            html.append("<p>" + "<br>".join(inline(p) for p in para) + "</p>")
    return "\n".join(html)


def page(title: str, body_html: str, rel_root: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>{CSS}</style>
</head>
<body>
<header class="site"><div>
<h1><a href="{rel_root}index.html">🛡️ AI Security Tracker</a></h1>
<p class="tagline">Daily LLM/AI-security intel — CVEs · CISA KEV · supply chain · research · chatter</p>
</div></header>
<main>
{body_html}
</main>
<footer>Generated automatically by GitHub Actions · sources: NVD, CISA KEV, OSV.dev, arXiv, Hacker News</footer>
</body>
</html>"""


def main():
    SITE_DIR.mkdir(exist_ok=True)
    (SITE_DIR / "reports").mkdir(exist_ok=True)

    reports = sorted(REPORTS_DIR.glob("*.md"), reverse=True)

    # ---- snapshot stats ----
    stats_html = ""
    if DATA_FILE.exists():
        snap = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        c = snap.get("counts", {})
        cards = [
            (c.get("nvd_cves", 0), "AI/LLM CVEs this week"),
            (c.get("kev_total", "–"), "KEV exploited vulns"),
            (c.get("osv_advisories", 0), "supply-chain advisories"),
            (c.get("arxiv_papers", 0), "research papers"),
            (c.get("hn_stories", 0), "community stories"),
        ]
        stats_html = '<div class="stats">' + "".join(
            f'<div class="stat"><b>{v}</b><span>{k}</span></div>'
            for v, k in cards) + "</div>"
        gen = snap.get("generated_at", "")[:16].replace("T", " ")
        stats_html += f'<p class="updated">Last update: {gen} UTC</p>'

    # ---- index ----
    items = "\n".join(
        f'<li>📄 <a href="reports/{p.stem}.html">{p.stem}</a></li>'
        for p in reports)
    index_body = (f"<p>An automated daily radar of the AI threat landscape "
                  f"— built with zero-dependency Python, running on "
                  f"GitHub Actions.</p>{stats_html}<h2>Daily Reports</h2>"
                  f'<ul class="report-list">{items}</ul>')
    (SITE_DIR / "index.html").write_text(
        page("AI Security Tracker", index_body), encoding="utf-8")

    # ---- report pages ----
    for p in reports:
        body = md_to_html(p.read_text(encoding="utf-8"))
        body = ('<p class="back"><a href="../index.html">← All reports'
                "</a></p>" + body)
        (SITE_DIR / "reports" / f"{p.stem}.html").write_text(
            page(f"AI Security Tracker — {p.stem}", body,
                 rel_root="../"), encoding="utf-8")

    print(f"[site] built {len(reports)} report page(s) into site/")


if __name__ == "__main__":
    main()
