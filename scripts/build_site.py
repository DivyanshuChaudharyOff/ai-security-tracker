#!/usr/bin/env python3
"""
Build the static dashboard site from reports/*.md + data/*.json -> site/.

Pure stdlib. Produces:
  site/index.html          — dashboard: stats, trend, top threats, archive
  site/search.html         — vulnerability search (local index + live NVD)
  site/reports/*.html      — rendered daily reports
  site/search-index.json   — ~6-month AI/LLM CVE index for client-side search
  site/kev.json            — CISA KEV CVE id list for exploit flags
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
SITE_DIR = ROOT / "site"
DATA_DIR = ROOT / "data"

CSS = """
:root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3;
        --dim:#8b949e; --accent:#58a6ff; --good:#3fb950; --warn:#d29922;
        --bad:#f85149; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:16px/1.65 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif; }
main { max-width:960px; margin:0 auto; padding:20px 20px 64px; }
header.site { border-bottom:1px solid var(--border); background:var(--panel); }
header.site div { max-width:960px; margin:0 auto; padding:16px 20px 0; }
h1 { font-size:1.5rem; margin:0; }
h1 a { color:var(--fg); text-decoration:none; }
.tagline { color:var(--dim); margin:2px 0 10px; font-size:.95rem; }
nav.top { display:flex; gap:20px; font-size:.95rem; }
nav.top a { text-decoration:none; color:var(--dim); padding:6px 2px;
            border-bottom:2px solid transparent; }
nav.top a.active { color:var(--accent); border-color:var(--accent); }
h2 { border-bottom:1px solid var(--border); padding-bottom:8px;
     margin-top:1.8em; font-size:1.2rem; }
h3 { margin:1.3em 0 .4em; font-size:1.02rem; }
a { color:var(--accent); }
blockquote { margin:1em 0; padding:10px 16px; border-left:3px solid var(--accent);
             background:var(--panel); color:var(--dim); border-radius:0 6px 6px 0; }
table { border-collapse:collapse; width:100%; margin:1em 0; font-size:.9rem; }
th,td { border:1px solid var(--border); padding:8px 10px; text-align:left;
        vertical-align:top; }
th { background:var(--panel); }
tr:nth-child(even) td { background:#11161d; }
code { background:var(--panel); border:1px solid var(--border); padding:1px 6px;
       border-radius:4px; font-size:.88em; }
hr { border:none; border-top:1px solid var(--border); margin:2.2em 0; }
.stats { display:flex; flex-wrap:wrap; gap:12px; margin:18px 0; }
.stat { flex:1 1 140px; background:var(--panel); border:1px solid var(--border);
        border-radius:8px; padding:14px 16px; }
.stat b { display:block; font-size:1.7rem; color:var(--accent); }
.stat span { color:var(--dim); font-size:.85rem; }
.updated { color:var(--good); font-size:.9rem; }
.report-list { list-style:none; padding:0; }
.report-list li { background:var(--panel); border:1px solid var(--border);
                  border-radius:8px; margin:10px 0; padding:12px 16px; }
.report-list a { text-decoration:none; font-weight:600; }
footer { color:var(--dim); text-align:center; padding:24px;
         border-top:1px solid var(--border); margin-top:48px; font-size:.85rem; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px;
         font-size:.74rem; font-weight:700; letter-spacing:.03em; }
.sev-CRITICAL { background:#f8514922; color:#f85149; border:1px solid #f8514966; }
.sev-HIGH      { background:#db6d2822; color:#db6d28; border:1px solid #db6d2866; }
.sev-MEDIUM    { background:#d2992222; color:#d29922; border:1px solid #d2992266; }
.sev-LOW       { background:#3fb95022; color:#3fb950; border:1px solid #3fb95066; }
.sev-UNKNOWN   { background:#8b949e22; color:#8b949e; border:1px solid #8b949e66; }
.kevflag { background:var(--bad); color:#fff; padding:1px 8px; border-radius:4px;
           font-size:.72rem; font-weight:800; margin-left:8px; }
.spark { width:100%; height:70px; margin:10px 0 2px; }
.spark-cap { color:var(--dim); font-size:.8rem; }
.searchbar { display:flex; gap:10px; flex-wrap:wrap; margin:14px 0 6px;
             align-items:center; }
.searchbar input[type=text] { flex:1 1 340px; background:var(--panel);
    border:1px solid var(--border); color:var(--fg); padding:11px 14px;
    border-radius:8px; font-size:1rem; }
.searchbar input[type=text]:focus { outline:1px solid var(--accent); }
button, .btn { background:var(--accent); color:#0d1117; border:none;
    padding:10px 18px; border-radius:8px; font-weight:700; cursor:pointer;
    text-decoration:none; display:inline-block; }
.opt { color:var(--dim); font-size:.9rem; display:flex; gap:6px;
       align-items:center; }
.opt select { background:var(--panel); color:var(--fg);
              border:1px solid var(--border); border-radius:6px; padding:4px 8px; }
.result { background:var(--panel); border:1px solid var(--border);
          border-radius:8px; padding:12px 16px; margin:10px 0; }
.result .meta { color:var(--dim); font-size:.85rem; margin:4px 0; }
.result .desc { font-size:.93rem; }
.count { color:var(--good); font-size:.92rem; }
.err { color:var(--bad); font-size:.92rem; }
.hint { color:var(--dim); font-size:.85rem; }
mark { background:#d2992288; color:inherit; border-radius:2px; padding:0 2px; }
"""


# ------------------------------------------------------------- md -> html --

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
            i += 1
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


# ----------------------------------------------------------------- pieces --

def sev_badge(sev, score=None) -> str:
    sev = (sev or "UNKNOWN").upper()
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sev = "UNKNOWN"
    label = f"{sev}" + (f" {score}" if score is not None else "")
    return f'<span class="badge sev-{sev}">{label}</span>'


def sparkline(history: dict, key: str = "nvd_cves") -> str:
    pts = sorted(history.items())[-90:]
    vals = [c.get(key) or 0 for _, c in pts]
    if not vals:
        return ""
    w, h = 900, 70
    mx = max(vals) or 1
    step = w / max(1, len(vals) - 1)
    coords = " ".join(
        f"{i * step:.1f},{h - (v / mx) * (h - 8) - 4:.1f}"
        for i, v in enumerate(vals))
    first_date = pts[0][0] if pts else ""
    last_date = pts[-1][0] if pts else ""
    return (f'<svg class="spark" viewBox="0 0 {w} {h}" preserveAspectRatio="none">'
            f'<polyline fill="none" stroke="#58a6ff" stroke-width="2.5" '
            f'points="{coords}"/></svg>'
            f'<div class="spark-cap">AI/LLM CVEs per day, {first_date} → '
            f'{last_date} (peak {mx}/day)</div>')


def page(title: str, body_html: str, rel_root: str = "",
         active: str = "", latest: str = "") -> str:
    latest_link = (f'{rel_root}reports/{latest}.html' if latest
                   else f'{rel_root}index.html')

    def nav_cls(key):
        return ' class="active"' if active == key else ""

    nav = (f'<nav class="top">'
           f'<a href="{rel_root}index.html"{nav_cls("home")}>Dashboard</a>'
           f'<a href="{rel_root}search.html"{nav_cls("search")}>🔎 Search CVEs</a>'
           f'<a href="{latest_link}"{nav_cls("latest")}>Latest Report</a>'
           f'</nav>')
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
{nav}
</div></header>
<main>
{body_html}
</main>
<footer>Generated automatically by GitHub Actions · sources: NVD, CISA KEV, OSV.dev, arXiv, Hacker News</footer>
</body>
</html>"""


# ------------------------------------------------------------------ index --

def build_index(snapshot: dict, history: dict, reports: list) -> str:
    c = snapshot.get("counts", {})
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
    gen = snapshot.get("generated_at", "")[:16].replace("T", " ")
    stats_html += f'<p class="updated">Last update: {gen} UTC</p>'

    parts = [
        '<p>An automated daily radar of the AI threat landscape — built '
        'with zero-dependency Python, running on GitHub Actions.</p>',
        '<p><a class="btn" href="search.html">🔎 Search vulnerabilities by '
        'symptom</a></p>',
        stats_html,
    ]
    if history:
        parts.append("<h2>Trend</h2>" + sparkline(history))

    top = snapshot.get("top_cves") or []
    if top:
        rows = []
        for t in top:
            summ = esc(t.get("summary") or "") or "<i>no description</i>"
            rows.append(
                f'<tr><td>{sev_badge(t.get("severity"), t.get("score"))}</td>'
                f'<td><a href="{t["url"]}">{esc(t["id"])}</a>'
                f'{"<span class=kevflag>KEV</span>" if t.get("id") in set(snapshot.get("kev_ids", [])) else ""}</td>'
                f'<td>{esc(t.get("published", ""))}</td>'
                f'<td>{summ}</td></tr>')
        parts.append("<h2>Top AI/LLM Threats This Week</h2>"
                     '<table><thead><tr><th>Severity</th><th>CVE</th>'
                     "<th>Published</th><th>Summary</th></tr></thead>"
                     "<tbody>" + "".join(rows) + "</tbody></table>")

    items = "\n".join(
        f'<li>📄 <a href="reports/{p.stem}.html">{p.stem}</a></li>'
        for p in reports)
    parts.append("<h2>Daily Reports</h2>"
                 f'<ul class="report-list">{items}</ul>')
    return "\n".join(parts)


# ----------------------------------------------------------------- search --

SEARCH_BODY = """
<p>Search AI/LLM CVEs by <b>symptom, product, or keyword</b> — no exact CVE
id needed. Local index covers ~6 months of AI/LLM-related CVEs (with CISA KEV
exploit flags); Live mode queries the <b>entire NVD database</b> in real time.</p>

<div class="searchbar">
  <input type="text" id="q" placeholder='e.g. "prompt injection", "header spoofing", "path traversal", "langchain", "RCE"' autofocus>
  <button onclick="run()">Search</button>
</div>
<div class="searchbar">
  <span class="opt"><input type="checkbox" id="live"> <label for="live">Live NVD (whole database)</label></span>
  <span class="opt">Min severity:
    <select id="minsev">
      <option value="ANY">Any</option>
      <option value="LOW">LOW+</option>
      <option value="MEDIUM">MEDIUM+</option>
      <option value="HIGH">HIGH+</option>
      <option value="CRITICAL">CRITICAL only</option>
    </select></span>
  <span class="opt"><input type="checkbox" id="kevonly"> <label for="kevonly">KEV (exploited in the wild) only</label></span>
</div>
<p class="hint" id="idxinfo"></p>
<div id="results"></div>

<script>
let IDX = [], KEV = new Set();
const $ = id => document.getElementById(id);
const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

const esc = s => String(s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function highlight(escaped, tokens) {
  let out = escaped;
  for (const t of tokens) {
    const re = new RegExp('(' + t.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + ')', 'gi');
    out = out.replace(re, '<mark>$1</mark>');
  }
  return out;
}

function badge(it) {
  let sev = (it.severity || 'UNKNOWN').toUpperCase();
  if (!SEV_ORDER[sev]) sev = 'UNKNOWN';
  const score = it.score != null ? ' ' + it.score : '';
  let html = '<span class="badge sev-' + sev + '">' + sev + score + '</span>';
  if (it.kev) html += '<span class="kevflag">KEV · EXPLOITED</span>';
  return html;
}

function row(it, tokens) {
  const summ = highlight(esc(it.summary || 'no description'), tokens);
  return '<div class="result">'
    + '<a href="' + esc(it.url) + '"><b>' + esc(it.id) + '</b></a> '
    + badge(it)
    + '<div class="meta">published ' + esc(it.published || '?') + '</div>'
    + '<div class="desc">' + summ + '</div>'
    + '</div>';
}

function passes(it, minsev, kevonly) {
  if (minsev !== 'ANY' && (SEV_ORDER[(it.severity || '').toUpperCase()] || 0)
      < SEV_ORDER[minsev]) return false;
  if (kevonly && !it.kev) return false;
  return true;
}

function localSearch(q) {
  const tokens = q.toLowerCase().split(/\\W+/).filter(t => t.length > 1);
  if (!tokens.length) return { list: [], tokens: [] };
  const minsev = $('minsev').value, kevonly = $('kevonly').checked;
  const scored = [];
  for (const it of IDX) {
    if (!passes(it, minsev, kevonly)) continue;
    const hay = (it.id + ' ' + (it.summary || '')).toLowerCase();
    let sc = 0, hits = 0;
    for (const t of tokens) {
      if (hay.includes(t)) {
        hits++;
        sc += it.id.toLowerCase().includes(t) ? 10 : 1;
      }
    }
    if (hits === tokens.length || hits >= Math.max(1, tokens.length - 1))
      scored.push({ it, sc });
  }
  scored.sort((a, b) => b.sc - a.sc || (b.it.score || 0) - (a.it.score || 0));
  return { list: scored.slice(0, 30).map(r => r.it), tokens };
}

async function liveSearch(q) {
  const minsev = $('minsev').value, kevonly = $('kevonly').checked;
  const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch='
    + encodeURIComponent(q) + '&resultsPerPage=30';
  const resp = await fetch(url);
  if (!resp.ok) throw new Error('NVD returned HTTP ' + resp.status +
    ' (rate limit is 5 requests / 30s per IP — wait a moment and retry)');
  const data = await resp.json();
  const out = [];
  for (const v of (data.vulnerabilities || [])) {
    const c = v.cve || {};
    const m = c.metrics || {};
    let score = null, sev = null;
    for (const k of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
      if (m[k] && m[k][0]) {
        score = m[k][0].cvssData.baseScore;
        sev = m[k][0].cvssData.baseSeverity;
        break;
      }
    }
    let desc = '';
    for (const d of (c.descriptions || [])) {
      if (d.lang === 'en') { desc = d.value; break; }
    }
    const it = {
      id: c.id,
      published: (c.published || '').slice(0, 10),
      score, severity: sev,
      kev: KEV.has(c.id),
      summary: desc.slice(0, 320),
      url: 'https://nvd.nist.gov/vuln/detail/' + c.id,
    };
    if (passes(it, minsev, kevonly)) out.push(it);
  }
  out.sort((a, b) => (b.score || 0) - (a.score || 0));
  return { list: out, tokens: q.toLowerCase().split(/\\W+/).filter(t => t.length > 1) };
}

async function run() {
  const q = $('q').value.trim();
  const box = $('results');
  if (!q) { box.innerHTML = '<p class="hint">Type a symptom, product, or keyword.</p>'; return; }
  box.innerHTML = '<p class="hint">Searching…</p>';
  try {
    const { list, tokens } = $('live').checked ? await liveSearch(q) : localSearch(q);
    if (!list.length) {
      box.innerHTML = '<p class="hint">No matches for “' + esc(q) + '”. '
        + 'Try broader terms, or enable Live NVD mode.</p>';
      return;
    }
    box.innerHTML = '<p class="count">' + list.length + ' result(s)</p>'
      + list.map(it => row(it, tokens)).join('');
  } catch (e) {
    box.innerHTML = '<p class="err">' + esc(e.message) + '</p>';
  }
}
$('q').addEventListener('keydown', e => { if (e.key === 'Enter') run(); });

(async () => {
  try {
    const [a, b] = await Promise.all([
      fetch('search-index.json').then(r => r.json()),
      fetch('kev.json').then(r => r.json()),
    ]);
    IDX = a; KEV = new Set(b);
    const kevCount = IDX.filter(x => x.kev).length;
    $('idxinfo').textContent = 'Local index: ' + IDX.length
      + ' AI/LLM CVEs (' + kevCount + ' flagged exploited in the wild).';
  } catch (e) {
    $('idxinfo').textContent = 'Local index failed to load — use Live NVD mode.';
  }
})();
</script>
"""


def main():
    SITE_DIR.mkdir(exist_ok=True)
    (SITE_DIR / "reports").mkdir(exist_ok=True)

    latest_path = DATA_DIR / "latest.json"
    snapshot = (json.loads(latest_path.read_text(encoding="utf-8"))
                if latest_path.exists() else {})
    hist_path = DATA_DIR / "history.json"
    history = (json.loads(hist_path.read_text(encoding="utf-8"))
               if hist_path.exists() else {})

    # ship search data to the site
    idx_path = DATA_DIR / "ai_cve_index.json"
    if idx_path.exists():
        (SITE_DIR / "search-index.json").write_text(
            idx_path.read_text(encoding="utf-8"), encoding="utf-8")
    (SITE_DIR / "kev.json").write_text(
        json.dumps(snapshot.get("kev_ids", []), separators=(",", ":")),
        encoding="utf-8")

    reports = sorted(REPORTS_DIR.glob("*.md"), reverse=True)
    latest = reports[0].stem if reports else ""

    index_body = build_index(snapshot, history, reports)
    (SITE_DIR / "index.html").write_text(
        page("AI Security Tracker", index_body, active="home", latest=latest),
        encoding="utf-8")

    (SITE_DIR / "search.html").write_text(
        page("Search CVEs — AI Security Tracker", SEARCH_BODY,
             active="search", latest=latest),
        encoding="utf-8")

    for p in reports:
        body = md_to_html(p.read_text(encoding="utf-8"))
        body = ('<p class="back"><a href="../index.html">← All reports'
                "</a></p>" + body)
        (SITE_DIR / "reports" / f"{p.stem}.html").write_text(
            page(f"AI Security Tracker — {p.stem}", body,
                 rel_root="../", latest=latest),
            encoding="utf-8")

    print(f"[site] built index + search + {len(reports)} report page(s)")


if __name__ == "__main__":
    main()
