#!/usr/bin/env python3
"""
AI Security Tracker — daily digest generator.

Pulls from free public sources (no API keys required):
  1. NVD CVE feed        — new CVEs mentioning LLM / language models
  2. CISA KEV catalog    — known-exploited vulns (total + recent additions)
  3. OSV.dev             — advisories for popular AI/ML Python packages
  4. arXiv               — fresh papers on LLM security / adversarial ML
  5. Hacker News         — community chatter on AI security topics

Outputs:
  reports/YYYY-MM-DD.md   — the daily digest
  data/latest.json        — machine-readable snapshot
  README.md               — refreshes the report index between markers

Stdlib only. Safe to run locally or in GitHub Actions.
"""

import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
DATA_DIR = ROOT / "data"
README = ROOT / "README.md"

LOOKBACK_DAYS = 7          # window for CVEs / papers / news
KEV_RECENT_DAYS = 14       # "newly added to KEV" window
BACKFILL_WINDOWS = 3       # 3 x 60-day windows = ~6 months for search index
HTTP_TIMEOUT = 25

AI_PACKAGES = [
    "langchain",
    "openai",
    "anthropic",
    "transformers",
    "llama-cpp-python",
    "huggingface_hub",
]

ARXIV_QUERY = (
    '(all:"prompt injection" OR all:"jailbreak LLM"'
    ' OR all:"adversarial machine learning"'
    ' OR all:"LLM security" OR all:"large language model attack")'
)

HN_QUERIES = ["prompt injection", "AI security", "LLM vulnerability"]

HEADERS = {"User-Agent": "ai-security-tracker/1.0 (automated digest)"}


# ---------------------------------------------------------------- helpers --

def _ssl_context() -> ssl.SSLContext:
    """Prefer certifi's CA bundle (Windows venvs often lack system certs)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def http_get(url: str, accept: str = "application/json") -> bytes:
    req = urllib.request.Request(url, headers={**HEADERS, "Accept": accept})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT,
                                context=_ssl_context()) as resp:
        return resp.read()


def iso_days_ago(days: int, end: bool = False) -> str:
    """NVD-style timestamp N days ago."""
    base = datetime.now(timezone.utc).replace(tzinfo=None)
    if end:
        base += timedelta(days=1)
    stamp = (base - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    return stamp


def epoch_days_ago(days: int) -> int:
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())


def clean(text: str, limit: int = 280) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[: limit - 1].rstrip() + "\u2026" if len(text) > limit else text


def section(title: str) -> list:
    return [f"\n## {title}\n"]


def empty_note(lines: list, note: str) -> list:
    lines.append(f"*{note}*\n")
    return lines


# ----------------------------------------------------------------- sources --

def fetch_nvd() -> tuple[list, str]:
    """New CVEs whose description mentions LLM-related keywords."""
    seen, items = {}, []
    for kw in ("LLM", "language model"):
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={urllib.parse.quote(kw)}"
            f"&pubStartDate={iso_days_ago(LOOKBACK_DAYS)}"
            f"&pubEndDate={iso_days_ago(0, end=True)}"
            "&resultsPerPage=50"
        )
        try:
            data = json.loads(http_get(url))
        except Exception as exc:
            print(f"[nvd] '{kw}' failed: {exc}", file=sys.stderr)
            continue
        time.sleep(6)  # unauthenticated NVD rate limit: 5 req / 30 s
        for vuln in (data.get("vulnerabilities") or []):
            cve = (vuln.get("cve") or {})
            cid = cve.get("id", "")
            if not cid or cid in seen:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key) or []
                if arr:
                    score = arr[0].get("cvssData", {}).get("baseScore")
                    break
            sev = None
            for key in ("cvssMetricV31", "cvssMetricV30"):
                arr = metrics.get(key) or []
                if arr:
                    sev = arr[0].get("cvssData", {}).get("baseSeverity")
                    break
            seen[cid] = True
            items.append({
                "id": cid,
                "published": (cve.get("published") or "")[:10],
                "score": score,
                "severity": sev,
                "summary": clean(desc),
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            })
    items.sort(key=lambda x: (x.get("score") or 0), reverse=True)
    status = "ok" if items else "no results in window"
    return items[:12], status


def fetch_nvd_backfill(kev_ids: set) -> list:
    """Rolling ~6-month index of AI/LLM CVEs powering the search page."""
    out, seen = [], set()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    windows = []
    for w in range(BACKFILL_WINDOWS):
        end = now - timedelta(days=60 * w)
        start = end - timedelta(days=60)
        windows.append((start, end))
    for kw in ("LLM", "language model"):
        for start, end in windows:
            url = (
                "https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={urllib.parse.quote(kw)}"
                f"&pubStartDate={start.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                f"&pubEndDate={end.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                "&resultsPerPage=200"
            )
            try:
                data = json.loads(http_get(url))
            except Exception as exc:
                print(f"[backfill] '{kw}' {start:%m-%d} failed: {exc}",
                      file=sys.stderr)
                continue
            time.sleep(6)  # respect unauthenticated rate limit
            for vuln in (data.get("vulnerabilities") or []):
                cve = (vuln.get("cve") or {})
                cid = cve.get("id", "")
                if not cid or cid in seen:
                    continue
                seen.add(cid)
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                score = sev = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = cve.get("metrics", {}).get(key) or []
                    if arr:
                        cv = arr[0].get("cvssData", {})
                        score = score if score is not None else cv.get("baseScore")
                        sev = sev or cv.get("baseSeverity")
                        break
                out.append({
                    "id": cid,
                    "published": (cve.get("published") or "")[:10],
                    "score": score,
                    "severity": sev,
                    "kev": cid in kev_ids,
                    "summary": clean(desc, 320),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                })
    out.sort(key=lambda x: x["published"], reverse=True)
    (DATA_DIR / "ai_cve_index.json").write_text(
        json.dumps(out, separators=(",", ":")), encoding="utf-8")
    return out


def fetch_kev() -> dict:
    """CISA Known Exploited Vulnerabilities: totals + recent + AI matches."""
    url = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    data = json.loads(http_get(url))
    vulns = data.get("vulnerabilities", [])
    cutoff = (datetime.utcnow() - timedelta(days=KEV_RECENT_DAYS)).date()
    recent, ai_hits = [], []
    ai_kw = re.compile(
        r"\b(LLM|language model|OpenAI|ChatGPT|GPT-|machine learning|"
        r"artificial intelligence|Hugging Face|Ollama)\b", re.I)
    for v in vulns:
        added_raw = v.get("dateAdded", "")
        try:
            added = datetime.strptime(added_raw, "%Y-%m-%d").date()
        except ValueError:
            continue
        blob = " ".join(str(v.get(k, "")) for k in
                        ("vendorProject", "product", "vulnerabilityName",
                         "description"))
        if ai_kw.search(blob):
            ai_hits.append(v)
        if added >= cutoff:
            recent.append(v)
    recent.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return {
        "total": len(vulns),
        "kev_ids": sorted(v.get("cveID") for v in vulns if v.get("cveID")),
        "recent": [
            {
                "id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": clean(v.get("vulnerabilityName"), 140),
                "added": v.get("dateAdded"),
                "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
            }
            for v in recent[:8]
        ],
        "ai_matches": [
            {
                "id": v.get("cveID"),
                "name": clean(v.get("vulnerabilityName"), 140),
                "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
            }
            for v in ai_hits[:8]
        ],
        "status": "ok",
    }


def fetch_osv() -> tuple[list, str]:
    """Recent advisories for widely-used AI/ML packages via OSV.dev."""
    cutoff = epoch_days_ago(LOOKBACK_DAYS)
    out = []
    for pkg in AI_PACKAGES:
        body = json.dumps({
            "package": {"name": pkg, "ecosystem": "PyPI"},
        }).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query", data=body,
            headers={**HEADERS, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                data = json.loads(r.read())
        except Exception as exc:
            print(f"[osv] {pkg} failed: {exc}", file=sys.stderr)
            continue
        time.sleep(1)
        for adv in data.get("vulns", []):
            modified = adv.get("modified", "")
            published = adv.get("published", "") or modified
            try:
                ts = datetime.fromisoformat(
                    published.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            if ts < cutoff:
                continue
            sev = []
            for s in adv.get("severity", [])[:1]:
                sev.append(s.get("score", ""))
            aliases = ",".join(a for a in adv.get("aliases", [])[:3])
            out.append({
                "package": pkg,
                "id": adv.get("id"),
                "aliases": aliases,
                "published": published[:10],
                "summary": clean(adv.get("summary")
                                 or adv.get("details"), 160),
                "url": (adv.get("references") or [{}])[0].get("url")
                       or f"https://osv.dev/vulnerability/{adv.get('id')}",
            })
    # dedupe on advisory id
    uniq, seen = [], set()
    for item in sorted(out, key=lambda x: x["published"], reverse=True):
        if item["id"] not in seen:
            seen.add(item["id"])
            uniq.append(item)
    return uniq[:10], "ok" if uniq else "no new advisories in window"


def fetch_arxiv() -> tuple[list, str]:
    """Fresh arXiv papers on LLM/adversarial-ML security."""
    cutoff = epoch_days_ago(LOOKBACK_DAYS)
    url = (
        "http://export.arxiv.org/api/query?"
        f"search_query={urllib.parse.quote(ARXIV_QUERY)}"
        "&sortBy=submittedDate&sortOrder=descending&max_results=25"
    )
    xml_bytes = http_get(url, accept="application/atom+xml")
    ns = {"a": "http://www.w3.org/2005/Atom"}
    root = ET.fromstring(xml_bytes)
    items = []
    for entry in root.findall("a:entry", ns):
        published = entry.findtext("a:published", "", ns)
        try:
            ts = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            continue
        if ts.timestamp() < cutoff:
            continue
        link = re.sub(r"v\d+$", "", entry.findtext("a:id", "", ns))
        authors = [a.findtext("a:name", "", ns)
                   for a in entry.findall("a:author", ns)[:3]]
        items.append({
            "title": clean(entry.findtext("a:title", "", ns), 150),
            "authors": ", ".join(authors) + (" et al." if len(authors) == 3
                                             else ""),
            "published": published[:10],
            "summary": clean(entry.findtext("a:summary", "", ns), 260),
            "url": link,
        })
    return items[:10], "ok" if items else "no fresh papers matched"


def fetch_hn() -> tuple[list, str]:
    """HN stories on AI-security topics from the past week, ranked by points."""
    cutoff = epoch_days_ago(LOOKBACK_DAYS)
    best, seen, titles = [], set(), set()
    for q in HN_QUERIES:
        url = ("https://hn.algolia.com/api/v1/search?"
               f"tags=story&query={urllib.parse.quote(q)}"
               f"&numericFilters=created_at_i>{cutoff}"
               "&hitsPerPage=10")
        try:
            data = json.loads(http_get(url))
        except Exception as exc:
            print(f"[hn] '{q}' failed: {exc}", file=sys.stderr)
            continue
        time.sleep(1)
        for hit in data.get("hits", []):
            hid = hit.get("objectID")
            norm_title = re.sub(r"\W+", "", (hit.get("title") or "").lower())
            if hid in seen or not hit.get("title") or norm_title in titles:
                continue
            seen.add(hid)
            titles.add(norm_title)
            best.append({
                "title": clean(hit["title"], 150),
                "points": hit.get("points", 0),
                "comments": hit.get("num_comments", 0),
                "date": (hit.get("created_at") or "")[:10],
                "url": hit.get("url")
                       or f"https://news.ycombinator.com/item?id={hid}",
                "discussion": f"https://news.ycombinator.com/item?id={hid}",
            })
        time.sleep(1)
    best.sort(key=lambda x: x["points"], reverse=True)
    return best[:10], "ok" if best else "no stories found"


# ----------------------------------------------------------------- render --

def render_report(date_str: str, nvd, kev, osv_items, osv_status,
                  papers, paper_status, hn, hn_status) -> str:
    L = [f"# AI Security Tracker — {date_str}",
         "",
         f"> Automated daily digest of LLM/AI-security CVEs, exploited "
         f"vulnerabilities, supply-chain advisories, research and chatter.",
         f"> Lookback window: **{LOOKBACK_DAYS} days**. "
         f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
         ]

    # --- CVEs ---
    L += section(f"New AI/LLM-related CVEs ({len(nvd)} shown)")
    if nvd:
        L.append("| CVE | Severity | Published | Summary |")
        L.append("|---|---|---|---|")
        for c in nvd:
            sev = c.get("severity") or "-"
            score = f"{c['score']}" if c.get("score") is not None else "-"
            summary = c["summary"].replace("|", "\\|") or "_no description_"
            L.append(f"| [{c['id']}]({c['url']}) | {sev} ({score}) | "
                     f"{c['published']} | {summary} |")
        L.append("")
    else:
        empty_note(L, "No new CVEs matched AI/LLM keywords in this window.")

    # --- KEV ---
    L += section("CISA KEV — Known Exploited Vulns")
    if kev:
        L.append(f"Catalog total: **{kev['total']}** · "
                 f"added in last {KEV_RECENT_DAYS} days: "
                 f"**{len(kev['recent'])}**\n")
        if kev["recent"]:
            L.append("| CVE | Vendor | Product | Added |")
            L.append("|---|---|---|---|")
            for v in kev["recent"]:
                L.append(f"| [{v['id']}]({v['url']}) | {v['vendor']} | "
                         f"{v['product']} | {v['added']} |")
            L.append("")
        if kev["ai_matches"]:
            L.append("**AI-flagged entries in KEV:**\n")
            for v in kev["ai_matches"]:
                L.append(f"- [{v['id']}]({v['url']}) — {v['name']}")
            L.append("")
        else:
            empty_note(L, "No AI/LLM-specific entries currently flagged in KEV.")
    else:
        empty_note(L, "KEV feed unavailable.")

    # --- OSV ---
    L += section(f"AI Supply Chain — New Advisories ({len(osv_items)})")
    if osv_items:
        for a in osv_items:
            alias = f" ({a['aliases']})" if a["aliases"] else ""
            L.append(f"- **`{a['package']}`** [{a['id']}]({a['url']})"
                     f"{alias} — {a['summary']} _({a['published']})_")
        L.append("")
    else:
        empty_note(L, osv_status)

    # --- arXiv ---
    L += section(f"Research Radar — arXiv ({len(papers)} papers)")
    if papers:
        for p in papers:
            L.append(f"### [{p['title']}]({p['url']})")
            L.append(f"*{p['authors']} · {p['published']}*")
            L.append(f"{p['summary']}\n")
    else:
        empty_note(L, paper_status)

    # --- HN ---
    L += section(f"Community Signal — Hacker News ({len(hn)} stories)")
    if hn:
        for s in hn:
            L.append(f"- **[{s['points']:+d} pts]** "
                     f"[{s['title']}]({s['url']}) "
                     f"— [discussion]({s['discussion']}) _({s['date']})_")
        L.append("")
    else:
        empty_note(L, hn_status)

    L += ["---",
          f"*Built automatically by "
          f"[scripts/update_digest.py]"
          f"(scripts/update_digest.py) · sources: NVD, CISA KEV, OSV.dev, "
          f"arXiv, Hacker News.*"]
    return "\n".join(L)


def update_readme_index(date_str: str):
    """Keep a rolling index of reports inside README."""
    if not README.exists():
        return
    text = README.read_text(encoding="utf-8")
    start = "<!-- REPORTS:START -->"
    end = "<!-- REPORTS:END -->"
    if start in text and end in text:
        pre, rest = text.split(start, 1)
        _, post = rest.split(end, 1)
        block = (f"{start}\n"
                 f"- [`{date_str}`](reports/{date_str}.md)\n"
                 f"{end}")
        README.write_text(pre + block + post, encoding="utf-8")


# ------------------------------------------------------------------- main --

def main():
    REPORTS_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    print(f"== AI Security Tracker :: {date_str} ==")

    nvd, nvd_status = [], "failed"
    kev = None
    osv_items, osv_status = [], "failed"
    papers, paper_status = [], "failed"
    hn, hn_status = [], "failed"

    try:
        kev = fetch_kev()
        print(f"[kev]   ok ({kev['total']} total)")
    except Exception as exc:
        print(f"[kev] failed: {exc}", file=sys.stderr)
    try:
        nvd, nvd_status = fetch_nvd()
        print(f"[nvd]   {nvd_status} ({len(nvd)} items)")
    except Exception as exc:
        print(f"[nvd] failed: {exc}", file=sys.stderr)
    try:
        kev_ids = set(kev["kev_ids"]) if kev else set()
        index = fetch_nvd_backfill(kev_ids)
        print(f"[backfill] search index: {len(index)} CVEs")
    except Exception as exc:
        print(f"[backfill] failed: {exc}", file=sys.stderr)
    try:
        osv_items, osv_status = fetch_osv()
        print(f"[osv]   {osv_status} ({len(osv_items)} items)")
    except Exception as exc:
        print(f"[osv] failed: {exc}", file=sys.stderr)
    try:
        papers, paper_status = fetch_arxiv()
        print(f"[arxiv] {paper_status} ({len(papers)} papers)")
    except Exception as exc:
        print(f"[arxiv] failed: {exc}", file=sys.stderr)
    try:
        hn, hn_status = fetch_hn()
        print(f"[hn]    {hn_status} ({len(hn)} stories)")
    except Exception as exc:
        print(f"[hn] failed: {exc}", file=sys.stderr)

    report = render_report(date_str, nvd, kev, osv_items, osv_status,
                           papers, paper_status, hn, hn_status)
    out = REPORTS_DIR / f"{date_str}.md"
    out.write_text(report, encoding="utf-8")
    update_readme_index(date_str)

    snapshot = {
        "date": date_str,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "nvd_cves": len(nvd),
            "kev_total": kev["total"] if kev else None,
            "kev_recent": len(kev["recent"]) if kev else None,
            "kev_ai_matches": len(kev["ai_matches"]) if kev else None,
            "osv_advisories": len(osv_items),
            "arxiv_papers": len(papers),
            "hn_stories": len(hn),
        },
        "top_cves": [
            {"id": c["id"], "url": c["url"], "score": c.get("score"),
             "severity": c.get("severity"), "summary": c["summary"][:160]}
            for c in nvd[:5]
        ],
        "kev_ids": kev["kev_ids"] if kev else [],
        "status": {
            "nvd": nvd_status, "kev": "ok" if kev else "failed",
            "osv": osv_status, "arxiv": paper_status, "hn": hn_status,
        },
    }
    (DATA_DIR / "latest.json").write_text(
        json.dumps(snapshot, indent=2), encoding="utf-8")

    # rolling daily history for the dashboard trend line
    hist_path = DATA_DIR / "history.json"
    try:
        hist = json.loads(hist_path.read_text(encoding="utf-8")) \
            if hist_path.exists() else {}
    except (json.JSONDecodeError, OSError):
        hist = {}
    hist[date_str] = snapshot["counts"]
    if len(hist) > 400:
        for k in sorted(hist)[:-400]:
            hist.pop(k)
    hist_path.write_text(json.dumps(hist, separators=(",", ":")),
                         encoding="utf-8")

    print(f"[done] wrote {out.relative_to(ROOT)}")
    print(json.dumps(snapshot["counts"], indent=2))


if __name__ == "__main__":
    main()
