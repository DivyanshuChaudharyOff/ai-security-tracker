# 🤖 AI Security Tracker

> Automated daily digest of LLM/AI-security CVEs, exploited vulnerabilities,
> supply-chain advisories, research papers, and community chatter.

Built and maintained as part of a cybersecurity engineering practice focused on
AI detection & response (AIDR) — tracking the offensive/defensive AI threat
landscape one day at a time.

## What you get every day

| Section | Source | What it captures |
|---|---|---|
| New AI/LLM CVEs | [NVD](https://nvd.nist.gov/) | CVEs mentioning LLM/language-model keywords, ranked by CVSS |
| Known Exploited Vulns | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Catalog totals, recent additions, AI-flagged entries |
| Supply Chain Advisories | [OSV.dev](https://osv.dev/) | New advisories for langchain, openai, anthropic, transformers, llama-cpp-python, huggingface_hub |
| Research Radar | [arXiv](https://arxiv.org/) | Fresh papers on prompt injection, jailbreaks, adversarial ML |
| Community Signal | [Hacker News](https://news.ycombinator.com/) | Top AI-security stories of the week by points |

## Automation

A GitHub Action (`daily-digest`) runs at **03:30 UTC daily** (~9:00 AM IST):

1. Runs `scripts/update_digest.py` (pure stdlib Python — no dependencies)
2. Writes `reports/YYYY-MM-DD.md`
3. Auto-commits the new report

No API keys required — all sources are free public feeds.

<!-- REPORTS:START -->
- [`2026-09-03`](reports/2026-09-03.md)
<!-- REPORTS:END -->

## Running locally

```bash
python scripts/update_digest.py
```

Output lands in `reports/`, snapshot in `data/latest.json`.

## Why this exists

AI systems are becoming attack surface faster than traditional tooling can
track them: prompt injection CVEs, jailbreak research shipping weekly, and
ML supply-chain packages under active exploit. This repo is a lightweight
daily radar for that landscape — useful for SOC teams building AI detection
and response capabilities.

## License

MIT
