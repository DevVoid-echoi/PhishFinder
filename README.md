# PhishFinder

[![tests](https://github.com/DevVoid-echoi/PhishFinder/actions/workflows/tests.yml/badge.svg)](https://github.com/DevVoid-echoi/PhishFinder/actions/workflows/tests.yml)

A phishing link detector aimed at scams that target Vietnamese users: fake bank, e-wallet and e-commerce domains such as `vietcombank-xacthuc.com`, `sh0pee.vn` or `mоmо.vn` (with a Cyrillic `о`).

Every verdict comes with the rules that fired and why, and every change to the rules is measured against a labelled dataset before it is kept. The core runs on Python's standard library plus `tldextract`; a Chrome extension that runs the same rules in the browser is planned (see [Roadmap](#roadmap)).

> **Status:** core detection, measurement and reputation checks are done (October 2026). The production API is done; SOC alerts, page analysis, the browser extension and the public release are in progress.

## Example

```bash
python -m app.scorer "http://vietcombank-xacthuc.com/dang-nhap"
```

```json
{
    "url": "http://vietcombank-xacthuc.com/dang-nhap",
    "domain": "vietcombank-xacthuc.com",
    "score": 70,
    "level": "dangerous",
    "reasons": [
        {"rule": "check_lookalike", "points": 40, "reason": "Domain contains 'vietcombank' but is not an official vietcombank domain"},
        {"rule": "check_keywords", "points": 20, "reason": "Contains suspicious keywords: xacthuc, dang-nhap"},
        {"rule": "check_no_https", "points": 10, "reason": "Connection is not encrypted (HTTP instead of HTTPS)"}
    ]
}
```

Levels: `dangerous` (60 and above), `suspicious` (30 to 59), `likely_safe` (below 30). There is deliberately no `safe` level: a rule-based tool can only say it found no warning signs.

## Quick start

Requires Python 3.12 or later.

```bash
git clone https://github.com/DevVoid-echoi/PhishFinder.git
cd PhishFinder
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest                                    # 194 tests, no network access
```

Check a URL, a domain's registration age, or its TLS certificate:

```bash
python -m app.scorer "https://mоmо.vn"
python -m app.online example.com          # RDAP lookup (network)
python -m app.reputation example.com      # TLS handshake (network)
```

## How it works

```
URL ─► parser ─► rules (in the browser) ─► score + level + reasons
         │            │
         │            ├─ blocklist (always wins)
         │            └─ allowlist (Tranco top 10,000)
         │
         └─► server checks, hostname only: domain age (RDAP), TLS certificate
```

**Parsing.** URLs are split with the Public Suffix List (`tldextract`, bundled snapshot, no runtime download) so that `login.vietcombank.com.vn.evil.xyz` resolves to `evil.xyz`, and user sites on shared hosting (`evil.github.io`) are not merged into the platform domain. Unicode hostnames are converted to punycode, as browsers do.

**Rules.** Each rule returns `(points, reason)` or nothing.

| Rule | Points | Signal |
| --- | --- | --- |
| `check_lookalike` | 40 / 35 | Brand name or abbreviation in a non-official domain, typosquatting (`vietcornbank`), homoglyphs (`sh0pee`), Cyrillic look-alikes (`mоmо`), brand in a subdomain |
| `check_ip_host` | 30 | Raw IP address instead of a domain |
| `check_at_symbol` | 30 | `@` before the host hides the real destination |
| `check_punycode` | 25 | Internationalized (`xn--`) hostname |
| `check_keywords` | 10 each, max 25 | `xacthuc`, `dang-nhap`, `nhanqua`, `otp`... |
| `check_many_subdomains` | 15 | Three or more subdomain levels |
| `check_suspicious_tld` | 15 | Frequently abused TLDs (`.xyz`, `.top`, `.icu`...) |
| `check_no_https` | 10 | Plain HTTP |
| `check_long_url` | 10 | URL longer than 100 characters |
| `check_shortener` | 10 | Known URL shortener |

Brands, official domains and abbreviations live in [`data/brands.json`](data/brands.json) (18 Vietnamese and regional brands). Short brands (5 characters or fewer) only match as a separate token, so `zalo-nhanqua.com` is caught while `zalora.com` is not.

**Lists.**
- *Blocklist:* 16,843 Vietnamese-targeted domains (vn-badsite-filter, CC0/MIT) and OpenPhish URLs. A hit always scores 100.
- *Allowlist:* the Tranco top 10,000 skip lookalike checks on their own name only. Subdomain checks still run, because 752 of the collected phishing pages sit on popular hosting platforms (`eu.cc`, `mybluehost.me`...); skipping them would let `vietcombank-xacthuc.wordpress.com` through. This cut false alarms on the top 10,000 sites from 35 to 10.

**Server checks** (hostname only, never the full URL). The extension strips each URL to its hostname before sending; `GET /v1/reputation?host=` rejects anything else, so paths and query strings, which can carry reset tokens or emails, never leave the user's machine:
- *Domain age* through RDAP, the JSON successor of WHOIS: under 30 days scores 35. In a first live check, 6 of 8 freshly reported phishing domains were under 30 days old.
- *TLS certificate:* invalid certificates score 30, certificates issued in the last 7 days score 20. The connection is protected against SSRF: every resolved address must be public (`is_global`), and the client connects to the checked IP with the hostname as SNI, so DNS rebinding cannot redirect it to an internal address.
- *Short-link expansion:* `GET /v1/expand?url=` follows a known shortener (`bit.ly`, `tinyurl.com`...) to its destination and returns the whole redirect chain. It is the only endpoint that takes a full URL, and it refuses any other link. Every hop is checked again before connecting: http/https only, ports 80 and 443 only, public addresses only, pinned to the checked IP; at most 5 hops in 15 seconds.

## Measurement

Phishing links are collected daily from phishing.army and OpenPhish; an entry's first-seen date is recorded the first time it appears, so the test set is phishing the rules have never seen. Legitimate pages are Tranco ranks 10,001 to 90,000 (never the allowlisted top 10,000, which would flatter the numbers) plus hand-checked Vietnamese sites.

- Benign pages are split 50/25/25 into train, validation and test with a fixed seed. Thresholds are tuned on validation; the test split is only measured.
- The blocklist is excluded from measurement, since it trivially "detects" its own entries.

Results for the rule layer (Tranco list `GQ32K`, 2026-10-25):

| Scoring | Benign test | Fresh phishing (Vietnamese) | False alarms, red | False alarms, yellow+ | Detected, yellow+ | Vietnamese detected |
| --- | --- | --- | --- | --- | --- | --- |
| Hand-written points | 19,997 | 7,326 (7) | 0.000% | 0.150% | 1.4% | 5 / 7 |
| Learned weights | 19,997 | 7,326 (7) | 0.005% | 0.005% | 0.7% | 0 / 7 |

Targets before release: red false alarms at or below 0.05% and yellow at or below 0.5%. Both scorings meet them.

**Reading these numbers.** Overall detection is low on purpose and for a clear reason: 77.8% of the fresh phishing in these international feeds are random domains (`6a2035.top`) that fire no informative rule, exactly like 98% of legitimate pages. No weighting of URL rules can separate inputs that look identical; that is the job of the server checks and, later, page analysis. The rules target Vietnamese brand impersonation, which these feeds barely contain (7 fresh samples so far).

**Learned weights.** `python -m scripts.evaluate --calibrate` fits a logistic regression on the fired rules: one interpretable weight per rule, class balancing, L2 chosen on validation, red and yellow thresholds picked to meet the false-alarm targets. About 207,000 URLs collapse into about 33 distinct rule sets, so training takes a fraction of a second. On current data the learned model detects less than the hand-written points, so it is not used; it will be retrained once server signals and more Vietnamese samples are in the data.

## Known limitations

- **Few Vietnamese samples.** The main Vietnamese feed (vn-badsite-filter, from ChongLuaDao) has been frozen since May 2025, and international feeds contain almost no Vietnamese-targeted pages.
- **Short-brand trade-off.** Matching short brands as whole tokens removes false alarms such as `zalora.com`, but misses `momoshop.com`. One-letter typos on short names (`shoppe`, `vpbamk`) fall under the similarity threshold.
- **Popular does not mean safe.** The Tranco allowlist measures traffic, not trust. It only disables lookalike checks on the domain itself, and the blocklist always wins.
- **Legitimate internationalized domains** (Thai, Russian...) can be flagged as suspicious by the punycode rule.
- **Server-side checks can be cloaked:** an attacker can answer the server differently from victims. No single server signal is trusted alone, and no signal ever lowers a score.
- **Hacked old sites** have a normal domain age and certificate, so only text rules and lists can catch them.
- **No `.vn` domain age:** there is no RDAP service for the TLD.
- **No rate limiting in the app yet:** it will sit behind an API gateway in production; the cache is in memory and reports are only logged.

The full list, with measurements, is kept in [`note.md`](note.md).

## Project layout

```
app/
  parser.py        URL splitting (Public Suffix List, punycode)
  heuristics.py    URL rules
  lookalike.py     brand impersonation, homoglyphs, Unicode look-alikes
  lists.py         blocklists, allowlist, list loaders
  scorer.py        score, level and reasons; optional learned weights
  online.py        domain age via RDAP
  reputation.py    TLS certificate check with SSRF protection
  page_fetch.py    redirect following with SSRF checks on every hop
  evaluation.py    dataset loading, splits, metrics
  calibrate.py     logistic regression and threshold selection
  api_core.py      hostname validation, thread-safe cache, reputation lookup
  main.py          production HTTP API (FastAPI): /v1/reputation, /v1/expand, /v1/report, /v1/health
scripts/           download_feeds, collect_fresh, update_tranco, evaluate
data/              brands.json, Tranco list ID, hand-checked Vietnamese sites
tests/             194 pytest tests; network access is blocked in every test
```

Downloaded feeds, the collected phishing set and the Tranco-derived files are not committed (personal-use terms and size). The scripts above recreate everything except the first-seen dates, which only accumulate over time.

## Roadmap

1. **SOC alerts:** MITRE ATT&CK-tagged alerts in JSON Lines for SIEM ingestion.
2. **Page analysis:** rules and AI on page content, opt-in only.
3. **Chrome extension:** the same rules in JavaScript, verified against Python test vectors; private beta, then Chrome Web Store.
4. **Later:** email header analysis (SPF, DKIM, DMARC) for analysts, Certificate Transparency monitoring.

## License

[MIT](LICENSE)
