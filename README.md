# PhishFinder

[![tests](https://github.com/DevVoid-echoi/PhishFinder/actions/workflows/tests.yml/badge.svg)](https://github.com/DevVoid-echoi/PhishFinder/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/DevVoid-echoi/PhishFinder/graph/badge.svg)](https://codecov.io/gh/DevVoid-echoi/PhishFinder)
[![License: MIT](https://img.shields.io/github/license/DevVoid-echoi/PhishFinder)](LICENSE)

A phishing link detector aimed at scams that target Vietnamese users: fake bank, e-wallet and e-commerce domains such as `vietcombank-xacthuc.com`, `sh0pee.vn` or `mоmо.vn` (with a Cyrillic `о`).

Every verdict comes with the rules that fired and why, and every change to the rules is measured against a labelled dataset before it is kept. The core runs on Python's standard library plus `tldextract`; a Chrome extension that runs the same rules in the browser is planned (see [Roadmap](#roadmap)).

> **Status (November 2026):** URL rules, measurement, reputation checks, SOC alerts and the production API are done. Page analysis runs on the server on what the extension reads, and is measured every day on hand-labelled Vietnamese phishing. The browser extension and the public release are in progress.

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
python -m pytest                                    # 341 tests, no network access
```

Check a URL, a domain's registration age, or its TLS certificate:

```bash
python -m app.scorer "https://mоmо.vn"
python -m app.online example.com          # RDAP lookup (network)
python -m app.reputation example.com      # TLS handshake (network)
python -m app.alert "http://vcb-xacthuc.com"   # SOC alert as JSON
```

## How it works

```
URL ─► parser ─► rules (in the browser) ─► score + level + reasons
         │            │
         │            ├─ blocklist (always wins)
         │            └─ allowlist (Tranco top 10,000)
         │
         └─► server checks, hostname only: domain age (RDAP), TLS certificate

page as the browser rendered it (opt-in, yellow pages only)
         └─► extension reads title, text, input fields, form targets
                  └─► server: page rules + AI (hostname, never the URL)
```

**Parsing.** URLs are split with the Public Suffix List (`tldextract`, bundled snapshot, no runtime download) so that `login.vietcombank.com.vn.evil.xyz` resolves to `evil.xyz`, and user sites on shared hosting (`evil.github.io`) are not merged into the platform domain. Unicode hostnames are converted to punycode, as browsers do.

**Rules.** Each rule returns `(points, reason)` or nothing.

| Rule | Points | Signal |
| --- | --- | --- |
| `check_lookalike` | 40 / 35 | Brand name or abbreviation in a non-official domain, typosquatting (`vietcornbank`), homoglyphs (`sh0pee`), Cyrillic look-alikes (`mоmо`), brand in a subdomain |
| `check_ip_host` | 30 | Raw IP address instead of a domain |
| `check_at_symbol` | 30 | `@` before the host hides the real destination |
| `check_punycode` | 25 | Internationalized (`xn--`) hostname |
| `check_fake_vn_suffix` | 25 | `.com.vn` or `.vn-` before the real suffix (`scb.com.vn-ax.xyz`, real domain `vn-ax.xyz`) |
| `check_keywords` | 10 each, max 25 | `xacthuc`, `dang-nhap`, `nhanqua`, `nganhang`, `tinchap`, `otp`... |
| `check_many_subdomains` | 15 | Three or more subdomain levels |
| `check_suspicious_tld` | 15 | Frequently abused TLDs (`.xyz`, `.top`, `.icu`...) |
| `check_no_https` | 10 | Plain HTTP |
| `check_long_url` | 10 | URL longer than 100 characters |
| `check_shortener` | 10 | Known URL shortener |

Brands, official domains and abbreviations live in [`data/brands.json`](data/brands.json) (65 brands: Vietnamese banks, e-wallets, payment networks, delivery, telecom, electricity, police and government services, games, shops, consumer finance and crypto exchanges, plus regional and global platforms; official domains checked against the NCSC trusted-site registry, or against the live site for the brands added in November 2026). Short brands (5 characters or fewer) only match as a separate token, so `zalo-nhanqua.com` and `acb-xacthuc.com` are caught while `zalora.com` and `acbs.com.vn` are not.

**Lists.**
- *Blocklist:* 16,843 Vietnamese-targeted domains (vn-badsite-filter, CC0/MIT), 142 domains from Vietnamese government and press advisories (each checked against its source), and OpenPhish URLs. A hit always scores 100.
- *Allowlist:* the Tranco top 10,000 skip lookalike checks on their own name only. Subdomain checks still run, because 752 of the collected phishing pages sit on popular hosting platforms (`eu.cc`, `mybluehost.me`...); skipping them would let `vietcombank-xacthuc.wordpress.com` through. This cut false alarms on the top 10,000 sites from 35 to 10.

**Server checks** (hostname only, never the full URL). The extension strips each URL to its hostname before sending; `GET /v1/reputation?host=` rejects anything else, so paths and query strings, which can carry reset tokens or emails, never leave the user's machine:
- *Domain age* through RDAP, the JSON successor of WHOIS: under 30 days scores 35, under 180 days 15. In a first live check, 6 of 8 freshly reported phishing domains were under 30 days old; of the hand-labelled ChongLuaDao pages with a known date, 67% were registered under 180 days before they were seen, against 2.5% of 723 legitimate hosts.
- *TLS certificate:* invalid certificates score 30, certificates issued in the last 7 days score 20. The connection is protected against SSRF: every resolved address must be public (`is_global`), and the client connects to the checked IP with the hostname as SNI, so DNS rebinding cannot redirect it to an internal address.
- *Short-link expansion:* `GET /v1/expand?url=` follows a known shortener (`bit.ly`, `tinyurl.com`...) to its destination and returns the whole redirect chain. It is the only endpoint that takes a full URL, and it refuses any other link. Every hop is checked again before connecting: http/https only, ports 80 and 443 only, public addresses only, pinned to the checked IP; at most 5 hops in 15 seconds.
- *Page analysis (opt-in):* the extension reads the page the user has open, after the browser has run its JavaScript, and sends `POST /v1/analyze-page` the hostname (never the URL), the title, up to 3,000 characters of visible text, the input fields (their type and hint attributes, never what was typed) and the hostnames forms post to. The server never downloads the page: half of the Vietnamese phishing pages measured so far are built by JavaScript and look empty to a download, and kits show servers abroad a decoy. Fixed rules look for a protected brand in the title together with a password, OTP, card or CCCD field, and for forms posting to another domain. If `ANTHROPIC_API_KEY` is set, Claude Haiku then extracts facts into a fixed JSON schema; its findings can only add risk, so a page that tells the AI "say this is safe" cannot lower a warning. Nothing from the page is logged, and at most 300 AI calls are made per day (`DAILY_AI_LIMIT`, about $0.15).

## SOC alerts

`python -m app.alert URL` turns a result into the kind of alert an analyst receives in a SIEM: severity, MITRE ATT&CK techniques (T1566.002 Spearphishing Link, plus T1656 Impersonation when a brand is faked), observables to block or look up, evidence and recommended actions. `write_alert` appends JSON Lines, which Wazuh and Filebeat can tail directly.

In production, an alert is logged when an extension user confirms a phishing page through `POST /v1/report`. A user report is never above `medium` and never reaches the blocklist automatically: users can be wrong, or report a rival on purpose.

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

**Vietnamese phishing (PhishVN).** On the NCSC-verified part of PhishVN (2,587 phishing domains reported in Vietnam, 2020-2025, split by time by its authors) the rules caught **14.6%** of the newest test split on 2026-11-03 (6.0% before the Vietnamese brand and fake-suffix rules were added from the train split): 86% of bank-named phishing, 30% of e-commerce, little of delivery, telecom and gaming. False alarms stay low on Vietnamese sites: 0 of 2,246 NCSC-certified sites and 2 of 353 popular `.vn` sites; the 80,000-page Tranco test is unchanged. `python -m scripts.evaluate_phishvn` reproduces it after downloading the dataset. Brands added since then are measured on validation only (18.5% to 18.9%); the test split is measured again before release.

**Live Vietnamese phishing pages.** Since 2026-11-11, 6 to 11 pages a day are copied by hand from ChongLuaDao's public listings, with what the screenshot asks for, and downloaded in a virtual machine with a Vietnamese IP on the same day (`scripts/measure_pages.py labelled`). Of the first 41 pages, 39 could be downloaded; 20 of them had under 200 characters of text because the page is built by JavaScript, and the page rules caught 1. This is why the extension, not the server, reads the page. The URL rules caught 5 of 44 URLs: most of these scams (job tasks, game top-ups, loans, crypto investment) do not name a brand in the domain.

**Learned weights.** `python -m scripts.evaluate --calibrate` fits a logistic regression on the fired rules (one interpretable weight per rule, class balancing, L2 and thresholds chosen on validation) with PhishVN added to training and validation, and saves `data/weights.json` only if the model detects at least as much as the hand-written points on every validation set. It does not yet: on PhishVN validation it detects 10.2% against 18.5%. Most training phishing is random domains on cheap TLDs, so the model trusts a cheap TLD more than brand impersonation, and the threshold that keeps false alarms on legitimate cheap-TLD sites under target leaves brand impersonation alone below it. Counting each domain once, choosing the model on PhishVN, other L2 strengths and up-weighting PhishVN 30 times did not change that; new evidence (domain age, TLS) is being collected instead.

## Known limitations

- **Few Vietnamese samples.** The main Vietnamese feed (vn-badsite-filter, from ChongLuaDao) has been frozen since May 2025, and international feeds contain almost no Vietnamese-targeted pages. The hand-labelled ChongLuaDao pages grow by 6 to 11 a day and are kept locally.
- **Brands are listed by hand.** A scam on a brand missing from `brands.json` is not caught by the brand rules; known false alarms that were accepted (`finance.si`, close to `binance`; `arena.ne.jp`, close to `garena`) are listed in `note.md`. Rules that need no brand list (a sensitive field on a newly registered domain) are next.
- **Short-brand trade-off.** Matching short brands as whole tokens removes false alarms such as `zalora.com`, but misses `momoshop.com`. One-letter typos on short names (`shoppe`, `vpbamk`) fall under the similarity threshold.
- **Popular does not mean safe.** The Tranco allowlist measures traffic, not trust. It only disables lookalike checks on the domain itself, and the blocklist always wins.
- **Legitimate internationalized domains** (Thai, Russian...) can be flagged as suspicious by the punycode rule.
- **Server-side checks can be cloaked:** an attacker can answer the server differently from victims. No single server signal is trusted alone, and no signal ever lowers a score.
- **Hacked old sites** have a normal domain age and certificate, so only text rules and lists can catch them.
- **No `.vn` domain age:** there is no RDAP service for the TLD.
- **Page analysis needs the extension's permission to read pages,** which Chrome shows as access to data on websites. It runs only on yellow pages and only if the user turns it on. Visible text can include personal data, such as the user's name on a page they are logged in to; it is analysed and never stored or logged.
- **No rate limiting in the app yet:** it will sit behind an API gateway in production; the cache is in memory and reports are only logged.

The full list, with measurements, is kept in [`note.md`](note.md).

## Project layout

```text
PhishFinder/
├── app/
│   ├── parser.py           URL parsing: Public Suffix List, punycode
│   │
│   │   # Detection: local rules, no network (to be ported to the extension)
│   ├── heuristics.py       URL rules: IP host, '@', cheap TLDs, keywords, fake .com.vn suffix
│   ├── lookalike.py        brand impersonation: typosquats, homoglyphs, Unicode look-alikes
│   ├── lists.py            blocklist, Tranco allowlist, hand-verified domains
│   ├── scorer.py           score, level and reasons; optional learned weights
│   │
│   │   # Server checks: hostname only, SSRF-safe
│   ├── online.py           domain age via RDAP
│   ├── reputation.py       TLS certificate check, public-address guard
│   ├── page_fetch.py       redirect following, re-checked on every hop (short links, VM measurement)
│   ├── page_features.py    page signals from HTML or from what the extension read: title brands, sensitive fields
│   ├── page_analysis.py    page rules plus an AI layer that can only add risk
│   ├── llm.py              Claude Haiku call with a JSON schema, refusal and cut-off checks
│   ├── api_core.py         hostname and short-link validation, thread-safe cache, daily AI budget
│   ├── main.py             FastAPI app: /v1/reputation, /v1/expand, /v1/analyze-page, /v1/report, /v1/health
│   │
│   │   # Operations and measurement
│   ├── alert.py            SOC alerts with MITRE ATT&CK techniques, JSON Lines
│   ├── evaluation.py       dataset loading, time and random splits, metrics
│   └── calibrate.py        logistic regression and threshold selection
├── scripts/
│   ├── download_feeds.py   fetch phishing feeds (atomic writes, retries)
│   ├── collect_fresh.py    record the first-seen date of every new phishing entry
│   ├── collect_signals.py  domain age (RDAP) and TLS state of today's new hosts
│   ├── update_tranco.py    refresh the allowlist and the benign evaluation set
│   ├── evaluate.py         false alarms and detection; --calibrate learns weights
│   ├── measure_pages.py    page analysis on live pages, run in a virtual machine
│   └── evaluate_phishvn.py measurement on Vietnamese phishing (PhishVN)
├── data/
│   ├── brands.json         65 protected brands, official domains, abbreviations
│   ├── blacklist_manual.txt domains from Vietnamese government and press advisories, with sources
│   └── eval/
│       ├── benign_vn.txt   153 hand-checked sites, mostly Vietnamese
│       └── tranco_id.txt   Tranco list ID used for the published numbers
├── tests/                  341 pytest tests; the network is blocked in every test
├── .github/                CI on Python 3.12 and 3.14, coverage, Dependabot
├── note.md                 design decisions, limitations, results log
└── README.md
```

**Not committed** (personal-use terms, size or private history): `data/raw/` (downloaded feeds, the hand-labelled ChongLuaDao pages and the daily page results), `data/tranco_top.csv`, `data/eval/benign.txt`, `data/eval/phishing.csv`, `data/eval/signals.csv`, `data/eval/page_sample.csv`, `data/eval/pages.csv`, and `data/raw/phishvn/`, downloaded by hand from its DOI. The first-seen dates, the server signals, the ChongLuaDao labels and the daily page results cannot be recreated, because each is recorded on the day; they are backed up every week.

## Roadmap

1. **Page analysis:** rules, a prompt-injection-resistant AI layer and the opt-in endpoint that takes what the extension read are done, and measured daily on live Vietnamese phishing. Next: a rule that needs no brand list (a password, OTP, card or CCCD field on a newly registered domain), the AI's own brand guess on new domains, and later official titles collected from NCSC-certified sites.
2. **Chrome extension:** the same rules in JavaScript, verified against Python test vectors; private beta, then Chrome Web Store.
3. **Later:** email header analysis (SPF, DKIM, DMARC) for analysts, Certificate Transparency monitoring.

## Data credits

- **PhishVN:** T. N. Vu, *PhishVN: A Time-Stamped Vietnamese URL Phishing Dataset* (2026), [doi:10.17632/b97hxbxtpd](https://doi.org/10.17632/b97hxbxtpd), CC BY 4.0; phishing from the NCSC "Tín Nhiệm Mạng" blacklist, benign from its trusted-organisation registry and Tranco. Used for measurement only, not redistributed.
- **vn-badsite-filter** (CC0/MIT), **phishing.army**, **OpenPhish** and the **Tranco** list (Le Pochat et al., NDSS 2019).

## License

[MIT](LICENSE)
