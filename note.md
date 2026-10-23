# Development Notes

Known limitations and design decisions found while building phase 1.
These feed the "Known limitations" section of the README.

## Known limitations

### Parser (`app/parser.py`)
- **Not every shared-hosting platform is a PSL private suffix.** `abc.wordpress.com` resolves to `wordpress.com`, while `evil.github.io` correctly resolves to `evil.github.io`. Relevant for the Tranco allowlist (step 8e); covered by a test in `tests/test_extras.py` that records the current behavior.
- **Bundled Public Suffix List snapshot.** `tldextract` runs offline (`suffix_list_urls=()`), so new suffixes only arrive when the library is upgraded.
- **Single-label hosts.** `localhost` gives `registered_domain='localhost'` and an empty suffix.
- **Port is ignored.** `urlparse` moves the port to `parts.port`; it is not stored. Possible future rule: non-standard port on a brand-like domain.
- **IDNA 2003 vs browsers.** Python's `idna` codec implements IDNA 2003: `straße.de` becomes `strasse.de`, while browsers (UTS #46) produce `xn--strae-oqa.de`. Rare, but a possible Python/JavaScript mismatch for step 12; the `idna` package (IDNA 2008) would remove it.
- **Unknown schemes are not flagged.** `ttps://`, `javascript:`, `data:` pass through; `check_no_https` only fires on exactly `http`. Found when a typo (`ttps://`) in a test still passed.

### Heuristics (`app/heuristics.py`)
- **Keyword matching is substring-based.** `login` in `github.com/login` adds 10 points to a legitimate page (low impact, stays below the threshold).
- **Weights are initial estimates**, not tuned on data yet (learned from data in step 9).

### Lookalike detection (`app/lookalike.py`)
- **Short brands (<= 5 chars) only match as separate tokens.** Fixes false positives such as `zalora.com`, `tikitaka.com`, `bidvietnam.com`, but `momoshop.com` is no longer caught. Accepted trade-off: fewer false positives for some missed lookalikes.
- **Aliases also match only as tokens.** `vcb-xacthuc.com` is caught, while `vcbs.com.vn`, `tcbs.vn`, `fbi.gov` are not flagged. An alias glued to another word is missed.
- **Typos on short names slip under the similarity threshold (0.85).** `shoppe` vs `shopee` = 0.83, `mono` vs `momo` = 0.75; both score 0.
- **Brand in userinfo is only caught by the `@` rule.** `vietcombank.com.vn@evil.com` scores 30; the lookalike rule does not inspect the part before `@`.
- **Unicode lookalikes use a small confusables table.** Punycode labels are decoded and Cyrillic/Greek look-alike letters are mapped to Latin, so `mоmо.vn` (Cyrillic о) scores 65. The full Unicode confusables list has thousands of entries; characters outside the table are missed.
- **Brand data is maintained by hand** in `data/brands.json`. A wrong or missing official domain flags a legitimate site; aliases are only added once seen in real phishing samples.

### Lists and evaluation data (`app/lists.py`, `scripts/`)
- **Few Vietnamese-targeted pages in fresh feeds.** About 78 of 155,901 phishing.army domains look Vietnam-related (`.vn` or a Vietnamese brand). Recall on Vietnamese phishing will rest on a small sample; manually collected links (`data/samples_phishing.txt`) matter most.
- **Labels are noisy.** Feeds contain dead pages and likely mislabels (e.g. `account.esms.vn`); hand-check 50 random entries per set before measuring.
- **Daily snapshots miss short-lived entries.** phishing.army refreshes every 4 hours; an entry added and removed within a day is never recorded.
- **Domain-list entries become `http://<domain>/`.** Every such phishing sample triggers `check_no_https` and none trigger path rules (keywords, long URL). Benign entries must be built the same way, or the evaluation and the weights learned in step 9 will reward the scheme instead of real signals.
- **The benign test set is too small for the red target.** With 30,000 Tranco domains, the split (50% train, 25% validation, 25% test) leaves 7,503 test pages; one red false alarm moves the rate by 0.013%, so the 0.05% target cannot be measured. About 80,000 benign pages (Tranco up to rank ~90,000) are needed for a 20,000-page test set.
- **The benign set changes with every Tranco list.** Runs on lists 262W9 and 746PX sampled different test pages (red false alarms 0.013% vs 0.000%). Pin one list ID while comparing rule changes, and only switch lists deliberately.
- **The time split is meaningless until several days of data exist.** On the first day every entry has the same `first_seen`, so the "newest 30%" is just the alphabetical tail.
- **Low recall on random-looking domains is expected.** Most phishing.army entries are random strings on cheap TLDs (`*.sbs`, `*.top`); they score 25 (TLD 15 + HTTP 10), below the yellow threshold. Domain age and TLS (step 8) and learned weights (step 9) target these.
- **The Vietnamese subset is defined by `.vn` suffix only**, so it does not depend on the rules being measured, but it misses Vietnamese-targeted pages on other suffixes (`vcb-xacthuc.com`). Manually collected samples would give a better Vietnamese set.
- **URL blocklist matching ignores scheme, host case and trailing slash, and drops an appended query** when the listed URL has none. A listed URL that carries its own query still needs that exact query, so attackers can evade it by changing parameters.

### Reputation (`app/online.py`)
- **No domain age for `.vn`:** there is no RDAP service for the TLD, so Vietnamese domains rely on the text rules only.
- **Hacked old sites have a normal age.** `aaghazedosti.com` (registered 2022) hosts phishing; domain age only catches newly registered domains.
- **Phishing domains disappear quickly.** `006901.com`, collected on 2026-10-21, returned 404 (no longer registered) a day later. Look up the step 9.3 sample soon after collection.
- **RDAP servers rate-limit and reset connections** (Verisign reset one request, then answered). The API in step 7 must cache results instead of querying on every request; any failure already gives no finding.
- **TLS: free certificates are not a signal; new ones are.** Only certificates issued in the last 7 days score (20). First live check: 4 of 15 fresh phishing hosts had certificates issued one day earlier.
- **TLS: invalid certificates score 30,** which also flags legitimate sites with expired or misconfigured certificates.
- **TLS: slow worst case.** About 10 s per host (2 addresses x 5 s timeout), and DNS resolution has no timeout of its own; the API (step 7) must cache results or run the check off the request path.
- **Server-side checks can be cloaked.** An attacker can answer the server differently from victims (by IP, region or time). Rules that run in the browser are not affected; no single server-side signal is trusted alone.
- **`None` does not say why.** Not registered, unsupported TLD and network errors all give no finding by design; call `fetch_json(rdap_url(...))` directly when debugging.

### False alarms seen in the first measurements (fix in step 9, measured on the validation set)
- **Official domains in other countries:** `facebook.de`, `thefacebook.com`, `shopeepay.com.br` are flagged as impersonation because `brands.json` lists only the main domains.
- **Brand contained in a longer real name:** `otpbank.ru` (a real bank) contains `tpbank` and scored red (60).
- **Three-letter names vs four-letter brands:** `bid.cars`, `mom.gov.sg`, `alo.rs` reach similarity 0.857 with `bidv`, `momo`, `zalo`, above the 0.85 threshold.
- **Alias as a whole label:** `fb.gg` matches the `fb` alias.
- **Legitimate IDN domains** (Thai, Russian) score 35 from punycode (25) plus HTTP (10). The 10 sites still flagged in the Tranco top 10,000 are all IDN domains; with `https://` they drop to 25. Punycode alone is a weak signal.
- **The allowlist cannot fix these on the benign test set** by design: it covers ranks 1-10,000 while the benign set uses 10,001-40,000.

### API (`app/main.py`)
- **Current `/check` accepts a full URL, which conflicts with the production plan.** Paths and query strings can carry reset tokens, emails or order IDs. To be replaced in step 7 by a hostname-only `/v1/reputation`; do not deploy the current version.
- **No authentication or rate limiting yet.** The server must stay bound to `127.0.0.1` (the uvicorn default) until phase 4.
- **`/docs` is always enabled.** Fine for development; should be disabled or protected when deployed.

## Decisions
- **Reasons and level names are in English** (`dangerous`, `suspicious`, `likely_safe`), unlike the Vietnamese examples in the guide. Any new code (alerts, email analysis) must use `score_to_level()` instead of repeating the thresholds.
- **TPBank:** only `tpb.vn` is listed as official (verified); `tpbank.vn` is intentionally not allowlisted.
- **Single parser path.** `tldextract` is a required dependency; the guide's hand-written fallback was dropped so results cannot differ between machines.
- **Test runner is pytest.** Install with `pip install -r requirements-dev.txt`, run with `python -m pytest` (avoids picking up a global pytest). All tests use pytest style (plain `assert`, `parametrize`, fixtures); the last unittest-style file was converted in step 8d.
- **Dependencies are split and list top-level packages only.** `requirements.txt` holds runtime packages (`fastapi`, `tldextract`, `uvicorn`); `requirements-dev.txt` adds test tools (`pytest`, `httpx2`). `pip freeze` is no longer used, so dev tools cannot leak into the runtime file. Trade-off: transitive dependencies are not pinned; a lock file (pip-tools or uv) would fix this.
- **HTTP status codes carry meaning.** `/check` returns 200 with a result, 400 for a URL without a hostname, and 422 for schema errors (missing, empty, wrong type, longer than 2048 chars), instead of 200 with an error body.
- **`httpx2` instead of `httpx` for `TestClient`.** Starlette 1.8 deprecates `httpx` for its test client.
- **`/check` uses `POST` with a JSON body**, so the checked URL never appears in request paths or access logs.
- **Hostnames are converted to punycode like browsers do**, so the Python core sees the same input as the extension.
- **Deterministic output.** Wherever a set is involved (e.g. the matched alias), pick with `sorted(...)`, so the JavaScript port (step 12) can match the Python results exactly.
- **Evaluation sources.** vn-badsite-filter is frozen since 2025-05 (upstream `api.chongluadao.vn` shut down), so it serves as blocklist (16,843 domains, CC0/MIT) and "old" phishing only. Fresh phishing comes from phishing.army (aggregated, refreshed every 4 hours, free for personal use) and OpenPhish (community feed, full URLs).
- **Raw feeds and `data/eval/phishing.csv` are not committed** (personal-use terms, size). `phishing.csv` must be backed up weekly because its `first_seen` dates cannot be recreated. First collection: 2026-10-21, 173,196 entries (all "old" by definition).
- **Tests never depend on downloaded data.** They replace lists with `monkeypatch` and write files under `tmp_path`, so results do not change when the feeds do.
- **`run_rules()` is separate from `analyze()`,** and `analyze(url, use_blacklist=False)` measures the rules alone; the blacklist would otherwise "detect" its own entries.
- **Tests start with empty lists** through an autouse fixture in `tests/conftest.py`, so `analyze()` can consult the real blacklist in production without making tests depend on downloaded data.
- **Benign and phishing entries share one URL form:** bare domains become `http://<domain>/` in both sets, so the scheme carries no label information.
- **Benign pages come from Tranco ranks 10,001-40,000,** never the top 10,000 that will be allowlisted; benign hosts also labelled phishing are dropped. The Tranco list ID is committed in `data/eval/tranco_id.txt`; the derived files are not.
- **Domain age uses RDAP** (JSON over HTTPS, standard library only) instead of python-whois, which failed on every `.vn` domain tested and returned no date for some gTLDs. Any lookup failure gives no finding. First live check: 6 of 8 fresh phishing domains were under 30 days old.
- **TLS check blocks SSRF with an allowlist, not a denylist:** every resolved address must be `is_global` and not multicast (the guide's check let CGNAT `100.64.0.0/10` and multicast through), and the connection goes to the checked IP with the hostname as SNI, which closes the DNS-rebinding gap.
- **No signal subtracts points.** Lookup failures, SSRF refusals and timeouts add nothing; the lowest level is named `likely_safe`, never `safe`.
- **Tests block the network** with an autouse fixture in `tests/conftest.py`: any accidental real request raises `RuntimeError`, which no code path catches, so the test fails.
- **The Tranco allowlist only disables lookalike checks on the registered domain;** subdomain and alias-in-subdomain checks still run. 752 collected phishing entries sit on allowlisted platforms (`eu.cc` 623, `mybluehost.me` 42, `cloudwaysapps.com` 14, `meusitehostgator.com.br` 13, `railway.app`, `gitbook.io`...), where the guide's design would skip every lookalike check (`vietcombank-xacthuc.wordpress.com`: 45 -> 10).
- **Measured benefit of the allowlist:** false alarms among the Tranco top 10,000 drop from 35 to 10 (Tranco 746PX), all of them brands' own foreign or infrastructure domains (`shopee.co.id`, `lazada.sg`, `facebook.net`, `fb.watch`, `cdninstagram.com`). Accepted cost: a few non-brand sites are spared too (`sssinstagram.com`, a third-party downloader).
- **`VERIFIED` (hand-checked after a user report) skips every rule;** the allowlist skips only the domain-level lookalike checks. The blacklist applies to both.
- **Feed downloads are bounded and atomic:** 60 s timeout, 20 MB cap, write to `.part` then rename.
- **The Python code is the reference for the JavaScript port**, including the deviations from the guide (`contains_brand`, aliases, Unicode handling, English reasons and levels).

## To address in upcoming steps
- Step 6b follow-up: grow the benign set to ~80,000 pages and pin one Tranco list while comparing changes; extend `data/eval/benign_vn.txt` to 300-500 Vietnamese pages, including login and payment subpages; hand-check 50 random entries per set.
- Daily until release: `python -m scripts.download_feeds`, then `python -m scripts.collect_fresh data/raw/phishing_army.txt data/raw/openphish.txt data/raw/vn_badsite.txt data/samples_phishing.txt`. Weekly: `python -m scripts.update_tranco`. Automated in step 14.
- Step 9 (idea, measure before adding): a public domain resolving to an internal address is anomalous and could score (possible DNS rebinding); legitimate developer domains (`localtest.me`, `lvh.me`, `*.nip.io`) would be false alarms.
- Step 9 (idea): for allowlisted domains, try reducing the domain-level lookalike points instead of skipping them, and keep whichever measures better on the validation set. Print false alarms from the validation split, not the test split, while tuning.
- Step 9: `level_of()` in the guide uses Vietnamese names; extend `score_to_level()` with red/yellow thresholds instead. Reset `WEIGHTS` for tests with a pytest fixture in `tests/conftest.py`.
- Step 7 (week 5, after step 8): rewrite the API as in the plan (`/v1/reputation?host=`, `/v1/report`, `/v1/health`, docs disabled, CORS); keep endpoints as plain `def` while checks are blocking. `Report.shown_level` must use English level names.
- Step 10: `to_alert` must handle error results; add `alerts.jsonl` to `.gitignore`.
- January (email tool): reuse `contains_brand` for display-name spoofing and `score_to_level` for email scoring.

## Results log
Rule layer only (`use_blacklist=False`), benign test split vs newest 30% of phishing.

| Date | Tranco ID | Benign test | Phishing test (VN) | FPR red | FPR yellow+ | Recall red | Recall yellow+ | Recall VN yellow+ | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-10-21 | 262W9 | 7,503 | 51,959 (178) | 0.013% | 0.120% | 0.2% | 1.8% | 11.2% | Baseline; single collection day |
| 2026-10-22 | 746PX | 7,503 | 51,959 (178) | 0.000% | 0.080% | 0.2% | 1.8% | 11.2% | Same phishing data, new Tranco list |

## After all steps are done
- **CI (GitHub Actions):** workflow `.github/workflows/tests.yml` that installs `requirements-dev.txt` and runs `pytest` on every push and pull request; add a "tests passing" badge to the README.
- **Repository ruleset for `main`:** require a pull request before merging, require the CI status check to pass, block force pushes and branch deletion.
