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
- **Most fresh phishing fires no informative rule.** On the first fresh test set, 77.8% of phishing URLs fired nothing besides the HTTP rule, exactly like 98.0% of benign pages; no reweighting can separate them. The rule layer caps detection at about 22% on these feeds.
- **The cheap-TLD rule is too common on legitimate sites to stand alone** (about 1.4% of benign pages, above the 0.5% yellow target), so a learned model cannot warn on it by itself.
- **Fresh Vietnamese phishing is almost absent:** 4 to 7 `.vn` entries in the fresh test set, so the Vietnamese detection rate is not yet meaningful.
- **Benign pages have no paths** (0 of 80,000) while 350 phishing entries do, so path-based rules (keywords in path, long URL) can learn leaked weights; `benign_private.txt` from real browsing would fix this.
- **Rules that never fire in training get weight 0** in the learned model (`check_ip_host`, `check_shortener`, `check_at_symbol`), i.e. they stop affecting the score while their reasons are still shown.
- **URL blocklist matching ignores scheme, host case and trailing slash, and drops an appended query** when the listed URL has none. A listed URL that carries its own query still needs that exact query, so attackers can evade it by changing parameters.

### Reputation (`app/online.py`)
- **No domain age for `.vn`:** there is no RDAP service for the TLD, so Vietnamese domains rely on the text rules only.
- **Hacked old sites have a normal age.** `aaghazedosti.com` (registered 2022) hosts phishing; domain age only catches newly registered domains.
- **Phishing domains disappear quickly.** `006901.com`, collected on 2026-10-21, returned 404 (no longer registered) a day later; `96fj.top`, registered on 2026-10-21, was gone by 2026-10-26. Look up the step 9.3 sample soon after collection.
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
- **No rate limiting in the app.** CORS only stops other web pages; scripts can call the API freely, so rate limiting belongs at the API Gateway (step 14). Until then, keep the server bound to `127.0.0.1`.
- **The cache lives in process memory.** It is lost on restart and not shared between instances (e.g. Lambda cold starts); acceptable at beta scale.
- **Reports are only written to the log** (`REPORT verdict level host version`); they must be read by hand daily in step 15 and moved to a database later.
- **TLS worst case is about 10 s per uncached host,** which the extension must tolerate (show the local result first, update when the server answers).

### Short-link expansion (`app/page_fetch.py`, `/v1/expand`)
- **Only HTTP redirects are followed** (301, 302, 303, 307, 308). Redirects done with JavaScript or `<meta http-equiv="refresh">` end the chain early, so `final` can be an intermediate page.
- **HEAD and GET can differ.** Some shorteners answer HEAD with 405 or a different target; HEAD is kept because it downloads no page body.
- **Cloaking:** a shortener or landing page can send the server (data-centre IP, no cookies) somewhere harmless while victims get the phishing page.
- **`SHORTENERS` lists 8 international services only;** Vietnamese shorteners are not covered yet, and any other link is refused with 400.
- **The expansion request is visible to the shortener,** which learns that someone checked the link (not who: the request comes from the server).

## Decisions
- **Reasons and level names are in English** (`dangerous`, `suspicious`, `likely_safe`), unlike the Vietnamese examples in the guide. Any new code (alerts, email analysis) must use `score_to_level()` instead of repeating the thresholds.
- **TPBank:** only `tpb.vn` is listed as official (verified); `tpbank.vn` is intentionally not allowlisted.
- **Single parser path.** `tldextract` is a required dependency; the guide's hand-written fallback was dropped so results cannot differ between machines.
- **Test runner is pytest.** Install with `pip install -r requirements-dev.txt`, run with `python -m pytest` (avoids picking up a global pytest). All tests use pytest style (plain `assert`, `parametrize`, fixtures); the last unittest-style file was converted in step 8d.
- **Dependencies are split and list top-level packages only.** `requirements.txt` holds runtime packages (`fastapi`, `tldextract`, `uvicorn`); `requirements-dev.txt` adds test tools (`pytest`, `httpx2`). `pip freeze` is no longer used, so dev tools cannot leak into the runtime file. Trade-off: transitive dependencies are not pinned; a lock file (pip-tools or uv) would fix this.
- **The production API accepts hostnames only** (`GET /v1/reputation?host=`): the extension strips the URL to its hostname on the user's machine before sending, and the server rejects anything else with 400 (full URLs, IPs, ports, Unicode). Data that is never sent cannot leak through gateway or access logs. The old full-URL `/check` endpoint was removed.
- **HTTP status codes carry meaning:** 400 for a value that is not a valid hostname, 422 for schema errors (missing field, wrong pattern), never 200 with an error body.
- **Endpoints are versioned (`/v1/`)** so old extension versions keep working when the format changes.
- **`/docs` and `/openapi.json` are disabled** unless `PHISHFINDER_DEV=1`; CORS allows only the origins in `EXTENSION_ORIGIN` (empty by default).
- **Logs hold counts, not hostnames,** for reputation lookups: a hostname next to a client IP is browsing history. Reports do log the validated hostname, which cannot inject log lines; `extension_version` is restricted to digits and dots for the same reason.
- **The cache is thread-safe** (FastAPI runs `def` endpoints on worker threads), and domain age is cached per registered domain, so subdomains share one RDAP lookup.
- **External check failures are logged, not swallowed** (`_safe` logs the error type, never the host).
- **`httpx2` instead of `httpx` for `TestClient`.** Starlette 1.8 deprecates `httpx` for its test client.
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
- **Weights are learned with logistic regression on rule sets, not URLs.** About 207,000 URLs collapse into ~33 distinct (rule set, label) groups; training on grouped counts gives the same result thousands of times faster, so 5,000 epochs take 0.1 s.
- **L2 is chosen on the validation split** (0.01 / 0.001 / 0.0001 / 0.00001): the guide's fixed 0.01 pushed rare rules to almost zero (lookalike 0.13). Thresholds are picked on benign validation, with floors of 70 (red) and 40 (yellow).
- **The phishing test set is every entry first seen after the first collection day;** the first day is a snapshot of everything already known and is used for training and validation only.
- **Learned weights are not used yet.** On the fresh test set they detect less than the hand-written points (0.7% vs 1.4%; Vietnamese 0/7 vs 5/7) while both meet the false-alarm targets. `data/weights.json` is not committed until a model beats the hand-written points on validation; rerun in week 6.
- **Tests always use the hand-written points** through an autouse fixture that sets `scorer.WEIGHTS = None`.
- **Feed downloads are bounded and atomic:** 60 s timeout, 20 MB cap, write to `.part` then rename. Each download is retried up to 3 times (waits 5 s, then 10 s) after phishing.army timed out once during the TLS handshake (2026-10-29); a feed that still fails keeps its previous file, so a day with far fewer new entries than usual (normally about 1,500-2,600) means the collection must be rerun the same day.
- **`/v1/expand` takes full URLs, but only for known shorteners** (`normalize_short_url`: http/https, no userinfo, no port, at most 200 characters, host in `SHORTENERS`). A short link's path is the whole link, and it carries no personal data the shortener does not already have.
- **Every redirect hop is checked again** before connecting: scheme (http/https), port (80/443 only) and that every resolved address is public. The connection goes to the checked IP (hostname kept for Host and SNI), so neither a redirect to `169.254.169.254` nor a name that resolves internally, nor DNS rebinding between check and connect, can reach internal services.
- **Limits:** 5 s per request, 15 s overall, 5 hops, HEAD by default, 1 MB body cap and `text/html` only for GET. The response includes the full `chain` and the last `status`; results are cached for 6 hours.
- **Pinned connections override `connect()` with `@override`,** so a misspelled method name (it happened: `connection`) fails at type-check time instead of silently connecting by hostname.
- **The Python code is the reference for the JavaScript port**, including the deviations from the guide (`contains_brand`, aliases, Unicode handling, English reasons and levels).

## To address in upcoming steps
- Step 6b follow-up: grow the benign set to ~80,000 pages and pin one Tranco list while comparing changes; extend `data/eval/benign_vn.txt` to 300-500 Vietnamese pages, including login and payment subpages; hand-check 50 random entries per set.
- Daily until release: `python -m scripts.download_feeds`, then `python -m scripts.collect_fresh data/raw/phishing_army.txt data/raw/openphish.txt data/raw/vn_badsite.txt data/samples_phishing.txt`. Weekly: `python -m scripts.update_tranco`. Automated in step 14.
- Step 9 (idea, measure before adding): a public domain resolving to an internal address is anomalous and could score (possible DNS rebinding); legitimate developer domains (`localtest.me`, `lvh.me`, `*.nip.io`) would be false alarms.
- Step 9 (idea): for allowlisted domains, try reducing the domain-level lookalike points instead of skipping them, and keep whichever measures better on the validation set. Print false alarms from the validation split, not the test split, while tuning.
- **After step 9: Vietnamese phishing sources.** Fresh Vietnamese samples are the main gap (4 `.vn` entries in the first fresh test set). Checked on 2026-10-23:
  - ChongLuaDao: `chongluadao.vn` is online with a public denylist page, but the old API (`api.chongluadao.vn`) no longer resolves and the GitHub mirrors (vn-badsite-filter, elliotwutingfeng/ChongLuaDao-Phishing-Blocklist) are frozen. Ask them for official data access; do not scrape the site without permission. The frozen lists remain usable as "old" phishing (vn-badsite-filter is CC0/MIT; check the other repo's license).
  - tinnhiemmang.vn (NCSC): manual lookup only, no public API.
  - hostsVN and ABPVN are active, but they are ad-blocking lists: their `.vn` entries are ad servers, not phishing. Using them as phishing labels would poison the data.
  - hagezi `fake` list: about 17,500 domains, only 1 Vietnam-related.
  - Most promising: manual collection into `data/samples_phishing.txt` (scam-warning groups, news), and Certificate Transparency queries for Vietnamese brand names (crt.sh) to find new lookalike domains. CT gives unlabeled candidates that need checking; it stays in January as planned.
  - Decision (2026-10-23): right after step 9, contact ChongLuaDao to ask for research access to their data. Everything else keeps the original schedule.
  - **Contacted ChongLuaDao on 2026-10-25** (awaiting a reply). Asked whether they provide phishing domains or URLs for non-commercial research, under which terms, and whether entries carry a first-seen date. Offered three usage levels for them to choose from: (a) measurement only, never shipped; (b) lookup on our server, the extension sends hostnames only; (c) bundled in the extension with attribution. We follow whichever level they allow, even (a) only. If they allow only (b), the list is consulted only for hostnames the server is asked about (currently yellow results).
  - Evidence given: of 7,326 fresh phishing entries (2026-10-22..25) none mentions a Vietnamese bank or e-wallet brand and only 7 have a `.vn` suffix (0.10%); counted on domain names only, page content was not checked. `api.chongluadao.vn` did not resolve on 2026-10-21, 23 and 25.
- Step 12/13 decision (the API needs no change): ask the server (hostname only) for the "uncertain" band 15-29 as well as yellow. On the fresh test set this band holds 20.2% of phishing but only 1.8% of benign pages, and it is exactly where domain age and TLS separate them; with "yellow only", those signals are never used.
- Step 9.3 (before the week 6 rerun): look up domain age and TLS for ~500 benign and ~500 phishing hosts soon after collection and pass them as `extra`; add `benign_private.txt` (pages with paths); collect Vietnamese samples.
- Step 7c: page analysis reuses `follow(..., method="GET")`; add Vietnamese shorteners to `SHORTENERS` once they are checked.
- Step 10: `to_alert` must handle error results; add `alerts.jsonl` to `.gitignore`.
- January (email tool): reuse `contains_brand` for display-name spoofing and `score_to_level` for email scoring.

## Results log
Rule layer only (`use_blacklist=False`), benign test split. Phishing test: newest 30% until 2026-10-22, entries first seen after the first collection day from 2026-10-25.

| Date | Tranco ID | Benign test | Phishing test (VN) | FPR red | FPR yellow+ | Recall red | Recall yellow+ | Recall VN yellow+ | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-10-21 | 262W9 | 7,503 | 51,959 (178) | 0.013% | 0.120% | 0.2% | 1.8% | 11.2% | Baseline; single collection day |
| 2026-10-22 | 746PX | 7,503 | 51,959 (178) | 0.000% | 0.080% | 0.2% | 1.8% | 11.2% | Same phishing data, new Tranco list |
| 2026-10-25 | GQ32K | 19,997 | 7,326 (7) | 0.000% | 0.150% | 0.1% | 1.4% | 71.4% | 80k benign; fresh-only phishing test; hand-written points |
| 2026-10-25 | GQ32K | 19,997 | 7,326 (7) | 0.005% | 0.005% | 0.7% | 0.7% | 0.0% | Learned weights (L2 0.001, thresholds 94/94); not adopted |

## After all steps are done
- **CI (GitHub Actions):** workflow `.github/workflows/tests.yml` that installs `requirements-dev.txt` and runs `pytest` on every push and pull request; add a "tests passing" badge to the README.
- **Repository ruleset for `main`:** require a pull request before merging, require the CI status check to pass, block force pushes and branch deletion.
