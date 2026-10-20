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

### API (`app/main.py`)
- **Current `/check` accepts a full URL, which conflicts with the production plan.** Paths and query strings can carry reset tokens, emails or order IDs. To be replaced in step 7 by a hostname-only `/v1/reputation`; do not deploy the current version.
- **No authentication or rate limiting yet.** The server must stay bound to `127.0.0.1` (the uvicorn default) until phase 4.
- **`/docs` is always enabled.** Fine for development; should be disabled or protected when deployed.

## Decisions
- **Reasons and level names are in English** (`dangerous`, `suspicious`, `likely_safe`), unlike the Vietnamese examples in the guide. Any new code (alerts, email analysis) must use `score_to_level()` instead of repeating the thresholds.
- **TPBank:** only `tpb.vn` is listed as official (verified); `tpbank.vn` is intentionally not allowlisted.
- **Single parser path.** `tldextract` is a required dependency; the guide's hand-written fallback was dropped so results cannot differ between machines.
- **Test runner is pytest.** Install with `pip install -r requirements-dev.txt`, run with `python -m pytest` (avoids picking up a global pytest). Existing unittest-style tests run unchanged; new tests use pytest style.
- **Dependencies are split and list top-level packages only.** `requirements.txt` holds runtime packages (`fastapi`, `tldextract`, `uvicorn`); `requirements-dev.txt` adds test tools (`pytest`, `httpx2`). `pip freeze` is no longer used, so dev tools cannot leak into the runtime file. Trade-off: transitive dependencies are not pinned; a lock file (pip-tools or uv) would fix this.
- **HTTP status codes carry meaning.** `/check` returns 200 with a result, 400 for a URL without a hostname, and 422 for schema errors (missing, empty, wrong type, longer than 2048 chars), instead of 200 with an error body.
- **`httpx2` instead of `httpx` for `TestClient`.** Starlette 1.8 deprecates `httpx` for its test client.
- **`/check` uses `POST` with a JSON body**, so the checked URL never appears in request paths or access logs.
- **Hostnames are converted to punycode like browsers do**, so the Python core sees the same input as the extension.
- **Deterministic output.** Wherever a set is involved (e.g. the matched alias), pick with `sorted(...)`, so the JavaScript port (step 12) can match the Python results exactly.
- **The Python code is the reference for the JavaScript port**, including the deviations from the guide (`contains_brand`, aliases, Unicode handling, English reasons and levels).

## To address in upcoming steps
- Step 6b: `evaluate()` in the guide counts Vietnamese level names (`nguy_hiem`, `dang_ngo`); use `dangerous` / `suspicious` or every metric reads 0%. Start collecting fresh phishing links daily as early as possible.
- Step 8a: `python-whois` fails on every `.vn` domain tested (`WhoisError`) and returns `None` for some gTLDs, which the guide scores as 10 points. Prefer RDAP (JSON over HTTPS, standard library only); it works for `.com`, `.xyz`, `.top`, `.shop`, `.icu`, but not `.vn`. Lookup failures must not add points.
- Step 8b: normalize URLs before blacklist lookup (case, query string); skip `localhost` / `0.0.0.0` entries in hosts files.
- Step 8d: SSRF guard should use `ip.is_global` (CGNAT `100.64.0.0/10` passes the current checks).
- Step 8e / 9: Tranco allowlist must only disable checks on the registered domain, never the subdomain check (`vietcombank-xacthuc.wordpress.com`). `run_rules` in the guide still skips the whole lookalike rule.
- Step 9: `level_of()` in the guide uses Vietnamese names; extend `score_to_level()` with red/yellow thresholds instead. Reset `WEIGHTS` for tests with a pytest fixture in `tests/conftest.py`.
- Step 7 (week 5, after step 8): rewrite the API as in the plan (`/v1/reputation?host=`, `/v1/report`, `/v1/health`, docs disabled, CORS); keep endpoints as plain `def` while checks are blocking. `Report.shown_level` must use English level names.
- Step 10: `to_alert` must handle error results; add `alerts.jsonl` to `.gitignore`.
- January (email tool): reuse `contains_brand` for display-name spoofing and `score_to_level` for email scoring.

## After all steps are done
- **CI (GitHub Actions):** workflow `.github/workflows/tests.yml` that installs `requirements-dev.txt` and runs `pytest` on every push and pull request; add a "tests passing" badge to the README.
- **Repository ruleset for `main`:** require a pull request before merging, require the CI status check to pass, block force pushes and branch deletion.
