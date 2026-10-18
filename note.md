# Development Notes

Known limitations and design decisions found while building phase 1.
These feed the "Known limitations" section of the README.

## Known limitations

### Parser (`app/parser.py`)
- **Not every shared-hosting platform is a PSL private suffix.** `abc.wordpress.com` resolves to `wordpress.com`, while `evil.github.io` correctly resolves to `evil.github.io`. Relevant for the Tranco allowlist (step 8e); covered by a test in `tests/test_extras.py` that records the current behavior.
- **Bundled Public Suffix List snapshot.** `tldextract` runs offline (`suffix_list_urls=()`), so new suffixes only arrive when the library is upgraded.
- **Single-label hosts.** `localhost` gives `registered_domain='localhost'` and an empty suffix.
- **Port is ignored.** `urlparse` moves the port to `parts.port`; it is not stored. Possible future rule: non-standard port on a brand-like domain.
- **Unknown schemes are not flagged.** `ttps://`, `javascript:`, `data:` pass through; `check_no_https` only fires on exactly `http`. Found when a typo (`ttps://`) in a test still passed.

### Heuristics (`app/heuristics.py`)
- **Keyword matching is substring-based.** `login` in `github.com/login` adds 10 points to a legitimate page (low impact, stays below the threshold).
- **Weights are initial estimates**, not tuned on data.

### Lookalike detection (`app/lookalike.py`)
- **Short brands (<= 5 chars) only match as separate tokens.** Fixes false positives such as `zalora.com`, `tikitaka.com`, `bidvietnam.com`, but `momoshop.com` is no longer caught. Accepted trade-off: fewer false positives for some missed lookalikes.
- **Aliases also match only as tokens.** `vcb-xacthuc.com` is caught, while `vcbs.com.vn`, `tcbs.vn`, `fbi.gov` are not flagged. An alias glued to another word is missed.
- **Typos on short names slip under the similarity threshold (0.85).** `shoppe` vs `shopee` = 0.83, `mono` vs `momo` = 0.75; both score 0.
- **Brand in userinfo is only caught by the `@` rule.** `vietcombank.com.vn@evil.com` scores 30; the lookalike rule does not inspect the part before `@`.
- **Brand data is maintained by hand** in `data/brands.json`. A wrong or missing official domain flags a legitimate site; aliases are only added once seen in real phishing samples.

## Decisions
- **Reasons and level names are in English** (`dangerous`, `suspicious`, `likely_safe`), unlike the Vietnamese examples in the guide. Any new code (alerts, email analysis) must use `score_to_level()` instead of repeating the thresholds.
- **TPBank:** only `tpb.vn` is listed as official (verified); `tpbank.vn` is intentionally not allowlisted.
- **Single parser path.** `tldextract` is a required dependency; the guide's hand-written fallback was dropped so results cannot differ between machines.
- **Test runner is pytest.** Install with `pip install -r requirements-dev.txt`, run with `python -m pytest` (avoids picking up a global pytest). Existing unittest-style tests run unchanged; new tests use pytest style.
- **Dependencies are split.** `requirements.txt` holds runtime packages only; `requirements-dev.txt` adds test tools.

## To address in upcoming steps
- Step 8: add an `online` flag so tests and email analysis never reach the network by default; SSRF guard should use `ip.is_global` (CGNAT `100.64.0.0/10` passes the current checks); WHOIS failures on `.vn` must not add points.
- Step 8b: normalize URLs before blacklist lookup (case, query string); skip `localhost` / `0.0.0.0` entries in hosts files.
- Step 8e: Tranco allowlist must only disable checks on the registered domain, never the subdomain check (`vietcombank-xacthuc.wordpress.com`).
- Step 9: `to_alert` must handle error results; add `alerts.jsonl` to `.gitignore`.
- Phase 2: reuse `contains_brand` for display-name spoofing and `score_to_level` for email scoring.

## After all steps are done
- **CI (GitHub Actions):** workflow `.github/workflows/tests.yml` that installs `requirements-dev.txt` and runs `pytest` on every push and pull request; add a "tests passing" badge to the README.
- **Repository ruleset for `main`:** require a pull request before merging, require the CI status check to pass, block force pushes and branch deletion.
