# Development Notes

Known limitations and design decisions found while building phase 1.
These feed the "Known limitations" section of the README.

## Known limitations

### Parser (`app/parser.py`)
- **Hand-written suffix list.** Only a few two-level suffixes (`com.vn`, `edu.vn`, ...) are recognized; others such as `ac.vn`, `info.vn`, `com.au` are split incorrectly. Planned fix: `tldextract` with the Public Suffix List (step 4b).
- **IP hosts produce meaningless fields.** `http://192.168.1.10` gives `registered_domain='1.10'`, `suffix='10'`. Harmless today because `check_ip_host` reads `hostname`, but any rule using `suffix` or `registered_domain` must keep this in mind.
- **Single-label hosts.** `localhost` gives `suffix='localhost'`.
- **Port is ignored.** `urlparse` moves the port to `parts.port`; it is not stored. Possible future rule: non-standard port on a brand-like domain.
- **Unknown schemes are not flagged.** `ttps://`, `javascript:`, `data:` pass through; `check_no_https` only fires on exactly `http`. Found when a typo (`ttps://`) in a test still passed.

### Heuristics (`app/heuristics.py`)
- **Keyword matching is substring-based.** `login` in `github.com/login` adds 10 points to a legitimate page (low impact, stays below the threshold).
- **Weights are initial estimates**, not tuned on data.

### Lookalike detection (`app/lookalike.py`)
- **Short brands (<= 5 chars) only match as separate tokens.** Fixes false positives such as `zalora.com`, `tikitaka.com`, `bidvietnam.com`, but `momoshop.com` is no longer caught. Accepted trade-off: fewer false positives for some missed lookalikes.
- **Typos on short names slip under the similarity threshold (0.85).** `shoppe` vs `shopee` = 0.83, `mono` vs `momo` = 0.75; both score 0.
- **Brand in userinfo is only caught by the `@` rule.** `vietcombank.com.vn@evil.com` scores 30; the lookalike rule does not inspect the part before `@`.
- **Official domain list is maintained by hand.** A wrong or missing entry flags a legitimate site.

## Decisions
- **Reasons and level names are in English** (`dangerous`, `suspicious`, `likely_safe`), unlike the Vietnamese examples in the guide. Any new code (alerts, email analysis) must use these names.
- **TPBank:** only `tpb.vn` is listed as official (verified); `tpbank.vn` is intentionally not allowlisted.

## To address in upcoming steps
- Step 4b: `tldextract` offline (`suffix_list_urls=()`), add `score_to_level()` shared by URL and email scoring.
- Step 8: add an `online` flag so tests and email analysis never reach the network by default; SSRF guard should use `ip.is_global` (CGNAT `100.64.0.0/10` passes the current checks); WHOIS failures on `.vn` must not add points.
- Step 8b: normalize URLs before blacklist lookup (case, query string); skip `localhost` / `0.0.0.0` entries in hosts files.
- Step 8e: Tranco allowlist must only disable checks on the registered domain, never the subdomain check (`vietcombank-xacthuc.wordpress.com`).
- Step 9: `to_alert` must handle error results; add `alerts.jsonl` to `.gitignore`.
- Phase 2: reuse `contains_brand` for display-name spoofing.
