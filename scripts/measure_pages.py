"""Measure page analysis on live pages. Run the measure command inside a virtual machine.

Four commands, so the virtual machine needs only the public code and one small file:
  python -m scripts.measure_pages sample [count]   on your computer, no network: pick the pages
  python -m scripts.measure_pages measure [--ai]   in the VM: download each page, run the page rules
  python -m scripts.measure_pages report           anywhere: print the results again
  python -m scripts.measure_pages labelled         on your computer: today's hand-labelled ChongLuaDao pages

Phishing pages die within days, so measure on the day you sample. Only the rules that fired are
saved, never the HTML. --ai also asks Claude (needs ANTHROPIC_API_KEY, about $0.0005 a page).
"""
import csv
import random
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from pathlib import Path

from app.evaluation import WARN, load_benign, load_phishing
from app.page_analysis import analyze_page
from app.page_features import extract
from app.page_fetch import follow
from app.parser import parse_url
from app.scorer import analyze

EVAL = Path(__file__).resolve().parent.parent / "data" / "eval"
SAMPLE = EVAL / "page_sample.csv"
OUT = EVAL / "pages.csv"
LABELS = EVAL.parent / "raw" / "chongluadao_daily.csv"
FIELDS = ["url", "label", "error", "rules", "points", "ai_answered",
          "has_password", "has_otp_or_card", "text_len", "html_len", "brands_in_title", "title",
          "expected_brand", "expected_asks"]
FRESH_DAYS = 2  # most phishing pages are taken down within a few days
LITTLE_TEXT = 200  # characters: a page this empty is usually built by JavaScript


def one_per_domain(urls: list) -> list:
    """Keep one URL per registered domain, so one large campaign cannot fill the sample."""
    seen, out = set(), []
    for u in sorted(urls):
        domain = parse_url(u).registered_domain
        if domain not in seen:
            seen.add(domain)
            out.append(u)
    return out


def pick_sample(phishing: list, benign: list, today: date, count: int) -> list:
    """(url, label) rows: fresh phishing, benign pages the URL rules already warn about, then
    random benign pages. The warned benign pages are where page analysis must not add an alarm."""
    rng = random.Random(today.isoformat())
    since = (today - timedelta(days=FRESH_DAYS - 1)).isoformat()
    fresh = one_per_domain([u for u, first_seen in phishing if first_seen >= since])
    warned = [u for u in benign if analyze(u, use_blacklist=False)["level"] in WARN]
    warned = rng.sample(warned, min(count // 2, len(warned)))
    others = sorted(set(benign) - set(warned))
    random_benign = rng.sample(others, min(count - len(warned), len(others)))
    rows = [(u, "phishing") for u in rng.sample(fresh, min(count, len(fresh)))]
    rows += [(u, "benign_warned") for u in warned] + [(u, "benign_random") for u in random_benign]
    return rows


def measure_one(url: str, label: str, llm_fn=None) -> dict:
    failed = {"url": url, "label": label, "rules": "", "points": 0, "ai_answered": False}
    try:
        page = follow(url, method="GET")
        if page["error"]:
            return {**failed, "error": page["error"]}
        result = analyze_page(page["html"], page["final"], llm_fn)
        # analyze_page drops the page text, so extract again to measure it
        f = extract(page["html"], page["final"])
    except Exception as e:  # one broken page must not stop a run of 400
        return {**failed, "error": f"Unexpected error: {type(e).__name__}"}
    rules = sorted(r["rule"] for r in result["reasons"])
    return {"url": url, "label": label, "error": "", "rules": ";".join(rules),
            "points": sum(r["points"] for r in result["reasons"]), "ai_answered": result["ai_summary"] is not None,
            "has_password": f["has_password"], "has_otp_or_card": f["has_otp"] or f["has_card"],
            "text_len": len(f["text"]), "html_len": len(page["html"]),
            "brands_in_title": ";".join(f["brands_in_title"]), "title": safe_title(f["title"])}


def safe_title(title: str) -> str:
    """The title is written by the attacker. Spreadsheets run a cell that starts with = + - or @
    as a formula, so such a title gets a leading quote."""
    title = " ".join(title.split())[:80]
    return "'" + title if title[:1] in ("=", "+", "-", "@") else title


def pick_labelled(rows: list, today: str) -> list:
    """Pages copied by hand from ChongLuaDao today, with what their screenshot asks for."""
    return [{"url": r["url"], "label": "phishing_vn", "expected_brand": r["brand"], "expected_asks": r["asks"]}
            for r in rows if r["seen"] == today]


def summarize(rows: list) -> list:
    """Printable lines per label: how many pages downloaded, and how many each layer flagged."""
    lines = []
    for label in ("phishing", "phishing_vn", "benign_warned", "benign_random"):
        group = [r for r in rows if r["label"] == label]
        loaded = [r for r in group if not r["error"]]
        if not group:
            continue
        by_rules = [r for r in loaded if any(not x.startswith("ai_") for x in r["rules"].split(";") if x)]
        by_any = [r for r in loaded if r["rules"]]
        answered = sum(1 for r in loaded if str(r["ai_answered"]) == "True")
        lines.append(f"{label}: {len(loaded)} of {len(group)} pages downloaded; flagged by rules "
                     f"{len(by_rules)}, by rules or AI {len(by_any)}; AI answered {answered}")
        counts = Counter(x for r in loaded for x in r["rules"].split(";") if x)
        lines += [f"  {rule}: {n}" for rule, n in counts.most_common()]
        missed = [r for r in loaded if not r["rules"]]
        if missed:
            password = sum(1 for r in missed if str(r.get("has_password")) == "True")
            empty = sum(1 for r in missed if int(r.get("text_len") or 0) < LITTLE_TEXT)
            lines.append(f"  not flagged {len(missed)}: with a password field {password}, "
                         f"with under {LITTLE_TEXT} characters of text {empty}")
        labelled = [r for r in loaded if r.get("expected_asks")]
        if labelled:
            password = [r for r in labelled if "password" in r["expected_asks"]]
            otp_card = [r for r in labelled if "otp" in r["expected_asks"] or "card" in r["expected_asks"]]
            lines.append(f"  screenshot vs downloaded HTML: password field "
                         f"{sum(1 for r in password if str(r.get('has_password')) == 'True')} of {len(password)}, "
                         f"OTP or card field "
                         f"{sum(1 for r in otp_card if str(r.get('has_otp_or_card')) == 'True')} of {len(otp_card)}")
        errors = Counter(r["error"].split(":")[0] for r in group if r["error"])
        lines += [f"  not downloaded, {err}: {n}" for err, n in errors.most_common()]
    return lines


def read_csv(path: Path) -> list:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, fields: list, rows: list) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "sample":
        count = int(sys.argv[2] if len(sys.argv) > 2 else 200)
        phishing = load_phishing(EVAL / "phishing.csv")
        benign = load_benign(EVAL / "benign.txt", EVAL / "benign_vn.txt")
        rows = pick_sample(phishing, benign, date.today(), count)
        write_csv(SAMPLE, ["url", "label"], [{"url": u, "label": label} for u, label in rows])
        print(f"{len(rows)} pages written to {SAMPLE}: {dict(Counter(label for _, label in rows))}")
    elif command == "measure":
        llm_fn = None
        if "--ai" in sys.argv:
            from app.llm import make_claude_extract
            llm_fn = make_claude_extract()
        jobs = read_csv(SAMPLE)
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(lambda j: {**measure_one(j["url"], j["label"], llm_fn),
                                            "expected_brand": j.get("expected_brand", ""),
                                            "expected_asks": j.get("expected_asks", "")}, jobs))
        write_csv(OUT, FIELDS, rows)
        print("\n".join(summarize(rows)))
    elif command == "labelled":
        rows = pick_labelled(read_csv(LABELS), date.today().isoformat())
        write_csv(SAMPLE, ["url", "label", "expected_brand", "expected_asks"], rows)
        print(f"{len(rows)} pages seen today written to {SAMPLE}")
    elif command == "report":
        print("\n".join(summarize(read_csv(OUT))))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
