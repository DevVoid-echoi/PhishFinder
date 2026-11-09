"""Production API. Run locally: python -m uvicorn app.main:app --reload

The extension decides locally; the server only does what a browser cannot:
domain age (RDAP) and TLS checks, for a hostname, never a full URL. The one exception is
/v1/analyze-page, which the user must turn on in the extension.
"""
import hashlib
import json
import logging
import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.alert import to_alert
from app.api_core import (DailyBudget,
                          TTLCache,
                          domain_reputation,
                          normalize_host,
                          normalize_page_url,
                          normalize_short_url)
from app.llm import make_claude_extract
from app.online import check_domain_age
from app.page_analysis import analyze_page
from app.page_fetch import follow
from app.reputation import check_tls

DEV = os.environ.get("PHISHFINDER_DEV") == "1"

# Interactive docs only in development: in production they map the attack surface for free
app = FastAPI(title="PhishFinder", version="1.0.0",
              docs_url="/docs" if DEV else None, redoc_url=None, openapi_url="/openapi.json" if DEV else None)

# Only the extension may call the API from a browser (its ID is known after publishing).
# CORS does not stop scripts, so rate limiting is still needed at the gateway.
EXTENSION_ORIGINS = [o for o in os.environ.get("EXTENSION_ORIGIN", "").split(",") if o]
app.add_middleware(CORSMiddleware, allow_origins=EXTENSION_ORIGINS, allow_methods=["GET", "POST"])

cache = TTLCache(ttl_seconds=6 * 3600)
age_cache = TTLCache(ttl_seconds= 24 * 3600)
expand_cache = TTLCache(ttl_seconds=6 * 3600, max_items=5000)
page_cache = TTLCache(ttl_seconds=6 * 3600, max_items=2000)
ai_budget = DailyBudget(limit=int(os.environ.get("DAILY_AI_LIMIT", "300")))
# Without a key, page analysis still runs its fixed rules
claude_extract = make_claude_extract() if os.environ.get("ANTHROPIC_API_KEY") else None
log = logging.getLogger("phishfinder")


@app.get("/v1/health")
def health():
    return {"status": "ok"}

@app.get("/v1/reputation")
def reputation(host: str = Query(..., max_length=253)):
    try:
        host = normalize_host(host)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    result = domain_reputation(host, check_domain_age, check_tls, cache, age_cache)
    # Count only: a hostname next to a client IP would be that user's browsing history
    log.info("reputation cached=%s findings=%d", result["cached"], len(result["reasons"]))
    return result

@app.get("/v1/expand")
def expand(url: str = Query(..., max_length=200)):
    """Where does a short link lead? Only links of known shorteners are accepted."""
    try:
        url = normalize_short_url(url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    cached = expand_cache.get(url)
    if cached is not None:
        return {**cached, "cached": True}
    r = follow(url, method="HEAD")
    result = {"final": r["final"], "chain": r["chain"], "status": r.get("status"), "error": r["error"]}
    expand_cache.set(url, result)
    log.info("expand hops=%d ok=%s", len(r["chain"]) - 1, r["final"] is not None)
    return {**result, "cached": False}

class Report(BaseModel):
    host: str = Field(..., max_length=253)
    shown_level: str = Field(..., pattern="^(dangerous|suspicious)$")
    verdict: str = Field(..., pattern="^(false_positive|confirmed_phishing)$")
    extension_version: str = Field(..., max_length=20, pattern=r"^[0-9]+(\.[0-9]+){0,3}$")

@app.post("/v1/report")
def report(r: Report):
    try:
        host = normalize_host(r.host)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # First version: read the log daily. The host is validated, so it cannot inject log lines.
    log.warning("REPORT %s %s %s v%s", r.verdict, r.shown_level, host, r.extension_version)
    if r.verdict == "confirmed_phishing":
        # A user report is never more than medium: users can be wrong or report a rival on purpose
        alert = to_alert(
            {"url": host, "domain": host, "level": "suspicious",
             "reasons": [{"rule": "user_report", "points": 0,
                          "reason": f"Extension user confirmed phishing (shown as {r.shown_level})"}]},
            observables=[{"type": "domain", "value": host}],
        )
        log.warning("ALERT %s", json.dumps(alert, ensure_ascii=False))
    return {"received": True}

class PageRequest(BaseModel):
    url: str = Field(..., max_length=2048)

@app.post("/v1/analyze-page")
def analyze_page_api(req: PageRequest):
    """Deep analysis of one page, only after the user turns it on: the full URL leaves the browser.
    The URL is never logged, and the cache keeps its hash, not the URL itself."""
    try:
        url = normalize_page_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    key = hashlib.sha256(url.encode()).hexdigest()
    cached = page_cache.get(key)
    if cached is not None:
        return {**cached, "cached": True}
    page = follow(url, method="GET")
    if page["error"]:
        log.info("analyze-page fetch failed")
        return {"reasons": [], "ai_summary": None, "error": page["error"], "cached": False}
    llm = ai_budget.limit_calls(claude_extract) if claude_extract else None
    analysis = analyze_page(page["html"], page["final"], llm)
    result = {"reasons": analysis["reasons"], "ai_summary": analysis["ai_summary"], "error": None}
    page_cache.set(key, result)
    log.info("analyze-page findings=%d ai=%s", len(result["reasons"]), result["ai_summary"] is not None)
    return {**result, "cached": False}
