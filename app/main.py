"""Production API. Run locally: python -m uvicorn app.main:app --reload

The extension decides locally; the server only does what a browser cannot:
domain age (RDAP) and TLS checks, for a hostname, never a full URL.
"""
import logging
import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.api_core import TTLCache, domain_reputation, normalize_host
from app.online import check_domain_age
from app.reputation import check_tls

DEV = os.environ.get("PHISHFINDER_DEV") == "1"

# Interactive docs only in development: in production they map the attack surface for free
app = FastAPI(title="PhishFinder", version="1.0.0",
              docs_url="/docs" if DEV else None, redoc_url=None, openapi_url="/openapi.json" if DEV else None)

# Only the extension may call the API from a browser (its ID is known after publishing).
# CORS does not stop scripts, so rate limiting is still needed at the gateway (step 14).
EXTENSION_ORIGINS = [o for o in os.environ.get("EXTENSION_ORIGIN", "").split(",") if o]
app.add_middleware(CORSMiddleware, allow_origins=EXTENSION_ORIGINS, allow_methods=["GET", "POST"])

cache = TTLCache(ttl_seconds=6 * 3600)
age_cache = TTLCache(ttl_seconds=24*3600)
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
    return {"received": True}