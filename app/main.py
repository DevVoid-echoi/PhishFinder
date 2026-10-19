"""HTTP API for the URL checker."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.scorer import analyze

app = FastAPI(title="PhishFinder", version="0.1.0")


class CheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048,
                     examples=["http://vietcombank-xacthuc.com/dang-nhap"])


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/check")
def check(req: CheckRequest):
    result = analyze(req.url)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result
