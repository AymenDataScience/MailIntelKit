from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

from .core import generate_report

app = FastAPI(title="email-security-check", version="0.1.0")

class ReportRequest(BaseModel):
    domain: str
    aggressive_dkim: Optional[bool] = False

@app.post("/report")
async def report(req: ReportRequest):
    try:
        data = await generate_report(req.domain.strip(), aggressive_dkim=bool(req.aggressive_dkim))
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))