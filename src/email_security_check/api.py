from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional

from .core import generate_report, human_report
from . import dns_utils

app = FastAPI(title="email-security-check", version="0.1.0")


class ReportRequest(BaseModel):
    domain: str
    aggressive_dkim: Optional[bool] = False


@app.get("/health")
async def health():
    """Simple health check endpoint."""
    return {"status": "ok", "service": "email-security-check"}





@app.get("/spf/{domain}")
async def get_spf(domain: str):
    """Return parsed SPF records and details for a domain."""
    try:
        spfs = await dns_utils.get_spf_records(domain.strip())
        details = [dns_utils.parse_spf(s) for s in spfs]
        # resolve lookup counts for each spf record (use resolve_spf_lookups)
        resolved = []
        total_lookup = 0
        errors = []
        for s in spfs:
            r, lookup_count, errs = await dns_utils.resolve_spf_lookups(domain.strip(), s)
            resolved.append(list(r))
            total_lookup += lookup_count
            errors.extend(errs)
        return {"domain": domain, "spf": {"records": spfs, "details": details, "resolved_includes": resolved, "estimated_dns_lookup_count": total_lookup, "errors": errors}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dkim/{domain}")
async def get_dkim(domain: str, selector: Optional[str] = Query(None), aggressive: Optional[bool] = Query(False)):
    """Return DKIM selector info.

    If 'selector' is provided, check that selector only. Otherwise run a heuristic discovery.
    Optional query param 'aggressive' expands selector list.
    """
    try:
        if selector:
            info = await dns_utils.check_dkim_selector(domain.strip(), selector.strip())
            return {"domain": domain, "selector": selector, "info": info}
        else:
            infos = await dns_utils.discover_dkim_selectors(domain.strip(), aggressive=bool(aggressive))
            return {"domain": domain, "found_selectors": infos, "aggressive_checked": bool(aggressive)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dmarc/{domain}")
async def get_dmarc(domain: str):
    """Return the DMARC TXT record and parsed tags for a domain."""
    try:
        rec = await dns_utils.get_dmarc_record(domain.strip())
        tags = dns_utils.parse_dmarc(rec) if rec else {}
        return {"domain": domain, "dmarc_raw": rec, "dmarc_tags": tags}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/report")
async def report(req: ReportRequest):
    try:
        data = await generate_report(req.domain.strip(), aggressive_dkim=bool(req.aggressive_dkim))
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))