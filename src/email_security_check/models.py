from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class DKIMInfo(BaseModel):
    selector: str
    name: str
    present: bool
    raw: Optional[str]
    key_type: Optional[str]
    key_bits_approx: Optional[int]
    has_pub: Optional[bool]

class SPFDetail(BaseModel):
    raw: str
    includes: List[str]
    redirect: Optional[str]
    lookup_mechanisms: List[str]
    all_mechanism: Optional[str]

class Report(BaseModel):
    domain: str
    time_utc: str
    spf: Dict[str, Any]
    dmarc: Dict[str, Any]
    dkim: Dict[str, Any]
    conclusions: Dict[str, Any]
    elapsed_seconds: float