import re
from typing import Dict, List, Optional, Set, Tuple

import dns.exception
import dns.asyncresolver

# ---------- Configuration ----------
DNS_TIMEOUT = 5.0  # seconds
SPF_DNS_LOOKUP_LIMIT = 10
MAX_INCLUDE_RECURSION = 10
DEFAULT_DKIM_SELECTORS = [
    "default", "selector1", "s1", "google", "google1", "mail", "smtp", "dkim",
    "mx", "selector", "k1", "k2", "mta"
]
AGGRESSIVE_DKIM_SELECTORS_A = [
    "default", "selector", "selector1", "selector2", "s1", "s2", "google",
    "google1", "google2","mta","amazonses", "mail", "smtp", "dkim", "mx", "k1",
    "k2", "201608", "2019", "2020", "2021", "2022", "mail1", "mail2", "smtp1"
]
AGGRESSIVE_DKIM_SELECTORS = [
    "default","selector", "selector1", "selector2","s","s1","s2","sel","mail","smtp","mx",
    "dkim","k","key","google","google1","google2","mta","amazonses","k1",
    "k2", "201608", "2019", "2020", "2021", "2022","mail1", "mail2", "smtp1",
    "sendgrid","mailgun","mandrill","zoho","outlook","office","o365","microsoft","sparkpost",
    "postfix","postmark","mailchimp","ses","sendinblue","elasticemail","yandex","icloud",
    "protonmail","fastmail","gws","gapp","domainkey","email","hosted","secure","info","securemail"
]
# -----------------------------------

# use dnspython async resolver
resolver = dns.asyncresolver.Resolver()
resolver.lifetime = DNS_TIMEOUT
resolver.timeout = DNS_TIMEOUT

async def dns_query_txt(name: str) -> List[str]:
    """Async: return list of TXT strings for a DNS name, or empty list."""
    try:
        answers = await resolver.resolve(name, "TXT")
        txts: List[str] = []
        for r in answers:
            try:
                # dnspython v2: r.strings is a list of byte-strings
                txt = b"".join(r.strings).decode("utf-8", errors="replace")
            except Exception:
                txt = str(r.to_text()).strip('"')
            txts.append(txt)
        return txts
    except (dns.asyncresolver.NoAnswer, dns.asyncresolver.NXDOMAIN, dns.exception.DNSException):
        return []

async def get_spf_records(domain: str) -> List[str]:
    """Async: return list of SPF strings (TXT records that start with v=spf1)."""
    txts = await dns_query_txt(domain)
    spfs = [t for t in txts if t.strip().lower().startswith("v=spf1")]
    return spfs

SPF_INCLUDE_RE = re.compile(r"\binclude:([^\s]+)", re.I)
SPF_REDIRECT_RE = re.compile(r"\bredirect=([^\s]+)", re.I)
SPF_MECHANISM_LOOKUP_RE = re.compile(
    r"\b(?:include:[^\s]+|exists:[^\s]+|ptr\b|mx\b|a\b|redirect=[^\s]+)", re.I
)
SPF_ALL_RE = re.compile(r"\b(?:~all|-all|\+all|\?all)\b", re.I)

def parse_spf(spf_text: str) -> Dict:
    """Parse SPF string into its components and find includes/redirects/mechanisms."""
    record = {"raw": spf_text}
    includes = SPF_INCLUDE_RE.findall(spf_text)
    redirect = SPF_REDIRECT_RE.findall(spf_text)
    lookup_mechanisms = SPF_MECHANISM_LOOKUP_RE.findall(spf_text)
    all_match = SPF_ALL_RE.search(spf_text)
    record.update(
        {
            "includes": includes,
            "redirect": redirect[0] if redirect else None,
            "lookup_mechanisms": lookup_mechanisms,
            "all_mechanism": all_match.group(0) if all_match else None,
        }
    )
    return record

async def resolve_spf_lookups(domain: str, spf_text: str, max_recursion=MAX_INCLUDE_RECURSION
                        ) -> Tuple[Set[str], int, List[str]]:
    """
    Async: Follow include: recursively and count DNS-lookup-like mechanisms.
    Returns (set_of_resolved_domains, total_lookup_count, errors_list)
    """
    resolved: Set[str] = set()
    visited: Set[str] = set()
    errors: List[str] = []
    lookup_count = 0

    async def _recurse(name: str, txt: str, depth: int):
        nonlocal lookup_count
        if depth > max_recursion:
            errors.append(f"spf include recursion depth exceeded at {name}")
            return
        mechs = SPF_MECHANISM_LOOKUP_RE.findall(txt)
        lookup_count += len(mechs)
        for inc in SPF_INCLUDE_RE.findall(txt):
            inc = inc.strip()
            if inc in visited:
                continue
            visited.add(inc)
            try:
                inc_txts = await dns_query_txt(inc)
                found_spf = [t for t in inc_txts if t.strip().lower().startswith("v=spf1")]
                resolved.add(inc)
                if found_spf:
                    for s in found_spf:
                        await _recurse(inc, s, depth + 1)
            except Exception as e:
                errors.append(f"error resolving include {inc}: {e}")

    await _recurse(domain, spf_text, 0)
    return resolved, lookup_count, errors

async def get_dmarc_record(domain: str) -> Optional[str]:
    name = f"_dmarc.{domain}"
    txts = await dns_query_txt(name)
    for t in txts:
        if t.strip().lower().startswith("v=dmarc1"):
            return t
    return None

DMARC_TAG_RE = re.compile(r"([a-zA-Z0-9_]+)=([^;]+)")

def parse_dmarc(dmarc_text: str) -> Dict:
    """Parse DMARC record into tag:value dict."""
    tags = {}
    try:
        parts = [p.strip() for p in dmarc_text.split(";")]
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                tags[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return tags

async def check_dkim_selector(domain: str, selector: str) -> Dict:
    """
    Async: Query selector._domainkey.domain for TXT. Return info dict with present flag and
    parsed key-type and key length if possible.
    """
    name = f"{selector}._domainkey.{domain}"
    txts = await dns_query_txt(name)
    info = {"selector": selector, "name": name, "present": False, "raw": None, "key_type": None,
            "key_bits_approx": None, "has_pub": False}
    if not txts:
        return info
    dkim_txt = None
    for t in txts:
        if "v=DKIM1" in t or "p=" in t:
            dkim_txt = t
            break
    if not dkim_txt:
        dkim_txt = txts[0]
    info["present"] = True
    info["raw"] = dkim_txt
    m_p = re.search(r"\bp=([^;]+)", dkim_txt)
    if m_p:
        pub = m_p.group(1).strip()
        info["has_pub"] = bool(pub and pub != "-")
        if info["has_pub"]:
            cleaned = re.sub(r"\s+", "", pub)
            try:
                b64_len = len(cleaned)
                bits = int(b64_len * 6)
                info["key_bits_approx"] = bits
            except Exception:
                pass
    k = re.search(r"\bk=([^;]+)", dkim_txt)
    if k:
        info["key_type"] = k.group(1).strip()
    return info

async def discover_dkim_selectors(domain: str, aggressive: bool = False) -> List[Dict]:
    selectors = AGGRESSIVE_DKIM_SELECTORS if aggressive else DEFAULT_DKIM_SELECTORS
    found: List[Dict] = []
    # sequential to avoid high query burst; caller can run concurrently if desired
    for sel in selectors:
        info = await check_dkim_selector(domain, sel)
        if info["present"]:
            found.append(info)
    return found