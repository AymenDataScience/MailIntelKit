import time
from typing import Dict, List, Optional

from . import dns_utils

def score_and_conclusions(spf_records: List[str], spf_details: List[Dict],
                          spf_lookup_count: int, spf_errors: List[str],
                          dmarc_text: Optional[str], dmarc_tags: Dict,
                          dkim_infos: List[Dict]) -> Dict:
    score = 100
    reasons = []

    if not spf_records:
        score -= 40
        reasons.append("No SPF record found (high risk of spoofing).")
    else:
        if len(spf_records) > 1:
            score -= 30
            reasons.append("Multiple SPF records found (invalid SPF configuration).")
        for d in spf_details:
            all_mech = d.get("all_mechanism")
            if not all_mech:
                reasons.append("SPF record has no 'all' mechanism - may allow unintended senders.")
                score -= 5
            else:
                if all_mech.lower() == "+all":
                    score -= 25
                    reasons.append("SPF uses +all (permits everything) — critical misconfiguration.")
                elif all_mech.lower() == "?all":
                    score -= 10
                    reasons.append("SPF uses ?all (neutral) — weak protection.")
                elif all_mech.lower() == "~all":
                    score -= 3
                    reasons.append("SPF uses ~all (softfail) — allows some leeway.")
                elif all_mech.lower() == "-all":
                    reasons.append("SPF uses -all (reject) — strict, good.")
        if spf_lookup_count > dns_utils.SPF_DNS_LOOKUP_LIMIT:
            score -= 20
            reasons.append(f"SPF mechanisms likely cause {spf_lookup_count} DNS lookups (> {dns_utils.SPF_DNS_LOOKUP_LIMIT}). This can break SPF enforcement.")
        elif spf_lookup_count > (dns_utils.SPF_DNS_LOOKUP_LIMIT - 3):
            score -= 7
            reasons.append(f"SPF mechanisms cause {spf_lookup_count} DNS lookups (close to limit).")

    if not dmarc_text:
        score -= 30
        reasons.append("No DMARC record found (no domain-wide policy for unauthenticated mail).")
    else:
        p = dmarc_tags.get("p", "").lower()
        if p == "none" or p == "":
            score -= 10
            reasons.append("DMARC policy p=none (monitoring only). Consider p=quarantine or p=reject.")
        elif p == "quarantine":
            score -= 3
            reasons.append("DMARC policy p=quarantine (moderate).")
        elif p == "reject":
            reasons.append("DMARC policy p=reject (strong).")
        try:
            pct = int(dmarc_tags.get("pct", "100"))
        except Exception:
            pct = 100
        if pct < 100:
            score -= 5
            reasons.append(f"DMARC pct={pct} (not applied to all mail).")
        if "rua" not in dmarc_tags:
            reasons.append("No RUA (aggregate) reporting configured (you won't get aggregate reports).")
            score -= 3

    if not dkim_infos:
        reasons.append("No DKIM selectors found using heuristics (may not use DKIM).")
        score -= 10
    else:
        for kinfo in dkim_infos:
            if kinfo.get("key_bits_approx"):
                bits = kinfo["key_bits_approx"]
                if bits < 1024:
                    score -= 10
                    reasons.append(f"DKIM selector {kinfo['selector']} has a weak public key (~{bits} bits estimated).")
                elif bits < 2048:
                    score -= 3
                    reasons.append(f"DKIM selector {kinfo['selector']} uses ~{bits} bits (consider 2048).")
                else:
                    reasons.append(f"DKIM selector {kinfo['selector']} key size looks OK (~{bits} bits).")

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return {"score": score, "reasons": reasons}

# convert generate_report to async and await dns helpers
async def generate_report(domain: str, aggressive_dkim: bool = False) -> Dict:
    t0 = time.time()
    out = {"domain": domain, "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # SPF
    spf_records = await dns_utils.get_spf_records(domain)
    out["spf"] = {"records": spf_records}
    spf_details = []
    total_lookup_count = 0
    spf_errors = []
    for s in spf_records:
        parsed = dns_utils.parse_spf(s)
        spf_details.append(parsed)
        resolved, lookup_count, errors = await dns_utils.resolve_spf_lookups(domain, s)
        total_lookup_count += lookup_count
        spf_errors.extend(errors)
    out["spf"]["details"] = spf_details
    out["spf"]["estimated_dns_lookup_count"] = total_lookup_count
    out["spf"]["errors"] = spf_errors

    # DMARC
    dmarc_text = await dns_utils.get_dmarc_record(domain)
    out["dmarc"] = {"raw": dmarc_text}
    if dmarc_text:
        parsed = dns_utils.parse_dmarc(dmarc_text)
        out["dmarc"]["tags"] = parsed
    else:
        out["dmarc"]["tags"] = {}

    # DKIM (discover selectors)
    dkim_infos = await dns_utils.discover_dkim_selectors(domain, aggressive=aggressive_dkim)
    out["dkim"] = {"found_selectors": dkim_infos, "aggressive_checked": aggressive_dkim}

    # Scoring and conclusions
    conclusions = score_and_conclusions(spf_records, spf_details, total_lookup_count, spf_errors,
                                        dmarc_text, out["dmarc"]["tags"], dkim_infos)
    out["conclusions"] = conclusions

    out["elapsed_seconds"] = round(time.time() - t0, 2)
    return out

def human_report(result: Dict) -> str:
    lines = []
    d = result
    lines.append(f"Email authentication report for: {d['domain']}")
    lines.append(f"Checked at (UTC): {d['time_utc']}")
    lines.append("-" * 60)
    lines.append("SPF:")
    if not d["spf"]["records"]:
        lines.append("  - No SPF TXT record found.")
    else:
        for i, r in enumerate(d["spf"]["records"], 1):
            lines.append(f"  - Record #{i}: {r}")
        lines.append(f"  - Estimated DNS-lookup-like mechanisms: {d['spf']['estimated_dns_lookup_count']}")
        if d["spf"]["errors"]:
            for e in d["spf"]["errors"]:
                lines.append(f"    ! error: {e}")
        for pd in d["spf"]["details"]:
            if pd.get("all_mechanism"):
                lines.append(f"  - SPF 'all' mechanism: {pd['all_mechanism']}")
    lines.append("")
    lines.append("DMARC:")
    if not d["dmarc"]["raw"]:
        lines.append("  - No DMARC record (no _dmarc.domain TXT).")
    else:
        lines.append(f"  - DMARC record: {d['dmarc']['raw']}")
        for k, v in d["dmarc"]["tags"].items():
            lines.append(f"    - {k} = {v}")
    lines.append("")
    lines.append("DKIM:")
    if not d["dkim"]["found_selectors"]:
        lines.append("  - No DKIM selectors found with heuristic list.")
        if not d["dkim"]["aggressive_checked"]:
            lines.append("    (you can try --aggressive-dkim to search more selectors)")
    else:
        for info in d["dkim"]["found_selectors"]:
            lines.append(f"  - Selector: {info['selector']} (DNS name: {info['name']})")
            if info.get("key_bits_approx"):
                lines.append(f"    - approx key bits: {info['key_bits_approx']}")
            if info.get("key_type"):
                lines.append(f"    - key type: {info['key_type']}")
            lines.append(f"    - raw TXT (first 200 chars): {info.get('raw', '')[:200]}")
    lines.append("")
    lines.append("Summary & score:")
    lines.append(f"  - Score (0-100): {d['conclusions']['score']}")
    for r in d["conclusions"]["reasons"]:
        lines.append(f"    - {r}")
    lines.append("-" * 60)
    lines.append(f"Elapsed time: {d.get('elapsed_seconds', '?')}s")
    return "\n".join(lines)