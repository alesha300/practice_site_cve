"""Email security: SPF, DKIM, DMARC record analysis."""

import asyncio

import requests

from config import DNS_TIMEOUT, parse_target

NAME = "email_security"
DESCRIPTION = "SPF / DKIM / DMARC email security"

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


def _dns_txt(domain: str, timeout: float) -> list[str]:
    """Fetch TXT records via Google DoH."""
    resp = requests.get(
        "https://dns.google/resolve",
        params={"name": domain, "type": "TXT"},
        timeout=timeout,
        headers={"Accept": "application/dns-json"},
    )
    if resp.status_code != 200:
        return []
    return [a["data"].strip('"') for a in resp.json().get("Answer", []) if "data" in a]


def _grade_spf(records: list[str]) -> dict:
    spf = [r for r in records if r.startswith("v=spf1")]
    if not spf:
        return {"present": False, "grade": "F", "value": None, "note": "No SPF record"}
    record = spf[0]
    grade, note = "A", "SPF present"
    if "+all" in record:
        grade, note = "F", "SPF allows all senders (+all)"
    elif "~all" in record:
        grade, note = "B", "Softfail (~all) — emails from unauthorized senders accepted but marked"
    elif "-all" not in record and "?all" in record:
        grade, note = "C", "Neutral policy (?all)"
    return {"present": True, "grade": grade, "value": record, "note": note}


def _grade_dmarc(records: list[str]) -> dict:
    dmarc = [r for r in records if r.startswith("v=DMARC1")]
    if not dmarc:
        return {"present": False, "grade": "F", "value": None, "note": "No DMARC record"}
    record = dmarc[0]
    grade, note = "A", "DMARC present"
    if "p=none" in record:
        grade, note = "C", "Policy is 'none' — no enforcement"
    elif "p=quarantine" in record:
        grade, note = "B", "Policy is 'quarantine'"
    return {"present": True, "grade": grade, "value": record, "note": note}


async def run(target: str) -> dict:
    info = parse_target(target)
    domain = info["domain"]
    result: dict = {"status": "success", "data": {}, "errors": []}

    # SPF
    try:
        txt_records = await asyncio.to_thread(_dns_txt, domain, DNS_TIMEOUT)
        result["data"]["spf"] = _grade_spf(txt_records)
    except Exception as e:
        result["errors"].append(f"SPF check error: {e}")

    # DMARC
    try:
        dmarc_records = await asyncio.to_thread(_dns_txt, f"_dmarc.{domain}", DNS_TIMEOUT)
        result["data"]["dmarc"] = _grade_dmarc(dmarc_records)
    except Exception as e:
        result["errors"].append(f"DMARC check error: {e}")

    # DKIM — try common selectors
    dkim_found: list[dict] = []
    for selector in DKIM_SELECTORS:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            records = await asyncio.to_thread(_dns_txt, dkim_domain, DNS_TIMEOUT)
            if records:
                dkim_found.append({"selector": selector, "value": records[0][:200]})
        except Exception:
            pass

    result["data"]["dkim"] = {
        "found": bool(dkim_found),
        "selectors": dkim_found,
        "grade": "A" if dkim_found else "F",
        "note": f"Found {len(dkim_found)} selector(s)" if dkim_found else "No DKIM selectors found",
    }

    if result["errors"]:
        result["status"] = "partial"
    return result
