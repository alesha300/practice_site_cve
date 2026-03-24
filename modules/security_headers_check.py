"""Security headers analysis and SSL certificate check."""

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone

import aiohttp

from config import HTTP_TIMEOUT, SECURITY_HEADERS, USER_AGENT, parse_target

NAME = "security_headers_check"
DESCRIPTION = "Security headers grading + SSL check"


def _grade_header(name: str, value: str | None, cfg: dict) -> dict:
    """Grade a single security header A-F."""
    if value is None:
        return {"present": False, "grade": "F", "value": None, "note": "Missing"}

    grade = "A"
    note = "Present"

    expected = cfg.get("expected")
    if expected:
        if isinstance(expected, list):
            if not any(e.lower() in value.lower() for e in expected):
                grade, note = "C", f"Unexpected value: {value[:60]}"
        elif isinstance(expected, str):
            if expected.lower() not in value.lower():
                grade, note = "C", f"Expected '{expected}'"

    if name == "Strict-Transport-Security":
        match = re.search(r"max-age=(\d+)", value)
        if match and int(match.group(1)) < 31536000:
            grade, note = "B", f"max-age too low ({match.group(1)})"

    if name == "Content-Security-Policy":
        if "unsafe-inline" in value or "unsafe-eval" in value:
            grade, note = "B", "Contains unsafe directives"

    return {"present": True, "grade": grade, "value": value[:200], "note": note}


def _check_ssl(domain: str) -> dict:
    """Check SSL certificate details."""
    info: dict = {"valid": False, "errors": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    info["errors"].append("No certificate returned")
                    return info
                info["valid"] = True
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["version"] = ssock.version()

                not_after = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)
                not_before = datetime.strptime(
                    cert["notBefore"], "%b %d %H:%M:%S %Y %Z",
                ).replace(tzinfo=timezone.utc)

                info["not_before"] = not_before.isoformat()
                info["not_after"] = not_after.isoformat()
                days = (not_after - datetime.now(timezone.utc)).days
                info["days_remaining"] = days

                if days < 0:
                    info["errors"].append("Certificate has EXPIRED")
                elif days < 30:
                    info["errors"].append(f"Expires in {days} days")

                info["san"] = [
                    v for _, v in cert.get("subjectAltName", [])
                ]
    except ssl.SSLCertVerificationError as e:
        info["errors"].append(f"SSL verification failed: {e}")
    except Exception as e:
        info["errors"].append(f"SSL error: {e}")
    return info


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    domain = info["domain"]
    result: dict = {"status": "success", "data": {}, "errors": []}

    # Fetch response headers
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                response_headers = dict(resp.headers)
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"Failed to fetch: {e}")
        return result

    # Grade each security header
    grades: dict = {}
    total_score = 0
    for header_name, cfg in SECURITY_HEADERS.items():
        value = response_headers.get(header_name)
        grade_info = _grade_header(header_name, value, cfg)
        grades[header_name] = grade_info
        total_score += {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}[grade_info["grade"]]

    max_score = len(SECURITY_HEADERS) * 4
    pct = (total_score / max_score * 100) if max_score else 0
    overall = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 50 else "D" if pct >= 25 else "F"

    result["data"]["headers"] = grades
    result["data"]["overall_grade"] = overall
    result["data"]["score"] = f"{total_score}/{max_score}"

    # SSL certificate check
    result["data"]["ssl"] = await asyncio.to_thread(_check_ssl, domain)
    return result
