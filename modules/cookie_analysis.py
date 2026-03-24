"""Cookie security analysis."""

import asyncio

import aiohttp

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "cookie_analysis"
DESCRIPTION = "Cookie security flags analysis"


def _parse_cookie(set_cookie: str) -> dict:
    """Parse a Set-Cookie header into structured info."""
    parts = [p.strip() for p in set_cookie.split(";")]
    name_val = parts[0] if parts else ""
    name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val

    flags_lower = [p.lower().strip() for p in parts[1:]]
    attrs = {p.split("=", 1)[0].strip(): p.split("=", 1)[1].strip() if "=" in p else True for p in flags_lower}

    secure = "secure" in attrs
    httponly = "httponly" in attrs
    samesite = attrs.get("samesite", "not set")
    if isinstance(samesite, bool):
        samesite = "empty"

    # Grade
    issues: list[str] = []
    if not secure:
        issues.append("Missing Secure flag")
    if not httponly:
        issues.append("Missing HttpOnly flag")
    if samesite in ("not set", "none", "empty"):
        issues.append(f"SameSite={samesite}")

    if not issues:
        grade = "A"
    elif len(issues) == 1:
        grade = "B"
    elif len(issues) == 2:
        grade = "C"
    else:
        grade = "F"

    return {
        "name": name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "grade": grade,
        "issues": issues,
    }


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    cookies: list[dict] = []

    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True, ssl=False,
            ) as resp:
                for header_val in resp.headers.getall("Set-Cookie", []):
                    cookies.append(_parse_cookie(header_val))
    except Exception as e:
        result["errors"].append(f"Request failed: {e}")
        result["status"] = "error"
        return result

    result["data"]["cookies"] = cookies
    result["data"]["total"] = len(cookies)

    insecure = [c for c in cookies if c["grade"] in ("C", "F")]
    result["data"]["insecure_count"] = len(insecure)

    if not cookies:
        result["data"]["note"] = "No cookies set by server"
    elif insecure:
        result["data"]["note"] = f"{len(insecure)}/{len(cookies)} cookies have security issues"
    else:
        result["data"]["note"] = "All cookies have proper security flags"

    return result
