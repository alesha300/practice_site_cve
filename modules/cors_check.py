"""CORS misconfiguration detection."""

import asyncio

import aiohttp

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "cors_check"
DESCRIPTION = "CORS misconfiguration check"

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


async def _test_origin(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
) -> dict:
    """Send request with a specific Origin and analyze CORS response."""
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
            headers=headers,
            allow_redirects=True, ssl=False,
        ) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            methods = resp.headers.get("Access-Control-Allow-Methods", "")

            misconfigured = False
            issues: list[str] = []

            if acao == origin:
                misconfigured = True
                issues.append(f"Reflects arbitrary origin: {origin}")
            if acao == "*" and acac.lower() == "true":
                misconfigured = True
                issues.append("Wildcard origin with credentials allowed")
            if acao == "null":
                misconfigured = True
                issues.append("Allows null origin")

            return {
                "origin_sent": origin,
                "acao": acao,
                "credentials": acac,
                "methods": methods,
                "misconfigured": misconfigured,
                "issues": issues,
            }
    except Exception as e:
        return {"origin_sent": origin, "error": str(e), "misconfigured": False, "issues": []}


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    tests: list[dict] = []

    try:
        async with aiohttp.ClientSession() as session:
            for origin in TEST_ORIGINS:
                test = await _test_origin(session, base_url, origin)
                tests.append(test)
    except Exception as e:
        result["errors"].append(f"CORS check failed: {e}")

    result["data"]["tests"] = tests

    any_misconfig = any(t.get("misconfigured") for t in tests)
    all_issues = [i for t in tests for i in t.get("issues", [])]
    result["data"]["misconfigured"] = any_misconfig
    result["data"]["issues"] = all_issues

    if any_misconfig:
        result["data"]["grade"] = "F"
        result["data"]["note"] = "CORS misconfiguration detected — potential data theft"
    else:
        result["data"]["grade"] = "A"
        result["data"]["note"] = "No CORS misconfiguration found"

    if result["errors"]:
        result["status"] = "partial"
    return result
