"""Dangerous HTTP methods detection."""

import asyncio

import aiohttp

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "http_methods"
DESCRIPTION = "HTTP methods enumeration"

DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "PATCH", "CONNECT"]
ALL_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    allowed: list[str] = []
    dangerous: list[str] = []

    # 1) Try OPTIONS to get Allow header
    try:
        async with aiohttp.ClientSession() as session:
            async with session.options(
                base_url,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True, ssl=False,
            ) as resp:
                allow_header = resp.headers.get("Allow", "")
                if allow_header:
                    allowed = [m.strip().upper() for m in allow_header.split(",")]
    except Exception:
        pass

    # 2) Probe each method directly
    probed: dict[str, int] = {}
    try:
        async with aiohttp.ClientSession() as session:
            for method in ALL_METHODS:
                try:
                    async with session.request(
                        method, base_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        headers={"User-Agent": USER_AGENT},
                        allow_redirects=True, ssl=False,
                    ) as resp:
                        probed[method] = resp.status
                        if resp.status not in (405, 501) and method not in allowed:
                            allowed.append(method)
                except Exception:
                    probed[method] = 0
    except Exception as e:
        result["errors"].append(f"Method probing failed: {e}")

    # Identify dangerous methods
    for method in DANGEROUS_METHODS:
        if method in allowed:
            dangerous.append(method)

    result["data"]["allowed_methods"] = sorted(set(allowed))
    result["data"]["probed"] = probed
    result["data"]["dangerous"] = dangerous

    if dangerous:
        result["data"]["grade"] = "F"
        result["data"]["note"] = f"Dangerous methods enabled: {', '.join(dangerous)}"
    else:
        result["data"]["grade"] = "A"
        result["data"]["note"] = "No dangerous methods detected"

    return result
