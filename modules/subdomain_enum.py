"""Subdomain enumeration via Certificate Transparency logs."""

import asyncio

import aiohttp

from config import MAX_CONCURRENT_REQUESTS, USER_AGENT, parse_target

NAME = "subdomain_enum"
DESCRIPTION = "Subdomain enumeration via crt.sh"

MAX_SUBDOMAINS = 500
MAX_LIVE_CHECK = 100


async def _check_alive(
    session: aiohttp.ClientSession,
    sub: str,
    sem: asyncio.Semaphore,
) -> dict | None:
    async with sem:
        for scheme in ("https", "http"):
            try:
                async with session.get(
                    f"{scheme}://{sub}",
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=True,
                    headers={"User-Agent": USER_AGENT},
                    ssl=False,
                ) as resp:
                    return {"subdomain": sub, "status": resp.status, "scheme": scheme}
            except Exception:
                continue
    return None


async def run(target: str) -> dict:
    info = parse_target(target)
    domain = info["domain"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    subdomains: set[str] = set()

    # Query crt.sh Certificate Transparency
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    for entry in data:
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name and name.endswith(domain) and "*" not in name:
                                subdomains.add(name)
                else:
                    result["errors"].append(f"crt.sh returned status {resp.status}")
    except Exception as e:
        result["errors"].append(f"crt.sh error: {e}")

    sorted_subs = sorted(subdomains)[:MAX_SUBDOMAINS]
    result["data"]["subdomains_found"] = sorted_subs
    result["data"]["total_found"] = len(subdomains)

    # Check which subdomains are live
    check_subs = sorted_subs[:MAX_LIVE_CHECK]
    live: list[dict] = []
    sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    if check_subs:
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [_check_alive(session, sub, sem) for sub in check_subs]
            results_list = await asyncio.gather(*tasks, return_exceptions=True)
            live = [r for r in results_list if isinstance(r, dict)]

    result["data"]["live_subdomains"] = live
    result["data"]["total_live"] = len(live)

    if result["errors"]:
        result["status"] = "partial" if subdomains else "error"
    return result
