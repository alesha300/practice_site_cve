"""Directory and file bruteforce via async HTTP requests."""

import asyncio

import aiohttp

from config import MAX_CONCURRENT_REQUESTS, USER_AGENT, WORDLIST, parse_target

NAME = "directory_bruteforce"
DESCRIPTION = "Directory bruteforce (~200 paths)"

SKIP_STATUS = {400, 404, 405, 500, 501, 502, 503, 504}


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"].rstrip("/")
    result: dict = {"status": "success", "data": {}, "errors": []}
    found: list[dict] = []
    sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async def check_path(session: aiohttp.ClientSession, path: str) -> None:
        url = f"{base_url}/{path}"
        async with sem:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                    headers={"User-Agent": USER_AGENT},
                    ssl=False,
                ) as resp:
                    if resp.status not in SKIP_STATUS:
                        size = resp.content_length or 0
                        location = resp.headers.get("Location", "")
                        found.append({
                            "path": f"/{path}",
                            "status": resp.status,
                            "size": size,
                            "redirect": location,
                        })
            except Exception:
                pass

    try:
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [check_path(session, p) for p in WORDLIST]
            await asyncio.gather(*tasks)
    except Exception as e:
        result["errors"].append(f"Bruteforce error: {e}")

    found.sort(key=lambda x: x["path"])
    result["data"]["found"] = found
    result["data"]["total_checked"] = len(WORDLIST)
    result["data"]["total_found"] = len(found)

    if result["errors"]:
        result["status"] = "partial" if found else "error"
    return result
