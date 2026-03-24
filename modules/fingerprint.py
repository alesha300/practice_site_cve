"""HTTP fingerprinting and technology detection."""

import asyncio

import aiohttp

from config import HTTP_TIMEOUT, TECH_SIGNATURES, USER_AGENT, parse_target

NAME = "fingerprint"
DESCRIPTION = "HTTP headers and technology fingerprinting"


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    technologies: set[str] = set()

    # Fetch main page
    headers_data: dict = {}
    html_content = ""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                headers_data = dict(resp.headers)
                html_content = await resp.text(errors="replace")
                result["data"]["status_code"] = resp.status
                result["data"]["final_url"] = str(resp.url)
    except Exception as e:
        result["errors"].append(f"Failed to fetch main page: {e}")
        result["status"] = "error"
        return result

    result["data"]["headers"] = headers_data

    # Detect from HTTP headers
    for header_name, signatures in TECH_SIGNATURES.get("headers", {}).items():
        header_val = headers_data.get(header_name, "")
        for pattern, tech in signatures.items():
            if pattern.lower() in header_val.lower():
                technologies.add(tech)

    # Detect from HTML content
    html_lower = html_content.lower()
    for tech_name, patterns in TECH_SIGNATURES.get("html", {}).items():
        for pattern in patterns:
            if pattern.lower() in html_lower:
                technologies.add(tech_name)
                break

    # Try to extract server version from headers
    server = headers_data.get("Server", "")
    if server:
        result["data"]["server_banner"] = server

    result["data"]["technologies"] = sorted(technologies)

    # Check common files
    common_files: dict = {}
    check_paths = ["/robots.txt", "/sitemap.xml", "/humans.txt"]
    if "FastAPI" in technologies:
        check_paths.extend(["/docs", "/redoc", "/openapi.json"])

    async with aiohttp.ClientSession() as session:
        for path in check_paths:
            try:
                url = base_url.rstrip("/") + path
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    headers={"User-Agent": USER_AGENT},
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        common_files[path] = {
                            "status": resp.status,
                            "size": len(body),
                            "preview": body[:500],
                        }
            except Exception:
                pass

    result["data"]["common_files"] = common_files
    if result["errors"]:
        result["status"] = "partial"
    return result
