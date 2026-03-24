"""Wayback Machine historical URL discovery."""

import asyncio
from collections import defaultdict

import requests

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "wayback"
DESCRIPTION = "Wayback Machine URL discovery"

CDX_API = "https://web.archive.org/cdx/search/cdx"
MAX_RESULTS = 500

# Patterns that indicate interesting finds
INTERESTING = {
    "admin": ["admin", "panel", "dashboard", "manage", "control"],
    "api": ["api/", "graphql", "swagger", "openapi", "rest/"],
    "config": [".env", "config.", "settings.", ".yml", ".yaml", ".toml", ".ini"],
    "backup": [".bak", ".backup", ".old", ".zip", ".tar", ".gz", ".sql", ".dump"],
    "auth": ["login", "signin", "auth", "oauth", "token", "session", "password"],
    "debug": ["debug", "trace", "phpinfo", "test", "staging", "dev/"],
    "sensitive": [".git", ".svn", ".htaccess", "wp-config", ".DS_Store", "id_rsa"],
    "docs": ["readme", "changelog", "license", "todo", "doc/", "docs/"],
}


def _query_wayback(domain: str, timeout: float) -> list[str]:
    """Query Wayback Machine CDX API for historical URLs."""
    resp = requests.get(
        CDX_API,
        params={
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": MAX_RESULTS,
        },
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    )
    if resp.status_code != 200:
        return []
    data = resp.json()
    # First row is header ["original"], skip it
    return list({row[0] for row in data[1:] if row}) if len(data) > 1 else []


async def run(target: str) -> dict:
    info = parse_target(target)
    domain = info["domain"]
    result: dict = {"status": "success", "data": {}, "errors": []}

    try:
        urls = await asyncio.to_thread(_query_wayback, domain, HTTP_TIMEOUT * 3)
    except Exception as e:
        result["errors"].append(f"Wayback query failed: {e}")
        result["status"] = "error"
        return result

    result["data"]["total_urls"] = len(urls)

    # Categorize interesting URLs
    categorized: dict[str, list[str]] = defaultdict(list)
    for url in urls:
        url_lower = url.lower()
        for category, patterns in INTERESTING.items():
            if any(p in url_lower for p in patterns):
                categorized[category].append(url)
                break

    result["data"]["categorized"] = {k: sorted(v)[:20] for k, v in categorized.items()}
    result["data"]["interesting_count"] = sum(len(v) for v in categorized.values())
    result["data"]["sample_urls"] = sorted(urls)[:50]

    return result
