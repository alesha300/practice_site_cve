"""JavaScript file analysis — extract endpoints, secrets, and API keys."""

import re
from urllib.parse import urljoin, urlparse

import aiohttp

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "js_analysis"
DESCRIPTION = "JavaScript files analysis: endpoints, secrets, API keys"

# Regex patterns for secrets
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":         r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Slack Token":          r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "Stripe Key":           r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    "SendGrid Key":         r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "JWT Token":            r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "Private Key Header":   r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Hardcoded Password":   r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded Secret":     r"(?i)(?:secret|api_?key|auth_?key|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "Basic Auth":           r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]{8,}",
    "Bearer Token":         r"(?i)authorization:\s*bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    "Database URL":         r"(?i)(?:mysql|postgres|mongodb|redis)://[^\s'\"<>]{10,}",
    "Internal IP":          r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
}

# API endpoint patterns
ENDPOINT_PATTERNS = [
    r"""(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*[`'"](\/[^\s`'"]+)[`'"]""",
    r"""(?:url|endpoint|path|api)\s*[:=]\s*[`'"](\/[a-zA-Z0-9_\-\/\.]+)[`'"]""",
    r"""[`'"](\/api\/[a-zA-Z0-9_\-\/\.?=&]+)[`'"]""",
]


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    """Find all JS file URLs in HTML."""
    pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
    urls = []
    for match in re.finditer(pattern, html, re.IGNORECASE):
        src = match.group(1)
        if src.startswith("//"):
            src = "https:" + src
        elif not src.startswith("http"):
            src = urljoin(base_url, src)
        if urlparse(src).netloc == urlparse(base_url).netloc:
            urls.append(src)
    return list(set(urls))[:20]  # cap at 20 files


def _scan_for_secrets(content: str) -> dict:
    findings: dict = {}
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            # Truncate matches to avoid massive output
            findings[name] = [m[:120] for m in matches[:5]]
    return findings


def _extract_endpoints(content: str) -> list[str]:
    endpoints: set[str] = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content):
            ep = match.group(1)
            if len(ep) > 2 and not ep.endswith(".js"):
                endpoints.add(ep)
    return sorted(endpoints)[:50]


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}

    # Fetch main page HTML to find JS files
    html = ""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                html = await resp.text(errors="replace")
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"Failed to fetch page: {e}")
        return result

    js_urls = _extract_js_urls(html, base_url)
    result["data"]["js_files_found"] = len(js_urls)

    all_secrets: dict = {}
    all_endpoints: set[str] = set()
    analyzed = 0

    async with aiohttp.ClientSession() as session:
        for url in js_urls:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"User-Agent": USER_AGENT},
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        continue
                    content = await resp.text(errors="replace")
                    analyzed += 1

                    # Scan for secrets
                    secrets = _scan_for_secrets(content)
                    for k, v in secrets.items():
                        all_secrets.setdefault(k, []).extend(v)

                    # Extract endpoints
                    endpoints = _extract_endpoints(content)
                    all_endpoints.update(endpoints)
            except Exception:
                pass

    result["data"]["js_files_analyzed"] = analyzed
    result["data"]["secrets_found"] = all_secrets
    result["data"]["secrets_count"] = sum(len(v) for v in all_secrets.values())
    result["data"]["api_endpoints"] = sorted(all_endpoints)[:50]
    result["data"]["endpoints_count"] = len(all_endpoints)

    if all_secrets:
        result["data"]["risk"] = "HIGH — potential credential exposure in JS files"

    if result["errors"]:
        result["status"] = "partial"
    return result
