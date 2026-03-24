"""Information disclosure detection — version leaks, debug pages, error messages."""

import re

import aiohttp

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "info_disclosure"
DESCRIPTION = "Information disclosure: version leaks, debug pages, error messages"

# Version-revealing header patterns
VERSION_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                   "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via"]

# Paths that commonly leak info
INFO_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.backup",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-info", "/server-status", "/nginx_status", "/fpm-status",
    "/debug", "/__debug__", "/console", "/actuator",
    "/actuator/env", "/actuator/health", "/actuator/info", "/actuator/metrics",
    "/api/debug", "/api/config", "/api/env",
    "/error", "/errors", "/exception",
    "/_profiler", "/_profiler/empty/search/results",
    "/wp-json/wp/v2/users",  # WordPress user enumeration
    "/CHANGELOG.md", "/CHANGELOG.txt", "/VERSION", "/version.txt",
    "/config.yml.bak", "/config.php.bak", "/database.yml",
    "/web.config", "/crossdomain.xml",
]

# Patterns that indicate info disclosure in response body
SENSITIVE_PATTERNS = {
    "Stack trace":      r"(?:Traceback|at\s+[\w\.\$]+\([\w\.]+:\d+\)|Exception in thread|System\.Exception)",
    "PHP error":        r"(?:Parse error|Fatal error|Warning:|Notice:)\s+.+?in\s+/.+? on line \d+",
    "SQL error":        r"(?:SQL syntax|mysql_fetch|ORA-\d+|pg_query|SQLSTATE\[)",
    "Debug mode":       r"(?:DEBUG\s*=\s*True|APP_DEBUG=true|display_errors\s*=\s*On)",
    "Internal path":    r"(?:/var/www|/home/\w+/|/usr/local|C:\\inetpub|C:\\xampp)",
    "Server version":   r"(?:Apache/\d+\.\d+|nginx/\d+\.\d+|PHP/\d+\.\d+|IIS/\d+\.\d+|OpenSSL/\d+)",
    "Config dump":      r"(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|APP_KEY)\s*=\s*[^\s]{4,}",
    "AWS metadata":     r"(?:169\.254\.169\.254|ec2\.internal|amazonaws\.com/latest/meta-data)",
    "Private key":      r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Email addresses":  r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
}


def _check_version_headers(headers: dict) -> list[dict]:
    """Find headers that leak version information."""
    leaks = []
    for h in VERSION_HEADERS:
        val = headers.get(h)
        if not val:
            continue
        # Check if value contains version numbers
        if re.search(r"\d+\.\d+", val) or len(val) > 5:
            leaks.append({"header": h, "value": val[:200]})
    return leaks


def _scan_body(body: str, url: str) -> list[dict]:
    """Scan response body for sensitive patterns."""
    findings = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            # Skip email false positives on normal pages
            if name == "Email addresses" and len(matches) > 5:
                findings.append({"type": name, "url": url,
                                  "sample": f"{len(matches)} addresses found", "count": len(matches)})
            else:
                findings.append({"type": name, "url": url,
                                  "sample": str(matches[0])[:150], "count": len(matches)})
    return findings


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    all_findings: list[dict] = []
    accessible_paths: list[dict] = []

    # Check version headers from main page
    header_leaks: list[dict] = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                header_leaks = _check_version_headers(dict(resp.headers))
                body = await resp.text(errors="replace")
                main_findings = _scan_body(body, base_url)
                all_findings.extend(main_findings)
    except Exception as e:
        result["errors"].append(f"Main page error: {e}")

    result["data"]["version_headers"] = header_leaks

    # Check sensitive paths
    async with aiohttp.ClientSession() as session:
        for path in INFO_PATHS:
            url = base_url.rstrip("/") + path
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=6),
                    headers={"User-Agent": USER_AGENT},
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    if resp.status in (200, 206):
                        body = await resp.text(errors="replace")
                        path_findings = _scan_body(body, url)
                        all_findings.extend(path_findings)
                        accessible_paths.append({
                            "path": path,
                            "status": resp.status,
                            "size": len(body),
                            "findings": len(path_findings),
                        })
            except Exception:
                pass

    result["data"]["sensitive_paths_accessible"] = accessible_paths
    result["data"]["findings"] = all_findings
    result["data"]["total_issues"] = len(all_findings) + len(header_leaks) + len(accessible_paths)

    if all_findings or header_leaks or accessible_paths:
        result["data"]["risk"] = (
            "HIGH" if any(f["type"] in ("Stack trace", "PHP error", "SQL error",
                                        "Config dump", "Private key") for f in all_findings)
            else "MEDIUM"
        )

    if result["errors"]:
        result["status"] = "partial"
    return result
