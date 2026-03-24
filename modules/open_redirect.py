"""Open redirect vulnerability detection."""

import asyncio

import aiohttp

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "open_redirect"
DESCRIPTION = "Open redirect vulnerability detection"

# Common redirect parameters
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "next", "next_url",
    "return", "return_url", "return_to", "returnUrl", "returnTo",
    "goto", "go", "continue", "target", "dest", "destination",
    "forward", "location", "out", "view", "redir", "r", "u",
    "link", "callback", "success", "cancel", "login_url",
]

# Payloads to test (from benign to tricky bypasses)
TEST_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "/\\evil.com",
    "https://evil.com%09",
    "https:///evil.com",
]


def _is_redirected_to_payload(final_url: str, original_host: str) -> bool:
    """Check if the final URL actually lands on evil.com (not just query param)."""
    from urllib.parse import urlparse
    parsed = urlparse(final_url)
    final_host = (parsed.hostname or "").lower()
    # True redirect: final HOST is evil.com, not just evil.com in query string
    if "evil.com" in final_host:
        return True
    # Also check: redirect to different domain than original (excluding subdomains)
    orig = original_host.lower().lstrip("www.")
    fin = final_host.lstrip("www.")
    if fin and fin != orig and not fin.endswith("." + orig):
        return True
    return False


async def _test_param(
    session: aiohttp.ClientSession,
    base_url: str,
    original_host: str,
    param: str,
    payload: str,
) -> dict | None:
    """Test a single param+payload combo. Returns finding or None."""
    test_url = f"{base_url}?{param}={payload}"
    try:
        async with session.get(
            test_url,
            timeout=aiohttp.ClientTimeout(total=8),
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
            ssl=False,
            max_redirects=5,
        ) as resp:
            final = str(resp.url)
            if _is_redirected_to_payload(final, original_host):
                return {
                    "param": param,
                    "payload": payload,
                    "test_url": test_url,
                    "final_url": final,
                    "status": resp.status,
                }
    except aiohttp.TooManyRedirects:
        pass
    except Exception:
        pass
    return None


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    vulnerabilities: list[dict] = []
    tested = 0

    # Semaphore to limit concurrent requests
    sem = asyncio.Semaphore(5)

    original_host = info["domain"]

    async def test_with_sem(session, base_url, host, param, payload):
        async with sem:
            return await _test_param(session, base_url, host, param, payload)

    try:
        async with aiohttp.ClientSession() as session:
            # Test each param with first payload only initially
            tasks = [
                test_with_sem(session, base_url, original_host, param, TEST_PAYLOADS[0])
                for param in REDIRECT_PARAMS
            ]
            first_results = await asyncio.gather(*tasks, return_exceptions=True)
            tested += len(REDIRECT_PARAMS)

            # For params that responded (not error), also test bypass payloads
            for i, res in enumerate(first_results):
                if isinstance(res, dict):
                    vulnerabilities.append(res)
                    # Found one — test more bypass payloads for this param
                    param = REDIRECT_PARAMS[i]
                    bypass_tasks = [
                        test_with_sem(session, base_url, original_host, param, p)
                        for p in TEST_PAYLOADS[1:]
                    ]
                    bypass_results = await asyncio.gather(*bypass_tasks, return_exceptions=True)
                    for br in bypass_results:
                        if isinstance(br, dict):
                            vulnerabilities.append(br)
                    tested += len(TEST_PAYLOADS) - 1

    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"Request error: {e}")

    result["data"]["params_tested"] = tested
    result["data"]["vulnerable"] = bool(vulnerabilities)
    result["data"]["vulnerabilities"] = vulnerabilities

    if vulnerabilities:
        result["data"]["risk"] = "HIGH — open redirect allows phishing/token theft attacks"

    return result
