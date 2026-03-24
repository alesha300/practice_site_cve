"""WAF (Web Application Firewall) detection."""

import asyncio

import aiohttp

from config import HTTP_TIMEOUT, USER_AGENT, parse_target

NAME = "waf_detect"
DESCRIPTION = "WAF / CDN detection"

# Header signatures: header_name -> {pattern: waf_name}
WAF_HEADERS = {
    "server": {
        "cloudflare": "Cloudflare", "sucuri": "Sucuri", "akamaighost": "Akamai",
        "ddos-guard": "DDoS-Guard", "aestiva": "Aestiva", "bigip": "F5 BIG-IP",
        "barracuda": "Barracuda", "imperva": "Imperva", "awselb": "AWS ELB",
        "netlify": "Netlify", "stackpath": "StackPath",
    },
    "x-powered-by": {"awslambda": "AWS Lambda"},
}

# Any header whose presence indicates a WAF
WAF_INDICATOR_HEADERS = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri", "x-sucuri-cache": "Sucuri",
    "x-akamai-transformed": "Akamai", "x-akamai-session-info": "Akamai",
    "x-cdn": "Generic CDN", "x-iinfo": "Imperva/Incapsula",
    "x-amz-cf-id": "AWS CloudFront", "x-amz-cf-pop": "AWS CloudFront",
    "x-cache": "CDN Cache",
}

# Payload that triggers WAF block responses
TRIGGER_PAYLOAD = "?id=1' OR '1'='1"


async def run(target: str) -> dict:
    info = parse_target(target)
    base_url = info["url"]
    result: dict = {"status": "success", "data": {}, "errors": []}
    detected: list[str] = []

    # 1) Analyze headers from normal request
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True, ssl=False,
            ) as resp:
                hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
                result["data"]["normal_status"] = resp.status

                for hdr_name, sigs in WAF_HEADERS.items():
                    val = hdrs.get(hdr_name, "")
                    for pattern, waf in sigs.items():
                        if pattern in val and waf not in detected:
                            detected.append(waf)

                for hdr_name, waf in WAF_INDICATOR_HEADERS.items():
                    if hdr_name in hdrs and waf not in detected:
                        detected.append(waf)
    except Exception as e:
        result["errors"].append(f"Normal request failed: {e}")

    # 2) Send malicious request to trigger WAF
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url + TRIGGER_PAYLOAD,
                timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True, ssl=False,
            ) as resp:
                result["data"]["trigger_status"] = resp.status
                body = (await resp.text(errors="replace")).lower()

                if resp.status in (403, 406, 429, 503):
                    result["data"]["waf_blocked"] = True
                elif any(w in body for w in (
                    "access denied", "blocked", "firewall",
                    "security check", "captcha", "ddos protection",
                )):
                    result["data"]["waf_blocked"] = True
                else:
                    result["data"]["waf_blocked"] = False
    except Exception as e:
        result["errors"].append(f"Trigger request failed: {e}")

    result["data"]["detected_waf"] = detected
    result["data"]["waf_present"] = bool(detected) or result["data"].get("waf_blocked", False)

    if result["errors"]:
        result["status"] = "partial" if detected else "error"
    return result
