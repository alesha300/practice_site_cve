"""WHOIS, DNS records, IP geolocation — pure Python, no external tools."""

import asyncio
import socket

import requests

from config import DNS_TIMEOUT, HTTP_TIMEOUT, USER_AGENT, WHOIS_TIMEOUT, parse_target

NAME = "basic_info"
DESCRIPTION = "WHOIS, DNS records, IP geolocation"


def _whois_query(server: str, query: str, timeout: float) -> str:
    """Raw WHOIS query via TCP socket (port 43)."""
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="replace")


def _whois_lookup(domain: str, timeout: float) -> str:
    """WHOIS with automatic referral follow (IANA -> TLD server)."""
    iana = _whois_query("whois.iana.org", domain, timeout)
    refer = None
    for line in iana.splitlines():
        low = line.strip().lower()
        if low.startswith("refer:") or low.startswith("whois:"):
            refer = line.split(":", 1)[1].strip()
            break
    if refer:
        return _whois_query(refer, domain, timeout)
    return iana


def _dns_resolve(domain: str, rtype: str, timeout: float) -> list[str]:
    """DNS lookup via Google DNS-over-HTTPS API."""
    resp = requests.get(
        "https://dns.google/resolve",
        params={"name": domain, "type": rtype},
        timeout=timeout,
        headers={"Accept": "application/dns-json"},
    )
    if resp.status_code != 200:
        return []
    answers = resp.json().get("Answer", [])
    return [a["data"] for a in answers if "data" in a]


async def run(target: str) -> dict:
    info = parse_target(target)
    domain = info["domain"]
    result: dict = {"status": "success", "data": {}, "errors": []}

    # WHOIS (pure Python, TCP port 43)
    try:
        whois_text = await asyncio.to_thread(_whois_lookup, domain, WHOIS_TIMEOUT)
        result["data"]["whois"] = whois_text.strip()
    except socket.timeout:
        result["errors"].append("WHOIS lookup timed out")
    except Exception as e:
        result["errors"].append(f"WHOIS error: {e}")

    # DNS records via Google DoH
    dns_records: dict = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
        try:
            records = await asyncio.to_thread(_dns_resolve, domain, rtype, DNS_TIMEOUT)
            if records:
                dns_records[rtype] = records
        except Exception as e:
            result["errors"].append(f"DNS {rtype} error: {e}")
    result["data"]["dns"] = dns_records

    # IP resolution
    ip = None
    try:
        ip = socket.gethostbyname(domain)
        result["data"]["ip"] = ip
    except socket.gaierror as e:
        result["errors"].append(f"IP resolution failed: {e}")

    # Geolocation via ip-api.com
    if ip:
        try:
            resp = await asyncio.to_thread(
                requests.get,
                f"http://ip-api.com/json/{ip}",
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code == 200:
                result["data"]["geolocation"] = resp.json()
        except Exception as e:
            result["errors"].append(f"Geolocation error: {e}")

    if result["errors"]:
        result["status"] = "partial" if result["data"] else "error"
    return result
