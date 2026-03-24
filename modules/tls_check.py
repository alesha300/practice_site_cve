"""Deep TLS/SSL configuration analysis — protocols, ciphers, weaknesses."""

import asyncio
import socket
import ssl

from config import parse_target

NAME = "tls_check"
DESCRIPTION = "TLS protocol versions and cipher suite security analysis"

# Known weak ciphers (partial names)
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "IDEA", "SEED", "CAMELLIA", "PSK", "SRP",
]

# TLS versions to probe
TLS_VERSIONS = {
    "TLS 1.0": ssl.TLSVersion.TLSv1,
    "TLS 1.1": ssl.TLSVersion.TLSv1_1,
    "TLS 1.2": ssl.TLSVersion.TLSv1_2,
    "TLS 1.3": ssl.TLSVersion.TLSv1_3,
}


def _probe_tls_version(domain: str, port: int, version_name: str, version) -> dict:
    """Try to connect with a specific TLS version."""
    result = {"supported": False, "error": None}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version

        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["supported"] = True
                result["negotiated"] = ssock.version()
                result["cipher"] = ssock.cipher()
    except ssl.SSLError as e:
        result["error"] = str(e)[:100]
    except Exception as e:
        result["error"] = str(e)[:100]
    return result


def _get_supported_ciphers(domain: str, port: int) -> list[dict]:
    """Get list of accepted cipher suites."""
    accepted = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:COMPLEMENTOFALL")

    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    is_weak = any(w in cipher[0] for w in WEAK_CIPHERS)
                    accepted.append({
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                        "weak": is_weak,
                    })
    except Exception:
        pass
    return accepted


def _check_hsts_preload(domain: str) -> bool:
    """Check if domain is in HSTS preload list via Chromium's API."""
    # We can't check the actual preload list without internet,
    # so we just note this is manual to verify
    return False


def _run_tls_analysis(domain: str, port: int) -> dict:
    """Full TLS analysis (runs in thread)."""
    data: dict = {
        "host": domain,
        "port": port,
        "protocols": {},
        "ciphers": [],
        "issues": [],
        "score": "A",
    }

    # Check each TLS version
    for name, version in TLS_VERSIONS.items():
        try:
            probe = _probe_tls_version(domain, port, name, version)
            data["protocols"][name] = probe["supported"]
            if probe["supported"] and name in ("TLS 1.0", "TLS 1.1"):
                data["issues"].append(f"{name} is enabled (deprecated, insecure)")
        except AttributeError:
            # Some Python builds lack TLSv1 constants
            data["protocols"][name] = None

    # Get ciphers
    ciphers = _get_supported_ciphers(domain, port)
    data["ciphers"] = ciphers
    for cipher in ciphers:
        if cipher.get("weak"):
            data["issues"].append(f"Weak cipher: {cipher['name']}")

    # Certificate info
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    data["cert_cn"] = dict(x[0] for x in cert.get("subject", [])).get("commonName", "")
                    data["tls_version"] = ssock.version()
                    # Forward secrecy
                    cipher = ssock.cipher()
                    if cipher:
                        data["negotiated_cipher"] = cipher[0]
                        has_fs = any(k in cipher[0] for k in ("ECDHE", "DHE", "EDH"))
                        data["forward_secrecy"] = has_fs
                        if not has_fs:
                            data["issues"].append("No forward secrecy (ECDHE/DHE not used)")
    except Exception as e:
        data["issues"].append(f"TLS connect error: {str(e)[:80]}")

    # Score
    critical = [i for i in data["issues"] if "TLS 1.0" in i or "TLS 1.1" in i or "Weak" in i]
    if critical:
        data["score"] = "F" if len(critical) > 2 else "D"
    elif data["issues"]:
        data["score"] = "C"
    else:
        data["score"] = "A"

    return data


async def run(target: str) -> dict:
    info = parse_target(target)
    domain = info["domain"]
    result: dict = {"status": "success", "data": {}, "errors": []}

    if info["scheme"] != "https":
        result["data"]["skipped"] = "Not an HTTPS target — TLS check not applicable"
        return result

    port = 443
    try:
        tls_data = await asyncio.to_thread(_run_tls_analysis, domain, port)
        result["data"] = tls_data
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"TLS analysis failed: {e}")

    return result
