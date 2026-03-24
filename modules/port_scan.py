"""Async TCP port scanner with banner grabbing."""

import asyncio
import socket

from config import MAX_CONCURRENT_PORTS, PORT_TIMEOUT, TOP_PORTS, parse_target

NAME = "port_scan"
DESCRIPTION = "TCP scan of top 100 ports"


async def _scan_port(host: str, port: int, timeout: float) -> dict | None:
    """Attempt TCP connect and grab banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        banner = ""
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = data.decode(errors="replace").strip()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"port": port, "state": "open", "banner": banner}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def run(target: str) -> dict:
    info = parse_target(target)
    domain = info["domain"]
    result: dict = {"status": "success", "data": {}, "errors": []}

    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        result["status"] = "error"
        result["errors"].append(f"Cannot resolve {domain}: {e}")
        return result

    result["data"]["target_ip"] = ip
    sem = asyncio.Semaphore(MAX_CONCURRENT_PORTS)

    async def bounded_scan(port: int) -> dict | None:
        async with sem:
            return await _scan_port(ip, port, PORT_TIMEOUT)

    tasks = [bounded_scan(p) for p in TOP_PORTS]
    scan_results = await asyncio.gather(*tasks)

    open_ports = sorted(
        [r for r in scan_results if r is not None],
        key=lambda x: x["port"],
    )

    # False positive detection: if >80% ports appear open, likely a
    # transparent proxy (Tor exit node) or firewall accepting all SYN.
    total = len(TOP_PORTS)
    if len(open_ports) > total * 0.8:
        result["data"]["warning"] = (
            f"All {len(open_ports)}/{total} ports appear open — likely a "
            "false positive due to Tor exit node or transparent proxy. "
            "Only ports with banners are reliable."
        )
        # Keep only ports that returned a banner (confirmed services)
        confirmed = [p for p in open_ports if p["banner"]]
        result["data"]["open_ports"] = confirmed
        result["data"]["all_responded"] = len(open_ports)
        result["data"]["total_open"] = len(confirmed)
    else:
        result["data"]["open_ports"] = open_ports
        result["data"]["total_open"] = len(open_ports)

    result["data"]["total_scanned"] = total
    return result
