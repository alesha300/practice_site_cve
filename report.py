"""Markdown report generator."""

from datetime import datetime, timezone
from pathlib import Path

from config import REPORTS_DIR


def generate(target: str, domain: str, results: dict) -> str:
    """Build a full markdown report from scan results."""
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append(f"# Reconnaissance Report: {domain}\n")
    lines.append(f"**Target:** {target}  ")
    lines.append(f"**Date:** {now}  ")
    lines.append(f"**Scanner:** WebRecon v1.0\n")
    lines.append("---\n")

    # 1 — Basic Info
    if data := results.get("basic_info", {}).get("data", {}):
        lines.append("## 1. Basic Information\n")
        if ip := data.get("ip"):
            lines.append(f"**IP Address:** `{ip}`\n")
        if geo := data.get("geolocation"):
            lines.append(
                f"**Location:** {geo.get('city', '?')}, "
                f"{geo.get('regionName', '?')}, {geo.get('country', '?')}  "
            )
            lines.append(f"**ISP:** {geo.get('isp', '?')}  ")
            lines.append(f"**AS:** {geo.get('as', '?')}\n")
        if dns := data.get("dns"):
            lines.append("### DNS Records\n")
            lines.append("| Type | Records |")
            lines.append("|------|---------|")
            for rtype, records in dns.items():
                lines.append(f"| {rtype} | {', '.join(records)} |")
            lines.append("")
        if whois_raw := data.get("whois"):
            lines.append("### WHOIS (excerpt)\n")
            lines.append("```")
            lines.extend(whois_raw.split("\n")[:30])
            lines.append("```\n")

    # 2 — Subdomains
    if data := results.get("subdomain_enum", {}).get("data", {}):
        lines.append("## 2. Subdomain Enumeration\n")
        lines.append(f"**Total found:** {data.get('total_found', 0)}  ")
        lines.append(f"**Live subdomains:** {data.get('total_live', 0)}\n")
        if live := data.get("live_subdomains"):
            lines.append("| Subdomain | Status | Scheme |")
            lines.append("|-----------|--------|--------|")
            for s in live:
                lines.append(f"| {s['subdomain']} | {s['status']} | {s['scheme']} |")
            lines.append("")

    # 3 — Fingerprint
    if data := results.get("fingerprint", {}).get("data", {}):
        lines.append("## 3. Fingerprinting\n")
        if techs := data.get("technologies"):
            lines.append(f"**Technologies:** {', '.join(techs)}\n")
        if hdrs := data.get("headers"):
            lines.append("### HTTP Response Headers\n")
            lines.append("| Header | Value |")
            lines.append("|--------|-------|")
            for k, v in sorted(hdrs.items()):
                lines.append(f"| {k} | {str(v).replace('|', '//')[:100]} |")
            lines.append("")
        if files := data.get("common_files"):
            lines.append("### Discovered Files\n")
            for path, info in files.items():
                lines.append(f"**{path}** (status: {info['status']}, size: {info['size']})")
                if info.get("preview"):
                    lines.append(f"```\n{info['preview'][:200]}\n```")
            lines.append("")

    # 4 — Port Scan
    if data := results.get("port_scan", {}).get("data", {}):
        lines.append("## 4. Port Scan\n")
        lines.append(f"**Scanned:** {data.get('total_scanned', 0)} ports  ")
        lines.append(f"**Open:** {data.get('total_open', 0)}\n")
        if ports := data.get("open_ports"):
            lines.append("| Port | State | Banner |")
            lines.append("|------|-------|--------|")
            for p in ports:
                banner = p["banner"][:80].replace("|", "//") if p["banner"] else "-"
                lines.append(f"| {p['port']} | {p['state']} | {banner} |")
            lines.append("")

    # 5 — Directory Bruteforce
    if data := results.get("directory_bruteforce", {}).get("data", {}):
        lines.append("## 5. Directory Bruteforce\n")
        lines.append(f"**Checked:** {data.get('total_checked', 0)} paths  ")
        lines.append(f"**Found:** {data.get('total_found', 0)}\n")
        if found := data.get("found"):
            lines.append("| Path | Status | Size | Redirect |")
            lines.append("|------|--------|------|----------|")
            for f in found:
                redir = f["redirect"][:50] if f["redirect"] else "-"
                lines.append(f"| {f['path']} | {f['status']} | {f['size']} | {redir} |")
            lines.append("")

    # 6 — Security Headers
    if data := results.get("security_headers_check", {}).get("data", {}):
        lines.append("## 6. Security Headers\n")
        lines.append(f"**Overall grade:** {data.get('overall_grade', '?')} ({data.get('score', '?')})\n")
        if hdrs := data.get("headers"):
            lines.append("| Header | Grade | Present | Note |")
            lines.append("|--------|-------|---------|------|")
            for name, info in hdrs.items():
                present = "Yes" if info["present"] else "No"
                lines.append(f"| {name} | {info['grade']} | {present} | {info['note']} |")
            lines.append("")
        if ssl_info := data.get("ssl"):
            lines.append("### SSL Certificate\n")
            if ssl_info.get("valid"):
                iss = ssl_info.get("issuer", {}).get("organizationName", "?")
                lines.append(f"**Valid:** Yes  ")
                lines.append(f"**Issuer:** {iss}  ")
                lines.append(f"**Expires:** {ssl_info.get('not_after', '?')}  ")
                lines.append(f"**Days remaining:** {ssl_info.get('days_remaining', '?')}  ")
                lines.append(f"**TLS Version:** {ssl_info.get('version', '?')}\n")
            else:
                lines.append("**Valid:** No\n")
            for err in ssl_info.get("errors", []):
                lines.append(f"- WARNING: {err}")
            lines.append("")

    # 7 — CVE Lookup
    if data := results.get("cve_lookup", {}).get("data", {}):
        lines.append("## 7. CVE Lookup\n")
        lines.append(f"**Total CVEs found:** {data.get('total_cves', 0)}\n")
        if by_sev := data.get("by_severity"):
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if cves := by_sev.get(sev):
                    lines.append(f"### {sev} ({len(cves)})\n")
                    lines.append("| CVE ID | Score | Technology | Description |")
                    lines.append("|--------|-------|------------|-------------|")
                    for c in cves:
                        desc = c["description"][:100].replace("|", "//")
                        lines.append(f"| {c['id']} | {c['score']} | {c['technology']} | {desc} |")
                    lines.append("")

    # Errors summary
    all_errors: list[str] = []
    for mod_name, mod_result in results.items():
        for err in mod_result.get("errors", []):
            all_errors.append(f"- **{mod_name}:** {err}")
    if all_errors:
        lines.append("## Errors\n")
        lines.extend(all_errors)
        lines.append("")

    lines.append("---\n*Generated by WebRecon Scanner*\n")
    return "\n".join(lines)


def save(domain: str, content: str) -> Path:
    """Save report markdown to a file, return the path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = domain.replace(".", "_").replace("/", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"{safe}_{ts}.md"
    path.write_text(content, encoding="utf-8")
    return path
