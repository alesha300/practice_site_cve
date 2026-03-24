from datetime import datetime, timezone
from pathlib import Path

from config import REPORTS_DIR


def generate(target: str, domain: str, results: dict) -> str:
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"# Reconnaissance Report: {domain}\n")
    lines.append(f"**Target:** {target} | **Date:** {now} | **Scanner:** WebRecon v2.0 | **Modules:** 17\n")
    lines.append("---\n")
    # 1
    if data := results.get("basic_info", {}).get("data", {}):
        lines.append("## 1. Basic Information\n")
        if ip := data.get("ip"):
            lines.append(f"**IP:** `{ip}`\n")
        if geo := data.get("geolocation"):
            lines.append(f"**Location:** {geo.get('city','?')}, {geo.get('country','?')} | **ISP:** {geo.get('isp','?')} | **AS:** {geo.get('as','?')}\n")
        if dns := data.get("dns"):
            lines.append("| Type | Records |\n|------|---------|")
            for rtype, records in dns.items():
                lines.append(f"| {rtype} | {', '.join(records)} |")
            lines.append("")
        if whois_raw := data.get("whois"):
            lines.append("### WHOIS\n```")
            lines.extend(whois_raw.split("\n")[:20])
            lines.append("```\n")
    # 2
    if data := results.get("subdomain_enum", {}).get("data", {}):
        lines.append(f"## 2. Subdomain Enumeration\n**Found:** {data.get('total_found',0)} | **Live:** {data.get('total_live',0)}\n")
        if live := data.get("live_subdomains"):
            lines.append("| Subdomain | Status |\n|-----------|--------|")
            for s in live:
                lines.append(f"| {s['subdomain']} | {s['status']} |")
            lines.append("")
    # 3
    if data := results.get("waf_detect", {}).get("data", {}):
        waf = ", ".join(data.get("detected_waf") or ["None detected"])
        lines.append(f"## 3. WAF/CDN\n**Present:** {'Yes' if data.get('waf_present') else 'No'} | **Detected:** {waf} | **Blocked:** {'Yes' if data.get('waf_blocked') else 'No'}\n")
    # 4
    if data := results.get("fingerprint", {}).get("data", {}):
        lines.append("## 4. Fingerprinting\n")
        if t := data.get("technologies"):
            lines.append(f"**Technologies:** {', '.join(t)}\n")
        if hdrs := data.get("headers"):
            lines.append("| Header | Value |\n|--------|-------|")
            for k, v in sorted(hdrs.items()):
                lines.append(f"| {k} | {str(v).replace('|','/')[:80]} |")
            lines.append("")
    # 5
    if data := results.get("js_analysis", {}).get("data", {}):
        lines.append(f"## 5. JavaScript Analysis\n**JS files:** {data.get('js_files_found',0)} found, {data.get('js_files_analyzed',0)} analyzed | **Secrets:** {data.get('secrets_count',0)} | **Endpoints:** {data.get('endpoints_count',0)}\n")
        if secrets := data.get("secrets_found"):
            lines.append("### Secrets Found\n")
            for name, values in secrets.items():
                lines.append(f"**{name}:** `{values[0][:100]}`")
            lines.append("")
        if eps := data.get("api_endpoints"):
            lines.append(f"### API Endpoints ({len(eps)})\n")
            for ep in eps[:20]:
                lines.append(f"- `{ep}`")
            lines.append("")
    # 6
    if data := results.get("port_scan", {}).get("data", {}):
        lines.append(f"## 6. Port Scan\n**Scanned:** {data.get('total_scanned',0)} | **Open:** {data.get('total_open',0)}\n")
        if ports := data.get("open_ports"):
            lines.append("| Port | State | Banner |\n|------|-------|--------|")
            for p in ports:
                banner = (p["banner"] or "-")[:60].replace("|", "/")
                lines.append(f"| {p['port']} | {p['state']} | {banner} |")
            lines.append("")
    # 7
    if data := results.get("directory_bruteforce", {}).get("data", {}):
        lines.append(f"## 7. Directory Bruteforce\n**Checked:** {data.get('total_checked',0)} | **Found:** {data.get('total_found',0)}\n")
        if found := data.get("found"):
            lines.append("| Path | Status | Size |\n|------|--------|------|")
            for f in found:
                lines.append(f"| {f['path']} | {f['status']} | {f['size']} |")
            lines.append("")
    # 8
    if data := results.get("http_methods", {}).get("data", {}):
        lines.append(f"## 8. HTTP Methods\n**Allowed:** {', '.join(data.get('allowed_methods',[]))} | **Dangerous:** {', '.join(data.get('dangerous',[]) or ['None'])} | **Grade:** {data.get('grade','?')}\n")
    # 9
    if data := results.get("cors_check", {}).get("data", {}):
        lines.append(f"## 9. CORS\n**Grade:** {data.get('grade','?')} — {data.get('note','')}\n")
        for issue in data.get("issues", []):
            lines.append(f"- {issue}")
        lines.append("")
    # 10
    if data := results.get("cookie_analysis", {}).get("data", {}):
        lines.append(f"## 10. Cookie Security\n**Total:** {data.get('total',0)} | {data.get('note','-')}\n")
        if cookies := data.get("cookies"):
            lines.append("| Name | Secure | HttpOnly | SameSite | Grade |\n|------|--------|----------|----------|-------|")
            for c in cookies:
                lines.append(f"| {c['name'][:25]} | {c['secure']} | {c['httponly']} | {c['samesite']} | {c['grade']} |")
            lines.append("")
    # 11
    if data := results.get("security_headers_check", {}).get("data", {}):
        lines.append(f"## 11. Security Headers\n**Grade:** {data.get('overall_grade','?')} ({data.get('score','?')})\n")
        if hdrs := data.get("headers"):
            lines.append("| Header | Grade | Note |\n|--------|-------|------|")
            for name, info in hdrs.items():
                lines.append(f"| {name} | {info['grade']} | {info['note']} |")
            lines.append("")
        if ssl := data.get("ssl"):
            iss = ssl.get("issuer", {}).get("organizationName", "?") if ssl.get("valid") else "Invalid"
            lines.append(f"**SSL:** Valid={ssl.get('valid')} | Issuer={iss} | Expires={ssl.get('not_after','?')} | Days={ssl.get('days_remaining','?')} | TLS={ssl.get('version','?')}\n")
    # 12
    if data := results.get("tls_check", {}).get("data", {}):
        lines.append(f"## 12. TLS Deep Check\n**Score:** {data.get('score','?')} | **TLS version:** {data.get('tls_version','?')} | **Forward Secrecy:** {data.get('forward_secrecy','?')}\n")
        if protos := data.get("protocols"):
            lines.append("| Protocol | Supported |\n|----------|-----------|\n" + "\n".join(f"| {k} | {v} |" for k, v in protos.items()))
            lines.append("")
        for issue in data.get("issues", []):
            lines.append(f"- ⚠️ {issue}")
        lines.append("")
    # 13
    if data := results.get("email_security", {}).get("data", {}):
        lines.append("## 13. Email Security\n")
        for check in ("spf", "dmarc"):
            if info := data.get(check):
                lines.append(f"**{check.upper()}:** {'Present' if info.get('present') else 'Missing'} (Grade: {info.get('grade','?')}) — {info.get('note','')}")
        if dkim := data.get("dkim"):
            lines.append(f"**DKIM:** {'Found' if dkim.get('found') else 'Not found'} — {dkim.get('note','')}\n")
    # 14
    if data := results.get("open_redirect", {}).get("data", {}):
        lines.append(f"## 14. Open Redirect\n**Vulnerable:** {'YES ⚠️' if data.get('vulnerable') else 'No'} | **Params tested:** {data.get('params_tested',0)}\n")
        for vuln in data.get("vulnerabilities", []):
            lines.append(f"- Param `{vuln['param']}` → redirects to `{vuln['final_url'][:80]}`")
        lines.append("")
    # 15
    if data := results.get("info_disclosure", {}).get("data", {}):
        lines.append(f"## 15. Information Disclosure\n**Total issues:** {data.get('total_issues',0)} | **Risk:** {data.get('risk','-')}\n")
        if vh := data.get("version_headers"):
            for h in vh:
                lines.append(f"- Header `{h['header']}` leaks: `{h['value']}`")
        if paths := data.get("sensitive_paths_accessible"):
            for p in paths:
                lines.append(f"- `{p['path']}` returned HTTP {p['status']} ({p['size']} bytes)")
        if findings := data.get("findings"):
            lines.append("\n| Type | Sample |\n|------|--------|")
            seen = set()
            for f in findings:
                if f["type"] not in seen:
                    seen.add(f["type"])
                    lines.append(f"| {f['type']} | {str(f.get('sample',''))[:80].replace('|','/')} |")
        lines.append("")
    # 16
    if data := results.get("wayback", {}).get("data", {}):
        lines.append(f"## 16. Wayback Machine\n**URLs found:** {data.get('total_urls',0)} | **Interesting:** {data.get('interesting_count',0)}\n")
        if categorized := data.get("categorized"):
            for cat, urls in categorized.items():
                lines.append(f"**{cat}:** {len(urls)} URLs")
                for u in urls[:5]:
                    lines.append(f"  - {u}")
            lines.append("")
    # 17
    if data := results.get("cve_lookup", {}).get("data", {}):
        lines.append(f"## 17. CVE Lookup\n**Total CVEs:** {data.get('total_cves',0)}\n")
        if by_sev := data.get("by_severity"):
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if cves := by_sev.get(sev):
                    lines.append(f"### {sev} ({len(cves)})\n| CVE | Score | Tech | Description |\n|-----|-------|------|-------------|")
                    for c in cves:
                        lines.append(f"| {c['id']} | {c['score']} | {c['technology']} | {c['description'][:80].replace('|','/')} |")
                    lines.append("")
    # Errors
    all_errors = [f"- **{m}:** {e}" for m, r in results.items() for e in r.get("errors", [])]
    if all_errors:
        lines.append("## Errors\n")
        lines.extend(all_errors)
    lines.append("\n---\n*Generated by WebRecon Scanner*\n")
    return "\n".join(lines)


def save(domain: str, content: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe = domain.replace(".", "_").replace("/", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"{safe}_{ts}.md"
    path.write_text(content, encoding="utf-8")
    return path
