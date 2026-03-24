"""CVE lookup via NVD API for detected technologies."""

import asyncio

import requests

from config import NVD_DELAY, NVD_TIMEOUT, USER_AGENT

NAME = "cve_lookup"
DESCRIPTION = "CVE lookup via NVD API"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _query_nvd(keyword: str) -> list[dict]:
    """Query NVD API for CVEs matching a technology keyword."""
    try:
        resp = requests.get(
            NVD_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 20},
            timeout=NVD_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 403:
            return [{"error": f"NVD rate limit hit for '{keyword}'"}]
        if resp.status_code != 200:
            return [{"error": f"NVD returned {resp.status_code} for '{keyword}'"}]

        cves: list[dict] = []
        for vuln in resp.json().get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description",
            )

            # Extract severity from CVSS metrics
            metrics = cve.get("metrics", {})
            severity, score = "UNKNOWN", 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss = metric_list[0].get("cvssData", {})
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                    score = cvss.get("baseScore", 0.0)
                    break

            cves.append({
                "id": cve_id,
                "severity": severity.upper(),
                "score": score,
                "description": desc[:300],
            })
        return cves
    except Exception as e:
        return [{"error": f"NVD query failed for '{keyword}': {e}"}]


async def run(target: str, technologies: list[str] | None = None) -> dict:
    """Look up CVEs for detected technologies."""
    result: dict = {"status": "success", "data": {}, "errors": []}

    if not technologies:
        result["data"]["message"] = "No technologies detected for CVE lookup"
        result["data"]["total_cves"] = 0
        return result

    all_cves: dict[str, list[dict]] = {}
    for i, tech in enumerate(technologies):
        if i > 0:
            await asyncio.sleep(NVD_DELAY)

        cves = await asyncio.to_thread(_query_nvd, tech)
        errors = [c for c in cves if "error" in c]
        valid = [c for c in cves if "error" not in c]

        for err in errors:
            result["errors"].append(err["error"])
        if valid:
            all_cves[tech] = valid

    # Group by severity
    grouped: dict[str, list[dict]] = {}
    for tech, cves in all_cves.items():
        for cve in cves:
            sev = cve["severity"]
            if sev not in grouped:
                grouped[sev] = []
            cve_copy = {**cve, "technology": tech}
            grouped[sev].append(cve_copy)

    result["data"]["by_technology"] = all_cves
    result["data"]["by_severity"] = grouped
    result["data"]["total_cves"] = sum(len(v) for v in all_cves.values())

    if result["errors"]:
        result["status"] = "partial" if all_cves else "error"
    return result
