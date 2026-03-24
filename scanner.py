#!/usr/bin/env python3
"""WebRecon - Black-box web reconnaissance scanner."""

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

import report
from config import MAX_CONCURRENT_SITES, REPORTS_DIR, parse_target
from modules import ALL_MODULES

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WebRecon - Black-box web reconnaissance scanner. "
        "For authorized security testing only.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("url", nargs="?", help="Target URL to scan")
    group.add_argument(
        "-f", "--file", help="File with list of URLs (one per line)",
    )
    parser.add_argument(
        "--concurrent",
        action="store_true",
        help="Scan multiple sites in parallel",
    )
    return parser.parse_args()


def load_urls(args: argparse.Namespace) -> list[str]:
    if args.file:
        path = Path(args.file)
        if not path.exists():
            console.print(f"[red]File not found: {args.file}[/red]")
            sys.exit(1)
        urls = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not urls:
            console.print("[red]No URLs found in file[/red]")
            sys.exit(1)
        return urls
    return [args.url]


async def scan_site(
    target: str,
    progress: Progress,
    task_id: int,
) -> dict:
    """Run all recon modules against a single target."""
    info = parse_target(target)
    domain = info["domain"]
    results: dict = {}
    technologies: list[str] = []

    for module in ALL_MODULES:
        progress.update(
            task_id,
            description=f"[cyan]{domain}[/cyan] > {module.DESCRIPTION}",
        )
        try:
            if module.NAME == "cve_lookup":
                mod_result = await module.run(target, technologies=technologies)
            else:
                mod_result = await module.run(target)
            results[module.NAME] = mod_result

            # Collect technologies for CVE lookup
            if module.NAME == "fingerprint":
                technologies = mod_result.get("data", {}).get("technologies", [])

            status_map = {
                "success": "[green]OK[/green]",
                "partial": "[yellow]PARTIAL[/yellow]",
                "error": "[red]FAIL[/red]",
            }
            tag = status_map.get(mod_result["status"], "?")
            progress.console.print(f"  {tag} {module.DESCRIPTION}")
        except Exception as e:
            results[module.NAME] = {
                "status": "error", "data": {}, "errors": [str(e)],
            }
            progress.console.print(f"  [red]FAIL[/red] {module.DESCRIPTION}: {e}")

        progress.advance(task_id)

    # Generate and save report
    md = report.generate(target, domain, results)
    report_path = report.save(domain, md)
    progress.console.print(f"  [green]Report saved:[/green] {report_path}\n")

    return {"domain": domain, "results": results, "report": str(report_path)}


async def main() -> None:
    args = parse_args()
    urls = load_urls(args)
    mode = "concurrent" if args.concurrent else "sequential"

    console.print(Panel(
        f"[bold]WebRecon Scanner[/bold]\n"
        f"Targets: {len(urls)} | Modules: {len(ALL_MODULES)} | Mode: {mode}",
        style="blue",
    ))

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    all_results: list = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        if args.concurrent and len(urls) > 1:
            sem = asyncio.Semaphore(MAX_CONCURRENT_SITES)
            tasks = []
            for url in urls:
                tid = progress.add_task(
                    f"[cyan]{parse_target(url)['domain']}[/cyan]",
                    total=len(ALL_MODULES),
                )

                async def _bound(u: str = url, t: int = tid) -> dict:
                    async with sem:
                        return await scan_site(u, progress, t)

                tasks.append(_bound())
            all_results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            for url in urls:
                tid = progress.add_task(
                    f"[cyan]{parse_target(url)['domain']}[/cyan]",
                    total=len(ALL_MODULES),
                )
                res = await scan_site(url, progress, tid)
                all_results.append(res)

    # Summary table
    console.print()
    table = Table(title="Scan Summary", show_lines=True)
    table.add_column("Domain", style="cyan")
    table.add_column("Ports", justify="center")
    table.add_column("Subs", justify="center")
    table.add_column("Dirs", justify="center")
    table.add_column("Sec", justify="center")
    table.add_column("TLS", justify="center")
    table.add_column("JS Secrets", justify="center")
    table.add_column("Redirect", justify="center")
    table.add_column("CVEs", justify="center")
    table.add_column("Report")

    critical_count = 0
    for r in all_results:
        if isinstance(r, Exception):
            continue
        res = r["results"]
        ports = res.get("port_scan", {}).get("data", {}).get("total_open", "?")
        subs = res.get("subdomain_enum", {}).get("data", {}).get("total_live", "?")
        dirs_found = res.get("directory_bruteforce", {}).get("data", {}).get("total_found", "?")
        grade = res.get("security_headers_check", {}).get("data", {}).get("overall_grade", "?")
        tls = res.get("tls_check", {}).get("data", {}).get("score", "?")
        js_sec = res.get("js_analysis", {}).get("data", {}).get("secrets_count", 0)
        redirect = "[red]YES[/red]" if res.get("open_redirect", {}).get("data", {}).get("vulnerable") else "No"
        cves = res.get("cve_lookup", {}).get("data", {}).get("total_cves", "?")
        crit = len(res.get("cve_lookup", {}).get("data", {}).get("by_severity", {}).get("CRITICAL", []))
        critical_count += crit
        table.add_row(r["domain"], str(ports), str(subs), str(dirs_found), grade, str(tls), str(js_sec), redirect, str(cves), r["report"])

    console.print(table)
    console.print(
        f"\n[green]Done.[/green] {len(all_results)} site(s) scanned. "
        f"Reports in [bold]{REPORTS_DIR}/[/bold]",
    )
    if critical_count:
        console.print(f"[red bold]CRITICAL CVEs found: {critical_count}[/red bold]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
