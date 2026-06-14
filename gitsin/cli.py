import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional
import sys
import json

# Simulated per-violation regulatory penalty for executive exposure theater.
_SUITS_MODE_PENALTY_PER_VIOLATION_USD = 250_000

from gitsin.scanner import GitleaksOrchestrator
from gitsin.blame import BlameEngine
from gitsin.compliance import ComplianceEngine
from gitsin.telemetry import TelemetryEngine
from gitsin.threats import ThreatScanner
from gitsin.exporter import ExportManager
from gitsin.models import RiskLedger
from gitsin import osv_adapter

app = typer.Typer(help="GitSin Auditor - Automated compliance and accountability tool.")
console = Console()

class OutputFormat(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"
    html = "html"

@app.callback()
def callback():
    """
    GitSin Auditor - Automated compliance and accountability tool.
    """
    pass

@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to the local Git repository target"),
    suits_mode: bool = typer.Option(False, "--suits-mode", help="Enable corporate executive financial exposure calculation theater"),
    output: OutputFormat = typer.Option(OutputFormat.console, "--output", "-o", help="Set the output format for pipeline integration."),
    no_threat_scan: bool = typer.Option(False, "--no-threat-scan", help="Disable supply chain threat heuristic scanning (Layer 1)."),
):
    """Scans a repository target natively using Gitleaks and attributes violations to their origin authors via Git Blame."""

    if output == OutputFormat.console:
        console.print(f"[bold cyan][*][/bold cyan] Commencing GitSin Reckoning Engine on: [yellow]{target}[/yellow]")

    try:
        # Initialize engines
        scanner = GitleaksOrchestrator(target)
        blamer = BlameEngine(target)
        compliance = ComplianceEngine()
        telemetry = TelemetryEngine(target)

        # Layer 1: Supply chain threat heuristics (always-on unless disabled)
        threat_indicators = []
        if not no_threat_scan:
            threat_scanner = ThreatScanner(target)
            threat_indicators = threat_scanner.scan()

        # Layer 2: OSV database cross-reference (auto-enabled if index exists)
        compiled_index = osv_adapter.load_compiled_index()
        if compiled_index is not None and not no_threat_scan:
            osv_indicators = osv_adapter.check_manifests(target, compiled_index)
            threat_indicators.extend(osv_indicators)

        # 1. Execute Scan
        raw_sins = scanner.execute_scan()

        # Warn if gitleaks was not available (scan continues with Layer 1/2)
        if getattr(scanner, "gitleaks_missing", False) and output == OutputFormat.console:
            console.print(
                "[bold yellow][!][/bold yellow] gitleaks binary not found in PATH — "
                "secret scanning skipped.\n"
                "[dim]    Install: winget install Gitleaks.Gitleaks  |  "
                "https://github.com/gitleaks/gitleaks[/dim]"
            )

        if not raw_sins and not threat_indicators:
            if output == OutputFormat.console:
                if getattr(scanner, "gitleaks_missing", False):
                    console.print("[bold yellow][+][/bold yellow] Threat scan complete (secret scanning unavailable — install gitleaks for full coverage).")
                else:
                    console.print("[bold green][+][/bold green] Grid Clean. Zero cryptographic vulnerabilities or supply chain threats identified.")
            else:
                ledger = RiskLedger(
                    repository_name=target,
                    scan_timestamp=datetime.now(timezone.utc),
                    deterministic_risk_score=0,
                    total_exposure_usd=0,
                    violations=[],
                    threat_indicators=[],
                    telemetry_activity=[],
                )
                if output == OutputFormat.json:
                    print(ExportManager.export_json(ledger))
                elif output == OutputFormat.sarif:
                    print(ExportManager.export_sarif(ledger))
                elif output == OutputFormat.html:
                    print(ExportManager.export_html(ledger))
            raise typer.Exit()

        # 2. Extract Provenance
        blame_records = []
        for sin in raw_sins:
            record = blamer.attribute_sin(sin)
            blame_records.append(record)

        # 3. Calculate Risk Score and Exposure
        risk_score = compliance.calculate_risk_score(blame_records, threat_indicators)
        simulated_fine = len(blame_records) * _SUITS_MODE_PENALTY_PER_VIOLATION_USD if suits_mode else 0

        # 3b. Aggregate at-risk compliance frameworks
        all_frameworks: set[str] = set()
        for record in blame_records:
            all_frameworks.update(compliance.map_frameworks(record.sin.rule_id))
        for indicator in threat_indicators:
            # Threat rules may reference frameworks via the rules JSON.
            if hasattr(indicator, "references"):
                for ref in indicator.references:
                    if ref.startswith("SLSA") or ref.startswith("SOC") or ref.startswith("ISO"):
                        all_frameworks.add(ref)
        # Add SLSA for any supply chain threats (they all implicate build provenance).
        if threat_indicators:
            all_frameworks.add("SLSA Level 3")

        # 4. Execute Telemetry
        activity = telemetry.get_recent_activity()

        # Compile Ledger
        ledger = RiskLedger(
            repository_name=target,
            scan_timestamp=datetime.now(timezone.utc),
            deterministic_risk_score=risk_score,
            total_exposure_usd=simulated_fine,
            violations=blame_records,
            threat_indicators=threat_indicators,
            compliance_frameworks=sorted(all_frameworks),
            telemetry_activity=activity,
        )

        # Handle Exporters
        if output == OutputFormat.json:
            print(ExportManager.export_json(ledger))
            raise typer.Exit(code=0)
        elif output == OutputFormat.sarif:
            print(ExportManager.export_sarif(ledger))
            raise typer.Exit(code=0)
        elif output == OutputFormat.html:
            print(ExportManager.export_html(ledger))
            raise typer.Exit(code=0)

        # Console Output — Secret Violations
        if blame_records:
            table = Table(title="🚨 DETECTED CRYPTOGRAPHIC TRANSGRESSIONS", show_lines=True)
            table.add_column("File Path", style="magenta")
            table.add_column("Line", style="bold white")
            table.add_column("Violation Rule", style="yellow")
            table.add_column("Compliance Frameworks", style="red")
            table.add_column("Responsible Sinner", style="bold red")
            table.add_column("Commit Hash", style="dim cyan")

            for record in blame_records:
                frameworks = compliance.map_frameworks(record.sin.rule_id)
                framework_str = "\n".join(frameworks)

                table.add_row(
                    record.sin.file_path,
                    str(record.sin.line_number),
                    record.sin.rule_id,
                    framework_str,
                    f"{record.actor.name}\n<{record.actor.email}>",
                    record.commit_hash[:8],
                )

            console.print(table)

        # Console Output — Supply Chain Threat Indicators
        if threat_indicators:
            threat_table = Table(title="🕷️ SUPPLY CHAIN THREAT INDICATORS", show_lines=True)
            threat_table.add_column("File Path", style="magenta")
            threat_table.add_column("Rule", style="yellow")
            threat_table.add_column("Category", style="cyan")
            threat_table.add_column("Severity", style="bold red")
            threat_table.add_column("Confidence", style="dim white")
            threat_table.add_column("Matched Content", style="dim", max_width=50)

            for ind in threat_indicators:
                sev_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}.get(ind.severity, "white")
                threat_table.add_row(
                    ind.file_path,
                    ind.rule_id,
                    ind.category,
                    f"[{sev_color}]{ind.severity}[/{sev_color}]",
                    ind.confidence,
                    ind.matched_line or "(presence-only)",
                )

            console.print(threat_table)

        # Display Risk Score
        risk_color = "red" if risk_score > 50 else "yellow"
        console.print(f"\n[bold]DETERMINISTIC RISK SCORE:[/bold] [{risk_color}]{risk_score}/100[/{risk_color}]")

        # Telemetry Console Output
        if activity:
            activity_str = "\n".join([f"  - {act}" for act in activity])
            console.print(Panel(
                f"[bold yellow]WARNING: Recent repository access detected.[/bold yellow]\n"
                f"The following local references/clones have touched this grid since the sin was committed:\n{activity_str}",
                title="👁️ VOYEUR PROTOCOL TELEMETRY",
                border_style="yellow",
            ))

        # Handle Executive Threat Modeling Calculations
        if suits_mode:
            console.print("\n[bold red][🚨] CRITICAL EXECUTIVE EXPOSURE DETECTED:[/bold red]")
            console.print(f" -> ESTIMATED COMPLIANCE EXPOSURE BLAST RADIUS: [bold red]${simulated_fine:,} USD[/bold red]")
            console.print("[dim] [!] EXECUTIVE BALK MODE: For strategic portfolio estimation scenarios only. Not legal counsel.[/dim]")

    except typer.Exit:
        raise
    except Exception as e:
        if output == OutputFormat.console:
            console.print(f"[bold red][🚨] Operational Error Encountered:[/bold red] {str(e)}")
        else:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
        raise typer.Exit(code=1)

@app.command(name="update-db")
def update_db(
    db_path: Optional[str] = typer.Option(None, "--db-path", help="Custom path for the OpenSSF database clone."),
    index_path: Optional[str] = typer.Option(None, "--index-path", help="Custom path for the compiled index file."),
):
    """Clone or update the OpenSSF Malicious Packages database and compile the lookup index."""
    try:
        # Step 1: Clone or pull
        console.print("[bold cyan][*][/bold cyan] Fetching OpenSSF Malicious Packages database...")
        db = Path(db_path) if db_path else None
        status = osv_adapter.clone_or_pull(db)
        console.print(f"[bold green][+][/bold green] {status}")

        # Step 2: Compile index
        console.print("[bold cyan][*][/bold cyan] Compiling threat intelligence index...")
        index = osv_adapter.compile_index(db)
        meta = index["metadata"]

        # Step 3: Save compiled index
        idx = Path(index_path) if index_path else None
        saved_path = osv_adapter.save_compiled_index(index, idx)

        # Step 4: Report stats
        ecosystems = index["index"]
        eco_summary = ", ".join(
            f"{eco}: {len(pkgs)}" for eco, pkgs in sorted(ecosystems.items())
        )
        console.print(
            f"[bold green][+][/bold green] Compiled "
            f"[bold]{meta['total_advisories']}[/bold] advisories across "
            f"[bold]{len(ecosystems)}[/bold] ecosystems "
            f"({eco_summary})"
        )
        if meta.get("total_errors", 0) > 0:
            console.print(f"[yellow][!][/yellow] Skipped {meta['total_errors']} malformed JSON files.")
        console.print(f"[bold green][+][/bold green] Index saved to: {saved_path}")
        console.print("[dim]Run 'gitsin scan <repo>' — Layer 2 will auto-activate.[/dim]")

    except Exception as e:
        console.print(f"[bold red][🚨] Database update failed:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
