"""
VALKRIEY CLI Main Entrypoint.
Commands:
  - scan      : Run CIS Benchmark security audit across AWS services.
  - remediate : Run security audit and automatically fix remediable vulnerabilities.
  - report    : Audit, remediate (optional), and generate Markdown/JSON compliance reports.
"""

import sys
from typing import Optional, List, Dict, Any
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

# Reconfigure stdout/stderr to UTF-8 on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from valkriey.auditors.s3_auditor import S3Auditor
from valkriey.auditors.sg_auditor import SecurityGroupAuditor
from valkriey.auditors.iam_auditor import IAMAuditor
from valkriey.auditors.logging_auditor import LoggingAuditor
from valkriey.auditors.base import AuditFinding, FindingStatus
from valkriey.remediators.s3_remediator import S3Remediator
from valkriey.remediators.sg_remediator import SecurityGroupRemediator
from valkriey.engine.score_calculator import ScoreCalculator
from valkriey.reporters.terminal_reporter import TerminalReporter
from valkriey.reporters.json_reporter import JSONReporter
from valkriey.reporters.markdown_reporter import MarkdownReporter

app = typer.Typer(
    name="VALKRIEY",
    help="Multi-Cloud Security Hardening & Compliance Auditor CLI Tool",
    add_completion=False,
)
console = Console()


def _run_all_audits(region: str, dry_run: bool) -> List[AuditFinding]:
    """Execute all security auditors (S3, Security Group, IAM, CloudTrail)."""
    all_findings: List[AuditFinding] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        # S3 Audit
        task = progress.add_task("[cyan]Auditing S3 Buckets (CIS 2.1)...", total=None)
        s3_auditor = S3Auditor(region_name=region, dry_run=dry_run)
        all_findings.extend(s3_auditor.run_audit())

        # Security Group Audit
        progress.update(task, description="[cyan]Auditing Security Groups (CIS 5.2)...")
        sg_auditor = SecurityGroupAuditor(region_name=region, dry_run=dry_run)
        all_findings.extend(sg_auditor.run_audit())

        # IAM Audit
        progress.update(task, description="[cyan]Auditing IAM Configurations (CIS 1.x)...")
        iam_auditor = IAMAuditor(region_name=region, dry_run=dry_run)
        all_findings.extend(iam_auditor.run_audit())

        # Logging Audit
        progress.update(task, description="[cyan]Auditing CloudTrail Logging (CIS 3.x)...")
        log_auditor = LoggingAuditor(region_name=region, dry_run=dry_run)
        all_findings.extend(log_auditor.run_audit())

    return all_findings


def _execute_auto_remediations(findings: List[AuditFinding], region: str, dry_run: bool):
    """Execute remediations on failed remediable findings."""
    remediation_results = []
    s3_remediator = S3Remediator(region_name=region, dry_run=dry_run)
    sg_remediator = SecurityGroupRemediator(region_name=region, dry_run=dry_run)

    for f in findings:
        if f.status == FindingStatus.FAIL and f.remediable:
            if f.rule_name == "S3_PUBLIC_ACCESS_BLOCK":
                res = s3_remediator.block_public_access(f.resource_id)
                remediation_results.append(res)
                if res["status"] == "SUCCESS":
                    f.status = FindingStatus.REMEDIATED
                    f.details += " [Auto-Remediated: Public Access Block Enabled]"

            elif f.rule_name == "SG_UNRESTRICTED_INBOUND":
                res = sg_remediator.revoke_sensitive_ingress(f.resource_id)
                remediation_results.append(res)
                if res["status"] == "SUCCESS":
                    f.status = FindingStatus.REMEDIATED
                    f.details += " [Auto-Remediated: Sensitive Ports 0.0.0.0/0 Revoked]"

    return remediation_results


@app.command()
def scan(
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS Region to audit"),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Run scan in dry-run mode using mock data"),
):
    """Scan cloud infrastructure for security misconfigurations and display terminal dashboard."""
    TerminalReporter.print_banner()
    if dry_run:
        console.print("[bold yellow]⚠️ Running scan in DRY-RUN mode using mock AWS dataset...[/bold yellow]\n")

    findings = _run_all_audits(region=region, dry_run=dry_run)
    summary = ScoreCalculator.calculate_summary(findings)

    TerminalReporter.display_summary(summary)
    TerminalReporter.display_findings_table(summary)


@app.command()
def remediate(
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS Region"),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Run remediation in simulation dry-run mode"),
    auto_remediate: bool = typer.Option(True, "--auto-remediate/--no-auto-remediate", help="Automatically remediate failed checks"),
):
    """Perform security audit and auto-remediates critical misconfigurations."""
    TerminalReporter.print_banner()
    if dry_run:
        console.print("[bold yellow]⚠️ Running auto-remediation in DRY-RUN simulation mode...[/bold yellow]\n")

    # Pre-hardening audit
    findings = _run_all_audits(region=region, dry_run=dry_run)
    pre_summary = ScoreCalculator.calculate_summary(findings)

    if auto_remediate:
        console.print("\n[bold cyan]⚡ Initiating Auto-Remediation Engine...[/bold cyan]")
        remediation_results = _execute_auto_remediations(findings, region=region, dry_run=dry_run)
        
        # Post-hardening summary
        post_summary = ScoreCalculator.calculate_summary(findings)

        TerminalReporter.display_summary(post_summary, pre_summary=pre_summary)
        TerminalReporter.display_remediation_results(remediation_results)
        TerminalReporter.display_findings_table(post_summary)
    else:
        TerminalReporter.display_summary(pre_summary)
        TerminalReporter.display_findings_table(pre_summary)


@app.command()
def report(
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS Region"),
    dry_run: bool = typer.Option(False, "--dry-run", "-d", help="Run report generation in dry-run mode"),
    auto_remediate: bool = typer.Option(False, "--auto-remediate", "-a", help="Auto-remediate before generating final report"),
    output: str = typer.Option("report.md", "--output", "-o", help="Markdown report output filepath"),
    json_output: str = typer.Option("results.json", "--json-output", "-j", help="JSON report output filepath"),
):
    """Run security scan, optional remediation, and generate Markdown & JSON reports."""
    TerminalReporter.print_banner()
    if dry_run:
        console.print("[bold yellow]⚠️ Generating report in DRY-RUN mode using mock data...[/bold yellow]\n")

    findings = _run_all_audits(region=region, dry_run=dry_run)
    pre_summary = ScoreCalculator.calculate_summary(findings)

    post_summary = None
    if auto_remediate:
        console.print("[bold cyan]⚡ Applying auto-remediations for post-hardening report...[/bold cyan]")
        _execute_auto_remediations(findings, region=region, dry_run=dry_run)
        post_summary = ScoreCalculator.calculate_summary(findings)

    final_summary = post_summary if post_summary else pre_summary

    # Output files
    md_file = MarkdownReporter.generate(final_summary, output_path=output, pre_summary=pre_summary if auto_remediate else None)
    json_file = JSONReporter.export(final_summary, output_path=json_output, pre_summary=pre_summary if auto_remediate else None)

    TerminalReporter.display_summary(final_summary, pre_summary=pre_summary if auto_remediate else None)
    TerminalReporter.display_findings_table(final_summary)

    console.print(f"\n[bold green]✅ Markdown report generated successfully: [/bold green][cyan]{md_file}[/cyan]")
    console.print(f"[bold green]✅ JSON audit results exported successfully: [/bold green][cyan]{json_file}[/cyan]\n")


if __name__ == "__main__":
    app()
