"""
Rich Terminal Dashboard Reporter for VALKRIEY.
Renders beautiful tables, panels, and badges in the CLI terminal.
"""

import sys
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from valkriey.auditors.base import AuditSummary, FindingStatus
from valkriey.config.rules import RISK_LEVEL_COLORS

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(force_terminal=True, legacy_windows=False)


class TerminalReporter:
    """Renders formatted compliance audit summaries and detailed findings to the terminal."""

    @staticmethod
    def print_banner():
        banner = r"""
 __   _____   _    _  _______  _____  _____ ________   __
 \ \ / / _ \ | |  | |/ /  __ \|_   _||  ____|\ \ \ / /   
  \ V / /_\ \| |  |  ' /| |__) | | |  | |__   \ \ V /    
   > /  _  || |  |  <  |  _  /  | |  |  __|   \ \ /     
  / /| | | || |__| . \ | | \ \ _| |_ | |____   | |      
 \/  \_| |_/\____/|_|\_\|_|  \_\_____|______|  |_|      
   Multi-Cloud Security Hardening & CIS Compliance Auditor
        """
        console.print(Panel(Text(banner, style="bold cyan"), title="🛡️ VALKRIEY Security Suite", border_style="cyan"))

    @staticmethod
    def display_summary(summary: AuditSummary, pre_summary: Optional[AuditSummary] = None):
        """Display overall compliance score dashboard panel."""
        score_color = "bold green" if summary.compliance_score >= 85 else "bold yellow" if summary.compliance_score >= 60 else "bold red"
        risk_color = RISK_LEVEL_COLORS.get(summary.risk_category, "white")

        score_text = Text()
        score_text.append(f"Compliance Score: ", style="bold white")
        score_text.append(f"{summary.compliance_score}%\n", style=score_color)
        score_text.append(f"Overall Risk Category: ", style="bold white")
        score_text.append(f"[{summary.risk_category}]\n\n", style=risk_color)

        score_text.append(f"Total Checks  : {summary.total_checks}\n", style="bold blue")
        score_text.append(f"Passed Checks : {summary.passed_checks}\n", style="bold green")
        score_text.append(f"Failed Checks : {summary.failed_checks}\n", style="bold red")
        score_text.append(f"Error Checks  : {summary.error_checks}\n", style="bold yellow")
        if summary.remediated_checks > 0:
            score_text.append(f"Remediated    : {summary.remediated_checks}\n", style="bold cyan")

        if pre_summary:
            score_text.append(f"\n[PRE-HARDENING SCORE : {pre_summary.compliance_score}% -> POST-HARDENING SCORE : {summary.compliance_score}%]", style="bold magenta")

        console.print(Panel(score_text, title="📊 Compliance Audit Dashboard", border_style="bold blue"))

    @staticmethod
    def display_findings_table(summary: AuditSummary):
        """Display detailed findings in a Rich table."""
        table = Table(title="🔍 Security Audit Findings", show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Rule ID", style="dim", width=14)
        table.add_column("Service", width=10)
        table.add_column("Resource ID", width=25)
        table.add_column("Status", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Details", justify="left")

        for f in summary.findings:
            status_style = "bold green" if f.status in [FindingStatus.PASS, FindingStatus.REMEDIATED] else "bold red" if f.status == FindingStatus.FAIL else "bold yellow"
            severity_style = RISK_LEVEL_COLORS.get(f.severity, "white")

            table.add_row(
                f.rule_id,
                f.service,
                f.resource_id,
                Text(f.status.value, style=status_style),
                Text(f.severity, style=severity_style),
                f.details,
            )

        console.print(table)

    @staticmethod
    def display_remediation_results(results: List[Dict[str, Any]]):
        """Display remediation outcomes."""
        table = Table(title="⚡ Auto-Remediation Execution Results", show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Status", width=12)
        table.add_column("Target Resource", width=25)
        table.add_column("Outcome Details")

        for r in results:
            status_style = "bold green" if r["status"] == "SUCCESS" else "bold red"
            table.add_row(
                Text(r["status"], style=status_style),
                r.get("bucket") or r.get("sg_id") or "N/A",
                r["message"],
            )

        console.print(table)
