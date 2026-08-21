"""
Markdown Report Generator for VALKRIEY.
Generates comprehensive Markdown reports with Pre vs Post-Hardening score comparison tables.
"""

import datetime
from typing import Optional
from valkriey.auditors.base import AuditSummary, FindingStatus


class MarkdownReporter:
    """Generates Markdown format compliance reports."""

    @staticmethod
    def generate(summary: AuditSummary, output_path: str = "report.md", pre_summary: Optional[AuditSummary] = None):
        """Build and write Markdown audit report file."""
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        md_lines = [
            "# 🛡️ VALKRIEY - Security Hardening & Compliance Audit Report",
            f"**Generated Date:** `{now_str}`  ",
            "**Compliance Standard:** `CIS AWS Foundations Benchmark v1.4.0`  ",
            "**Target Cloud:** `Amazon Web Services (AWS)`  ",
            "",
            "---",
            "",
            "## 📊 Executive Dashboard Summary",
            "",
        ]

        if pre_summary:
            md_lines.extend([
                "### 🔄 Pre-Hardening vs Post-Hardening Score Comparison Table",
                "",
                "| Metric | Pre-Hardening Audit | Post-Hardening Audit | Delta |",
                "| :--- | :---: | :---: | :---: |",
                f"| **Compliance Score** | `{pre_summary.compliance_score}%` | `{summary.compliance_score}%` | `+{round(summary.compliance_score - pre_summary.compliance_score, 2)}%` |",
                f"| **Overall Risk Category** | `{pre_summary.risk_category}` | `{summary.risk_category}` | `Improved` |",
                f"| **Total Checks** | `{pre_summary.total_checks}` | `{summary.total_checks}` | `0` |",
                f"| **Passed Checks** | `{pre_summary.passed_checks}` | `{summary.passed_checks}` | `+{summary.passed_checks - pre_summary.passed_checks}` |",
                f"| **Failed Checks** | `{pre_summary.failed_checks}` | `{summary.failed_checks}` | `-{pre_summary.failed_checks - summary.failed_checks}` |",
                f"| **Remediated Checks** | `0` | `{summary.remediated_checks}` | `+{summary.remediated_checks}` |",
                "",
            ])
        else:
            md_lines.extend([
                "| Metric | Value |",
                "| :--- | :--- |",
                f"| **Compliance Score** | `{summary.compliance_score}%` |",
                f"| **Overall Risk Category** | `{summary.risk_category}` |",
                f"| **Total Checks** | `{summary.total_checks}` |",
                f"| **Passed Checks** | `{summary.passed_checks}` |",
                f"| **Failed Checks** | `{summary.failed_checks}` |",
                f"| **Error Checks** | `{summary.error_checks}` |",
                f"| **Remediated Checks** | `{summary.remediated_checks}` |",
                "",
            ])

        md_lines.extend([
            "---",
            "",
            "## 🔍 Detailed Security Audit Findings",
            "",
            "| Rule ID | Service | Resource ID | Status | Severity | Audit Details |",
            "| :--- | :--- | :--- | :---: | :---: | :--- |",
        ])

        for f in summary.findings:
            status_icon = "✅ PASS" if f.status == FindingStatus.PASS else "⚡ REMEDIATED" if f.status == FindingStatus.REMEDIATED else "❌ FAIL" if f.status == FindingStatus.FAIL else "⚠️ ERROR"
            md_lines.append(
                f"| `{f.rule_id}` | `{f.service}` | `{f.resource_id}` | {status_icon} | `{f.severity}` | {f.details} |"
            )

        md_lines.extend([
            "",
            "---",
            "",
            "## 💡 Security Recommendations & Action Plan",
            "",
            "1. **S3 Public Access Block:** Ensure all S3 buckets enforce account-level and bucket-level Public Access Block.",
            "2. **Security Groups:** Restrict all inbound security group rules allowing `0.0.0.0/0` on sensitive ports (22 SSH, 3389 RDP, 5432 PostgreSQL, 27017 MongoDB).",
            "3. **IAM Hardening:** Enforce MFA on all IAM users, rotate access keys older than 90 days, and detach Administrator access policies directly attached to users.",
            "4. **CloudTrail Auditing:** Ensure CloudTrail is enabled globally across all regions with Log File Validation active.",
            "",
            "---",
            "*Report generated automatically by VALKRIEY Security Suite.*",
        ])

        content = "\n".join(md_lines)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return output_path
