"""
JSON Exporter Reporter for VALKRIEY.
Saves detailed audit summaries and findings to a JSON file.
"""

import json
from typing import Optional
from valkriey.auditors.base import AuditSummary


class JSONReporter:
    """Exports compliance audit results to JSON format."""

    @staticmethod
    def export(summary: AuditSummary, output_path: str = "results.json", pre_summary: Optional[AuditSummary] = None):
        """Write summary and findings to JSON file."""
        data = {
            "metadata": {
                "tool": "VALKRIEY",
                "version": "1.0.0",
                "compliance_standard": "CIS AWS Foundations Benchmark",
            },
            "summary": summary.model_dump(),
        }

        if pre_summary:
            data["pre_hardening_summary"] = pre_summary.model_dump()

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return output_path
