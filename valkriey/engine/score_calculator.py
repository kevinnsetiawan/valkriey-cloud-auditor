"""
Score Calculator Engine for VALKRIEY.
Calculates Compliance Score and determines overall Risk Level Categorization.
"""

from typing import List
from valkriey.auditors.base import AuditFinding, AuditSummary, FindingStatus


class ScoreCalculator:
    """Calculates compliance score and risk levels from audit findings."""

    @staticmethod
    def calculate_summary(findings: List[AuditFinding]) -> AuditSummary:
        """
        Calculate total, passed, failed, error, and remediated check counts,
        compute compliance percentage, and categorize risk level.
        """
        total = len(findings)
        if total == 0:
            return AuditSummary(
                total_checks=0,
                passed_checks=0,
                failed_checks=0,
                error_checks=0,
                remediated_checks=0,
                compliance_score=100.0,
                risk_category="RENDAH",
                findings=[],
            )

        passed = sum(1 for f in findings if f.status in [FindingStatus.PASS, FindingStatus.REMEDIATED])
        failed = sum(1 for f in findings if f.status == FindingStatus.FAIL)
        errors = sum(1 for f in findings if f.status == FindingStatus.ERROR)
        remediated = sum(1 for f in findings if f.status == FindingStatus.REMEDIATED)

        # Compliance Score = (Passed Checks / Total Checks) * 100%
        # (Where remediated counts as passed post-hardening)
        compliance_score = round((passed / total) * 100.0, 2)

        # Categorize risk level based on compliance score & critical finding presence
        critical_fails = sum(1 for f in findings if f.severity == "KRITIS" and f.status == FindingStatus.FAIL)

        if compliance_score < 50.0 or critical_fails >= 3:
            risk_category = "KRITIS"
        elif compliance_score < 75.0 or critical_fails >= 1:
            risk_category = "TINGGI"
        elif compliance_score < 90.0:
            risk_category = "SEDANG"
        else:
            risk_category = "RENDAH"

        return AuditSummary(
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            error_checks=errors,
            remediated_checks=remediated,
            compliance_score=compliance_score,
            risk_category=risk_category,
            findings=findings,
        )
