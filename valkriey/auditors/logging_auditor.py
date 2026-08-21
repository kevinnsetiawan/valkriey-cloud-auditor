"""
CloudTrail Logging Auditor for VALKRIEY.
Audits AWS CloudTrail for multi-region logging and log file validation.
"""

from typing import List
from botocore.exceptions import ClientError
from valkriey.auditors.base import BaseAuditor, AuditFinding, FindingStatus
from valkriey.config.rules import CIS_BENCHMARK_RULES
from valkriey.engine.mock_data import MOCK_CLOUDTRAILS


class LoggingAuditor(BaseAuditor):
    """Audits AWS CloudTrail configurations against CIS Security Benchmarks."""

    def run_audit(self) -> List[AuditFinding]:
        self.findings = []
        if self.dry_run:
            self._audit_mock_data()
        else:
            self._audit_live_aws()
        return self.findings

    def _audit_mock_data(self):
        """Audit mock CloudTrail configurations for dry-run testing."""
        global_rule = CIS_BENCHMARK_RULES["LOGGING_CLOUDTRAIL_GLOBAL"]
        val_rule = CIS_BENCHMARK_RULES["LOGGING_CLOUDTRAIL_VALIDATION"]

        if not MOCK_CLOUDTRAILS:
            self.findings.append(AuditFinding(
                rule_id=global_rule["id"],
                rule_name="LOGGING_CLOUDTRAIL_GLOBAL",
                service=global_rule["service"],
                resource_id="CloudTrail_Service",
                status=FindingStatus.FAIL,
                severity=global_rule["severity"],
                details="No CloudTrail trails found in AWS Account!",
                remediable=global_rule["remediable"],
            ))
            return

        for trail in MOCK_CLOUDTRAILS:
            trail_name = trail["name"]

            # Multi-region CloudTrail check
            if trail.get("is_multi_region", False) and trail.get("is_logging", False):
                self.findings.append(AuditFinding(
                    rule_id=global_rule["id"],
                    rule_name="LOGGING_CLOUDTRAIL_GLOBAL",
                    service=global_rule["service"],
                    resource_id=trail_name,
                    status=FindingStatus.PASS,
                    severity=global_rule["severity"],
                    details=f"CloudTrail '{trail_name}' is enabled and capturing multi-region events.",
                    remediable=global_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=global_rule["id"],
                    rule_name="LOGGING_CLOUDTRAIL_GLOBAL",
                    service=global_rule["service"],
                    resource_id=trail_name,
                    status=FindingStatus.FAIL,
                    severity=global_rule["severity"],
                    details=f"CloudTrail '{trail_name}' IS NOT multi-region or logging is stopped!",
                    remediable=global_rule["remediable"],
                ))

            # Log File Validation check
            if trail.get("log_file_validation", False):
                self.findings.append(AuditFinding(
                    rule_id=val_rule["id"],
                    rule_name="LOGGING_CLOUDTRAIL_VALIDATION",
                    service=val_rule["service"],
                    resource_id=trail_name,
                    status=FindingStatus.PASS,
                    severity=val_rule["severity"],
                    details=f"CloudTrail '{trail_name}' has Log File Validation enabled.",
                    remediable=val_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=val_rule["id"],
                    rule_name="LOGGING_CLOUDTRAIL_VALIDATION",
                    service=val_rule["service"],
                    resource_id=trail_name,
                    status=FindingStatus.FAIL,
                    severity=val_rule["severity"],
                    details=f"CloudTrail '{trail_name}' DOES NOT have log file validation enabled!",
                    remediable=val_rule["remediable"],
                ))

    def _audit_live_aws(self):
        """Audit live CloudTrails via boto3 CloudTrail client."""
        global_rule = CIS_BENCHMARK_RULES["LOGGING_CLOUDTRAIL_GLOBAL"]
        val_rule = CIS_BENCHMARK_RULES["LOGGING_CLOUDTRAIL_VALIDATION"]

        try:
            ct_client = self.get_client("cloudtrail")
            trails_res = ct_client.describe_trails()
            trails = trails_res.get("trailList", [])

            if not trails:
                self.findings.append(AuditFinding(
                    rule_id=global_rule["id"],
                    rule_name="LOGGING_CLOUDTRAIL_GLOBAL",
                    service=global_rule["service"],
                    resource_id="CloudTrail_Service",
                    status=FindingStatus.FAIL,
                    severity=global_rule["severity"],
                    details="No CloudTrail trails configured in account!",
                    remediable=global_rule["remediable"],
                ))
                return

            for trail in trails:
                trail_name = trail.get("Name")
                trail_arn = trail.get("TrailARN", trail_name)
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                log_val = trail.get("LogFileValidationEnabled", False)

                # Check if logging is actively running
                status_res = ct_client.get_trail_status(Name=trail_arn)
                is_logging = status_res.get("IsLogging", False)

                if is_multi_region and is_logging:
                    self.findings.append(AuditFinding(
                        rule_id=global_rule["id"],
                        rule_name="LOGGING_CLOUDTRAIL_GLOBAL",
                        service=global_rule["service"],
                        resource_id=trail_name,
                        status=FindingStatus.PASS,
                        severity=global_rule["severity"],
                        details=f"CloudTrail '{trail_name}' is multi-region and actively logging.",
                        remediable=global_rule["remediable"],
                    ))
                else:
                    self.findings.append(AuditFinding(
                        rule_id=global_rule["id"],
                        rule_name="LOGGING_CLOUDTRAIL_GLOBAL",
                        service=global_rule["service"],
                        resource_id=trail_name,
                        status=FindingStatus.FAIL,
                        severity=global_rule["severity"],
                        details=f"CloudTrail '{trail_name}' multi-region is {is_multi_region}, active logging is {is_logging}!",
                        remediable=global_rule["remediable"],
                    ))

                if log_val:
                    self.findings.append(AuditFinding(
                        rule_id=val_rule["id"],
                        rule_name="LOGGING_CLOUDTRAIL_VALIDATION",
                        service=val_rule["service"],
                        resource_id=trail_name,
                        status=FindingStatus.PASS,
                        severity=val_rule["severity"],
                        details=f"CloudTrail '{trail_name}' log file validation is enabled.",
                        remediable=val_rule["remediable"],
                    ))
                else:
                    self.findings.append(AuditFinding(
                        rule_id=val_rule["id"],
                        rule_name="LOGGING_CLOUDTRAIL_VALIDATION",
                        service=val_rule["service"],
                        resource_id=trail_name,
                        status=FindingStatus.FAIL,
                        severity=val_rule["severity"],
                        details=f"CloudTrail '{trail_name}' log file validation is disabled!",
                        remediable=val_rule["remediable"],
                    ))

        except ClientError as e:
            self.findings.append(
                self.handle_boto_error(e, "CloudTrail_Account", global_rule["id"], "LOGGING_CLOUDTRAIL_GLOBAL", global_rule["service"], global_rule["severity"])
            )
        except Exception as e:
            self.findings.append(AuditFinding(
                rule_id=global_rule["id"],
                rule_name="LOGGING_CLOUDTRAIL_GLOBAL",
                service=global_rule["service"],
                resource_id="CloudTrail_Account",
                status=FindingStatus.ERROR,
                severity="KRITIS",
                details=f"Error auditing CloudTrail: {str(e)}",
                remediable=False,
            ))
