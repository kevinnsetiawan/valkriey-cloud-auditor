"""
S3 Security Auditor for VALKRIEY.
Audits S3 Buckets for Public Access Block, Default Encryption, and Server Access Logging.
"""

from typing import List
from botocore.exceptions import ClientError
from valkriey.auditors.base import BaseAuditor, AuditFinding, FindingStatus
from valkriey.config.rules import CIS_BENCHMARK_RULES
from valkriey.engine.mock_data import MOCK_S3_BUCKETS


class S3Auditor(BaseAuditor):
    """Audits AWS S3 Buckets against CIS Security Benchmarks."""

    def run_audit(self) -> List[AuditFinding]:
        self.findings = []
        if self.dry_run:
            self._audit_mock_data()
        else:
            self._audit_live_aws()
        return self.findings

    def _audit_mock_data(self):
        """Audit mock S3 buckets for dry-run testing."""
        for bucket in MOCK_S3_BUCKETS:
            bucket_name = bucket["name"]
            
            # 1. Public Access Block Check
            pab_rule = CIS_BENCHMARK_RULES["S3_PUBLIC_ACCESS_BLOCK"]
            if bucket.get("public_access_block", {}).get("BlockPublicAcls", False) and \
               bucket.get("public_access_block", {}).get("BlockPublicPolicy", False) and \
               bucket.get("public_access_block", {}).get("IgnorePublicAcls", False) and \
               bucket.get("public_access_block", {}).get("RestrictPublicBuckets", False):
                self.findings.append(AuditFinding(
                    rule_id=pab_rule["id"],
                    rule_name="S3_PUBLIC_ACCESS_BLOCK",
                    service=pab_rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.PASS,
                    severity=pab_rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' has Public Access Block fully enabled.",
                    remediable=pab_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=pab_rule["id"],
                    rule_name="S3_PUBLIC_ACCESS_BLOCK",
                    service=pab_rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=pab_rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' DOES NOT have Public Access Block fully enabled!",
                    remediable=pab_rule["remediable"],
                ))

            # 2. Server-Side Encryption Check
            enc_rule = CIS_BENCHMARK_RULES["S3_DEFAULT_ENCRYPTION"]
            if bucket.get("encryption", {}).get("enabled", False):
                self.findings.append(AuditFinding(
                    rule_id=enc_rule["id"],
                    rule_name="S3_DEFAULT_ENCRYPTION",
                    service=enc_rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.PASS,
                    severity=enc_rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' has Server-Side Encryption enabled ({bucket['encryption'].get('type', 'AES256')}).",
                    remediable=enc_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=enc_rule["id"],
                    rule_name="S3_DEFAULT_ENCRYPTION",
                    service=enc_rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=enc_rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' DOES NOT have default server-side encryption enabled!",
                    remediable=enc_rule["remediable"],
                ))

            # 3. Server Access Logging Check
            log_rule = CIS_BENCHMARK_RULES["S3_SERVER_LOGGING"]
            if bucket.get("logging", {}).get("enabled", False):
                self.findings.append(AuditFinding(
                    rule_id=log_rule["id"],
                    rule_name="S3_SERVER_LOGGING",
                    service=log_rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.PASS,
                    severity=log_rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' has Server Access Logging enabled.",
                    remediable=log_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=log_rule["id"],
                    rule_name="S3_SERVER_LOGGING",
                    service=log_rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=log_rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' DOES NOT have server access logging configured!",
                    remediable=log_rule["remediable"],
                ))

    def _audit_live_aws(self):
        """Audit live S3 buckets via boto3 API."""
        try:
            s3_client = self.get_client("s3")
            response = s3_client.list_buckets()
            buckets = response.get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]
                self._check_public_access_block(s3_client, bucket_name)
                self._check_encryption(s3_client, bucket_name)
                self._check_logging(s3_client, bucket_name)

        except ClientError as e:
            rule = CIS_BENCHMARK_RULES["S3_PUBLIC_ACCESS_BLOCK"]
            self.findings.append(
                self.handle_boto_error(e, "S3_Account", rule["id"], "S3_SERVICE", rule["service"], rule["severity"])
            )
        except Exception as e:
            rule = CIS_BENCHMARK_RULES["S3_PUBLIC_ACCESS_BLOCK"]
            self.findings.append(AuditFinding(
                rule_id=rule["id"],
                rule_name="S3_SERVICE",
                service="S3",
                resource_id="S3_Account",
                status=FindingStatus.ERROR,
                severity="KRITIS",
                details=f"Error listing S3 buckets: {str(e)}",
                remediable=False,
            ))

    def _check_public_access_block(self, s3_client, bucket_name: str):
        rule = CIS_BENCHMARK_RULES["S3_PUBLIC_ACCESS_BLOCK"]
        try:
            res = s3_client.get_public_access_block(Bucket=bucket_name)
            pab = res.get("PublicAccessBlockConfiguration", {})
            if pab.get("BlockPublicAcls") and pab.get("IgnorePublicAcls") and \
               pab.get("BlockPublicPolicy") and pab.get("RestrictPublicBuckets"):
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_PUBLIC_ACCESS_BLOCK",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.PASS,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' has Public Access Block fully enabled.",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_PUBLIC_ACCESS_BLOCK",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' Public Access Block is partially or completely disabled!",
                    remediable=rule["remediable"],
                ))
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_PUBLIC_ACCESS_BLOCK",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' has NO Public Access Block configuration set!",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(
                    self.handle_boto_error(e, bucket_name, rule["id"], "S3_PUBLIC_ACCESS_BLOCK", rule["service"], rule["severity"])
                )

    def _check_encryption(self, s3_client, bucket_name: str):
        rule = CIS_BENCHMARK_RULES["S3_DEFAULT_ENCRYPTION"]
        try:
            res = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_DEFAULT_ENCRYPTION",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.PASS,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' has default server-side encryption enabled.",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_DEFAULT_ENCRYPTION",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' encryption configuration is empty!",
                    remediable=rule["remediable"],
                ))
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_DEFAULT_ENCRYPTION",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' DOES NOT have default server-side encryption configured!",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(
                    self.handle_boto_error(e, bucket_name, rule["id"], "S3_DEFAULT_ENCRYPTION", rule["service"], rule["severity"])
                )

    def _check_logging(self, s3_client, bucket_name: str):
        rule = CIS_BENCHMARK_RULES["S3_SERVER_LOGGING"]
        try:
            res = s3_client.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" in res:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_SERVER_LOGGING",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.PASS,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' has server access logging enabled to '{res['LoggingEnabled'].get('TargetBucket')}'.",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="S3_SERVER_LOGGING",
                    service=rule["service"],
                    resource_id=bucket_name,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"S3 Bucket '{bucket_name}' server access logging is disabled!",
                    remediable=rule["remediable"],
                ))
        except ClientError as e:
            self.findings.append(
                self.handle_boto_error(e, bucket_name, rule["id"], "S3_SERVER_LOGGING", rule["service"], rule["severity"])
            )
