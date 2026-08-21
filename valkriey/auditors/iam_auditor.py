"""
IAM Security Auditor for VALKRIEY.
Audits IAM Root Account, MFA compliance, Access Key Age (>90 days), and Direct Admin Policies.
"""

import datetime
from typing import List
from botocore.exceptions import ClientError
from valkriey.auditors.base import BaseAuditor, AuditFinding, FindingStatus
from valkriey.config.rules import CIS_BENCHMARK_RULES, ACCESS_KEY_MAX_AGE_DAYS
from valkriey.engine.mock_data import MOCK_IAM_USERS, MOCK_ROOT_ACCOUNT


class IAMAuditor(BaseAuditor):
    """Audits AWS IAM configurations against CIS Security Benchmarks."""

    def run_audit(self) -> List[AuditFinding]:
        self.findings = []
        if self.dry_run:
            self._audit_mock_data()
        else:
            self._audit_live_aws()
        return self.findings

    def _audit_mock_data(self):
        """Audit mock IAM users & root account for dry-run testing."""
        # 1. Root Account Check
        root_rule = CIS_BENCHMARK_RULES["IAM_ROOT_USAGE"]
        if MOCK_ROOT_ACCOUNT.get("has_access_keys", False) or MOCK_ROOT_ACCOUNT.get("mfa_enabled", False) is False:
            self.findings.append(AuditFinding(
                rule_id=root_rule["id"],
                rule_name="IAM_ROOT_USAGE",
                service=root_rule["service"],
                resource_id="root_account",
                status=FindingStatus.FAIL,
                severity=root_rule["severity"],
                details="AWS Root Account has active access keys or lacks MFA enabled!",
                remediable=root_rule["remediable"],
            ))
        else:
            self.findings.append(AuditFinding(
                rule_id=root_rule["id"],
                rule_name="IAM_ROOT_USAGE",
                service=root_rule["service"],
                resource_id="root_account",
                status=FindingStatus.PASS,
                severity=root_rule["severity"],
                details="AWS Root Account is properly secured without active access keys and has MFA enabled.",
                remediable=root_rule["remediable"],
            ))

        # 2. IAM User Audits
        mfa_rule = CIS_BENCHMARK_RULES["IAM_MFA_ENABLED"]
        key_rule = CIS_BENCHMARK_RULES["IAM_UNUSED_KEYS"]
        pol_rule = CIS_BENCHMARK_RULES["IAM_ADMIN_DIRECT_POLICY"]

        for user in MOCK_IAM_USERS:
            username = user["username"]

            # MFA Check
            if user.get("mfa_enabled", False):
                self.findings.append(AuditFinding(
                    rule_id=mfa_rule["id"],
                    rule_name="IAM_MFA_ENABLED",
                    service=mfa_rule["service"],
                    resource_id=username,
                    status=FindingStatus.PASS,
                    severity=mfa_rule["severity"],
                    details=f"IAM User '{username}' has MFA enabled.",
                    remediable=mfa_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=mfa_rule["id"],
                    rule_name="IAM_MFA_ENABLED",
                    service=mfa_rule["service"],
                    resource_id=username,
                    status=FindingStatus.FAIL,
                    severity=mfa_rule["severity"],
                    details=f"IAM User '{username}' DOES NOT have MFA enabled!",
                    remediable=mfa_rule["remediable"],
                ))

            # Access Key Age Check
            stale_keys = [k["id"] for k in user.get("access_keys", []) if k.get("age_days", 0) > ACCESS_KEY_MAX_AGE_DAYS]
            if stale_keys:
                self.findings.append(AuditFinding(
                    rule_id=key_rule["id"],
                    rule_name="IAM_UNUSED_KEYS",
                    service=key_rule["service"],
                    resource_id=username,
                    status=FindingStatus.FAIL,
                    severity=key_rule["severity"],
                    details=f"IAM User '{username}' has access key(s) older than {ACCESS_KEY_MAX_AGE_DAYS} days: {', '.join(stale_keys)}!",
                    remediable=key_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=key_rule["id"],
                    rule_name="IAM_UNUSED_KEYS",
                    service=key_rule["service"],
                    resource_id=username,
                    status=FindingStatus.PASS,
                    severity=key_rule["severity"],
                    details=f"IAM User '{username}' has no stale access keys (>90 days).",
                    remediable=key_rule["remediable"],
                ))

            # Direct Admin Policy Check
            direct_policies = user.get("attached_policies", [])
            has_admin = any("AdministratorAccess" in p or "Admin" in p for p in direct_policies)
            if has_admin:
                self.findings.append(AuditFinding(
                    rule_id=pol_rule["id"],
                    rule_name="IAM_ADMIN_DIRECT_POLICY",
                    service=pol_rule["service"],
                    resource_id=username,
                    status=FindingStatus.FAIL,
                    severity=pol_rule["severity"],
                    details=f"IAM User '{username}' has Administrator policies attached directly to the user!",
                    remediable=pol_rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=pol_rule["id"],
                    rule_name="IAM_ADMIN_DIRECT_POLICY",
                    service=pol_rule["service"],
                    resource_id=username,
                    status=FindingStatus.PASS,
                    severity=pol_rule["severity"],
                    details=f"IAM User '{username}' does not have direct Administrator policy attachments.",
                    remediable=pol_rule["remediable"],
                ))

    def _audit_live_aws(self):
        """Audit live IAM configurations via boto3 IAM client."""
        try:
            iam_client = self.get_client("iam")
            
            # Root Account Summary
            self._audit_root_account(iam_client)

            # Audit Users
            users_res = iam_client.list_users()
            for user in users_res.get("Users", []):
                username = user["UserName"]
                self._check_user_mfa(iam_client, username)
                self._check_user_access_keys(iam_client, username)
                self._check_user_attached_policies(iam_client, username)

        except ClientError as e:
            rule = CIS_BENCHMARK_RULES["IAM_ROOT_USAGE"]
            self.findings.append(
                self.handle_boto_error(e, "IAM_Account", rule["id"], "IAM_SERVICE", rule["service"], rule["severity"])
            )
        except Exception as e:
            rule = CIS_BENCHMARK_RULES["IAM_ROOT_USAGE"]
            self.findings.append(AuditFinding(
                rule_id=rule["id"],
                rule_name="IAM_SERVICE",
                service="IAM",
                resource_id="IAM_Account",
                status=FindingStatus.ERROR,
                severity="KRITIS",
                details=f"Error auditing IAM: {str(e)}",
                remediable=False,
            ))

    def _audit_root_account(self, iam_client):
        rule = CIS_BENCHMARK_RULES["IAM_ROOT_USAGE"]
        try:
            summary = iam_client.get_account_summary().get("SummaryMap", {})
            root_keys = summary.get("AccountAccessKeysPresent", 0)
            root_mfa = summary.get("AccountMFAEnabled", 0)

            if root_keys > 0 or root_mfa == 0:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_ROOT_USAGE",
                    service=rule["service"],
                    resource_id="root_account",
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"Root Account Has Access Keys: {root_keys > 0}, MFA Enabled: {root_mfa == 1}.",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_ROOT_USAGE",
                    service=rule["service"],
                    resource_id="root_account",
                    status=FindingStatus.PASS,
                    severity=rule["severity"],
                    details="Root Account has no access keys and MFA is enabled.",
                    remediable=rule["remediable"],
                ))
        except ClientError as e:
            self.findings.append(
                self.handle_boto_error(e, "root_account", rule["id"], "IAM_ROOT_USAGE", rule["service"], rule["severity"])
            )

    def _check_user_mfa(self, iam_client, username: str):
        rule = CIS_BENCHMARK_RULES["IAM_MFA_ENABLED"]
        try:
            res = iam_client.list_mfa_devices(UserName=username)
            devices = res.get("MFADevices", [])
            if devices:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_MFA_ENABLED",
                    service=rule["service"],
                    resource_id=username,
                    status=FindingStatus.PASS,
                    severity=rule["severity"],
                    details=f"IAM User '{username}' has MFA device configured.",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_MFA_ENABLED",
                    service=rule["service"],
                    resource_id=username,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"IAM User '{username}' DOES NOT have an MFA device configured!",
                    remediable=rule["remediable"],
                ))
        except ClientError as e:
            self.findings.append(
                self.handle_boto_error(e, username, rule["id"], "IAM_MFA_ENABLED", rule["service"], rule["severity"])
            )

    def _check_user_access_keys(self, iam_client, username: str):
        rule = CIS_BENCHMARK_RULES["IAM_UNUSED_KEYS"]
        try:
            res = iam_client.list_access_keys(UserName=username)
            keys = res.get("AccessKeyMetadata", [])
            now = datetime.datetime.now(datetime.timezone.utc)
            stale_keys = []

            for k in keys:
                create_date = k.get("CreateDate")
                if create_date:
                    age_days = (now - create_date).days
                    if age_days > ACCESS_KEY_MAX_AGE_DAYS:
                        stale_keys.append(f"{k['AccessKeyId']} ({age_days} days old)")

            if stale_keys:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_UNUSED_KEYS",
                    service=rule["service"],
                    resource_id=username,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"IAM User '{username}' has stale access key(s): {', '.join(stale_keys)}!",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_UNUSED_KEYS",
                    service=rule["service"],
                    resource_id=username,
                    status=FindingStatus.PASS,
                    severity=rule["severity"],
                    details=f"IAM User '{username}' has no stale access keys (>90 days).",
                    remediable=rule["remediable"],
                ))
        except ClientError as e:
            self.findings.append(
                self.handle_boto_error(e, username, rule["id"], "IAM_UNUSED_KEYS", rule["service"], rule["severity"])
            )

    def _check_user_attached_policies(self, iam_client, username: str):
        rule = CIS_BENCHMARK_RULES["IAM_ADMIN_DIRECT_POLICY"]
        try:
            res = iam_client.list_attached_user_policies(UserName=username)
            policies = res.get("AttachedPolicies", [])
            admin_attached = [p["PolicyName"] for p in policies if "AdministratorAccess" in p["PolicyName"] or "Admin" in p["PolicyName"]]

            if admin_attached:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_ADMIN_DIRECT_POLICY",
                    service=rule["service"],
                    resource_id=username,
                    status=FindingStatus.FAIL,
                    severity=rule["severity"],
                    details=f"IAM User '{username}' has direct Administrator policy attached: {', '.join(admin_attached)}!",
                    remediable=rule["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule["id"],
                    rule_name="IAM_ADMIN_DIRECT_POLICY",
                    service=rule["service"],
                    resource_id=username,
                    status=FindingStatus.PASS,
                    severity=rule["severity"],
                    details=f"IAM User '{username}' has no direct Administrator policy attachments.",
                    remediable=rule["remediable"],
                ))
        except ClientError as e:
            self.findings.append(
                self.handle_boto_error(e, username, rule["id"], "IAM_ADMIN_DIRECT_POLICY", rule["service"], rule["severity"])
            )
