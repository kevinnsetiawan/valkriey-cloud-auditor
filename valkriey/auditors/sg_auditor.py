"""
Security Group Auditor for VALKRIEY.
Audits EC2 Security Groups for unrestricted 0.0.0.0/0 inbound access on sensitive ports (22, 3389, 5432, 27017).
"""

from typing import List
from botocore.exceptions import ClientError
from valkriey.auditors.base import BaseAuditor, AuditFinding, FindingStatus
from valkriey.config.rules import CIS_BENCHMARK_RULES, SENSITIVE_PORTS
from valkriey.engine.mock_data import MOCK_SECURITY_GROUPS


class SecurityGroupAuditor(BaseAuditor):
    """Audits AWS EC2 Security Groups against CIS Security Benchmarks."""

    def run_audit(self) -> List[AuditFinding]:
        self.findings = []
        if self.dry_run:
            self._audit_mock_data()
        else:
            self._audit_live_aws()
        return self.findings

    def _audit_mock_data(self):
        """Audit mock security groups for dry-run testing."""
        rule_meta = CIS_BENCHMARK_RULES["SG_UNRESTRICTED_INBOUND"]
        for sg in MOCK_SECURITY_GROUPS:
            sg_id = sg["id"]
            sg_name = sg.get("name", sg_id)
            unrestricted_ports = []

            for ip_permission in sg.get("ip_permissions", []):
                from_port = ip_permission.get("from_port")
                to_port = ip_permission.get("to_port")
                ip_protocol = ip_permission.get("ip_protocol")
                ip_ranges = [r.get("CidrIp") for r in ip_permission.get("ip_ranges", [])]

                if "0.0.0.0/0" in ip_ranges:
                    for port, port_name in SENSITIVE_PORTS.items():
                        # Handle -1 (all protocols/ports) or port range inclusion
                        if ip_protocol == "-1" or (from_port is not None and to_port is not None and from_port <= port <= to_port):
                            unrestricted_ports.append(f"{port} ({port_name})")

            if unrestricted_ports:
                ports_str = ", ".join(unrestricted_ports)
                self.findings.append(AuditFinding(
                    rule_id=rule_meta["id"],
                    rule_name="SG_UNRESTRICTED_INBOUND",
                    service=rule_meta["service"],
                    resource_id=f"{sg_id} ({sg_name})",
                    status=FindingStatus.FAIL,
                    severity=rule_meta["severity"],
                    details=f"Security Group '{sg_id}' allows unrestricted 0.0.0.0/0 inbound access on sensitive ports: {ports_str}!",
                    remediable=rule_meta["remediable"],
                ))
            else:
                self.findings.append(AuditFinding(
                    rule_id=rule_meta["id"],
                    rule_name="SG_UNRESTRICTED_INBOUND",
                    service=rule_meta["service"],
                    resource_id=f"{sg_id} ({sg_name})",
                    status=FindingStatus.PASS,
                    severity=rule_meta["severity"],
                    details=f"Security Group '{sg_id}' has NO unrestricted 0.0.0.0/0 ingress on sensitive ports.",
                    remediable=rule_meta["remediable"],
                ))

    def _audit_live_aws(self):
        """Audit live Security Groups via boto3 EC2 client."""
        rule_meta = CIS_BENCHMARK_RULES["SG_UNRESTRICTED_INBOUND"]
        try:
            ec2_client = self.get_client("ec2")
            response = ec2_client.describe_security_groups()
            security_groups = response.get("SecurityGroups", [])

            for sg in security_groups:
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName", sg_id)
                unrestricted_ports = []

                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    proto = perm.get("IpProtocol")
                    ip_ranges = [r.get("CidrIp") for r in perm.get("IpRanges", [])]

                    if "0.0.0.0/0" in ip_ranges:
                        for port, port_name in SENSITIVE_PORTS.items():
                            if proto == "-1" or (from_port is not None and to_port is not None and from_port <= port <= to_port):
                                unrestricted_ports.append(f"{port} ({port_name})")

                if unrestricted_ports:
                    ports_str = ", ".join(unrestricted_ports)
                    self.findings.append(AuditFinding(
                        rule_id=rule_meta["id"],
                        rule_name="SG_UNRESTRICTED_INBOUND",
                        service=rule_meta["service"],
                        resource_id=f"{sg_id} ({sg_name})",
                        status=FindingStatus.FAIL,
                        severity=rule_meta["severity"],
                        details=f"Security Group '{sg_id}' allows unrestricted 0.0.0.0/0 inbound access on sensitive ports: {ports_str}!",
                        remediable=rule_meta["remediable"],
                    ))
                else:
                    self.findings.append(AuditFinding(
                        rule_id=rule_meta["id"],
                        rule_name="SG_UNRESTRICTED_INBOUND",
                        service=rule_meta["service"],
                        resource_id=f"{sg_id} ({sg_name})",
                        status=FindingStatus.PASS,
                        severity=rule_meta["severity"],
                        details=f"Security Group '{sg_id}' has NO unrestricted 0.0.0.0/0 ingress on sensitive ports.",
                        remediable=rule_meta["remediable"],
                    ))

        except ClientError as e:
            self.findings.append(
                self.handle_boto_error(e, "EC2_SecurityGroups", rule_meta["id"], "SG_UNRESTRICTED_INBOUND", rule_meta["service"], rule_meta["severity"])
            )
        except Exception as e:
            self.findings.append(AuditFinding(
                rule_id=rule_meta["id"],
                rule_name="SG_UNRESTRICTED_INBOUND",
                service=rule_meta["service"],
                resource_id="EC2_SecurityGroups",
                status=FindingStatus.ERROR,
                severity=rule_meta["severity"],
                details=f"Error listing Security Groups: {str(e)}",
                remediable=False,
            ))
