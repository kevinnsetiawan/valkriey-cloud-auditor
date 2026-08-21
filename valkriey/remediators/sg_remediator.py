"""
Security Group Auto-Remediator for VALKRIEY.
Revokes unrestricted 0.0.0.0/0 ingress rules on sensitive ports (22, 3389, 5432, 27017).
"""

from typing import Dict, Any, List
import boto3
from botocore.exceptions import ClientError
from valkriey.config.rules import SENSITIVE_PORTS
from valkriey.engine.mock_data import MOCK_SECURITY_GROUPS


class SecurityGroupRemediator:
    """Remediates Security Group unrestricted ingress misconfigurations."""

    def __init__(self, region_name: str = "us-east-1", dry_run: bool = False):
        self.region_name = region_name
        self.dry_run = dry_run

    def revoke_sensitive_ingress(self, sg_id: str) -> Dict[str, Any]:
        """Revoke 0.0.0.0/0 ingress rules on sensitive ports for the specified Security Group."""
        # Strip name suffix if formatted like "sg-xxxx (name)"
        clean_sg_id = sg_id.split(" ")[0].strip()

        if self.dry_run:
            # Simulate remediation on mock data
            revoked_ports = []
            for sg in MOCK_SECURITY_GROUPS:
                if sg["id"] == clean_sg_id:
                    new_permissions = []
                    for perm in sg.get("ip_permissions", []):
                        from_port = perm.get("from_port")
                        to_port = perm.get("to_port")
                        proto = perm.get("ip_protocol")
                        ip_ranges = [r.get("CidrIp") for r in perm.get("ip_ranges", [])]

                        if "0.0.0.0/0" in ip_ranges:
                            # Check if sensitive port
                            is_sensitive = False
                            for port in SENSITIVE_PORTS.keys():
                                if proto == "-1" or (from_port is not None and to_port is not None and from_port <= port <= to_port):
                                    is_sensitive = True
                                    revoked_ports.append(port)
                            if not is_sensitive:
                                new_permissions.append(perm)
                        else:
                            new_permissions.append(perm)
                    sg["ip_permissions"] = new_permissions

            return {
                "status": "SUCCESS",
                "message": f"[DRY-RUN SIMULATION] Revoked 0.0.0.0/0 ingress rules for sensitive ports on Security Group '{clean_sg_id}'.",
                "sg_id": clean_sg_id,
            }

        try:
            ec2_client = boto3.client("ec2", region_name=self.region_name)
            sg_desc = ec2_client.describe_security_groups(GroupIds=[clean_sg_id])
            sgs = sg_desc.get("SecurityGroups", [])
            if not sgs:
                return {"status": "FAILED", "message": f"Security Group '{clean_sg_id}' not found.", "sg_id": clean_sg_id}

            revoked_count = 0
            for perm in sgs[0].get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                proto = perm.get("IpProtocol")
                ip_ranges = [r.get("CidrIp") for r in perm.get("IpRanges", [])]

                if "0.0.0.0/0" in ip_ranges:
                    for port in SENSITIVE_PORTS.keys():
                        if proto == "-1" or (from_port is not None and to_port is not None and from_port <= port <= to_port):
                            ec2_client.revoke_security_group_ingress(
                                GroupId=clean_sg_id,
                                IpPermissions=[{
                                    "IpProtocol": proto,
                                    "FromPort": from_port,
                                    "ToPort": to_port,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                }]
                            )
                            revoked_count += 1

            return {
                "status": "SUCCESS",
                "message": f"Revoked {revoked_count} sensitive 0.0.0.0/0 ingress rule(s) on Security Group '{clean_sg_id}'.",
                "sg_id": clean_sg_id,
            }
        except ClientError as e:
            return {
                "status": "FAILED",
                "message": f"Failed to revoke ingress rules on '{clean_sg_id}': {e.response.get('Error', {}).get('Message', str(e))}",
                "sg_id": clean_sg_id,
            }
        except Exception as e:
            return {
                "status": "FAILED",
                "message": f"Error remediating Security Group '{clean_sg_id}': {str(e)}",
                "sg_id": clean_sg_id,
            }
