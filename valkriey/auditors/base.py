"""
Base classes and data models for VALKRIEY Auditors.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    REMEDIATED = "REMEDIATED"


class AuditFinding(BaseModel):
    rule_id: str
    rule_name: str
    service: str
    resource_id: str
    status: FindingStatus
    severity: str
    details: str
    remediable: bool = False


class AuditSummary(BaseModel):
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    error_checks: int = 0
    remediated_checks: int = 0
    compliance_score: float = 0.0
    risk_category: str = "UNKNOWN"
    findings: List[AuditFinding] = Field(default_factory=list)


class BaseAuditor:
    """Base class for AWS service auditors with rate limit & error handling."""

    def __init__(self, region_name: str = "us-east-1", dry_run: bool = False):
        self.region_name = region_name
        self.dry_run = dry_run
        self.findings: List[AuditFinding] = []

    def get_client(self, service_name: str):
        """Safely initialize boto3 client with regional fallback."""
        try:
            return boto3.client(service_name, region_name=self.region_name)
        except (NoCredentialsError, PartialCredentialsError) as e:
            raise PermissionError(f"AWS Credentials missing or invalid for {service_name}: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize AWS client for {service_name}: {str(e)}")

    def handle_boto_error(self, error: ClientError, resource_id: str, rule_id: str, rule_name: str, service: str, severity: str) -> AuditFinding:
        """Handle AWS ClientError exceptions, specifically rate limits & access denied."""
        error_code = error.response.get("Error", {}).get("Code", "Unknown")
        error_msg = error.response.get("Error", {}).get("Message", str(error))

        if error_code in ["Throttling", "RequestLimitExceeded", "TooManyRequestsException"]:
            details = f"AWS API Rate Limit exceeded for {resource_id} ({error_code}): {error_msg}"
        elif error_code in ["AccessDenied", "UnauthorizedOperation", "AccessDeniedException"]:
            details = f"Insufficient AWS IAM permissions to audit {resource_id}: {error_msg}"
        else:
            details = f"AWS ClientError ({error_code}) on {resource_id}: {error_msg}"

        return AuditFinding(
            rule_id=rule_id,
            rule_name=rule_name,
            service=service,
            resource_id=resource_id,
            status=FindingStatus.ERROR,
            severity=severity,
            details=details,
            remediable=False,
        )
