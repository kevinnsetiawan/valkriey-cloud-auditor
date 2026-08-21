"""
CIS Benchmark Rules and Security Configuration Thresholds.
"""

from typing import Dict, Any, List

# CIS Benchmark Mappings & Security Rule Metadata
CIS_BENCHMARK_RULES: Dict[str, Dict[str, Any]] = {
    # S3 Rules
    "S3_PUBLIC_ACCESS_BLOCK": {
        "id": "CIS-AWS-2.1.5",
        "title": "Ensure S3 Buckets Have Public Access Block Enabled",
        "service": "S3",
        "severity": "KRITIS",
        "description": "S3 buckets must block public read/write access to prevent data leaks.",
        "remediable": True,
    },
    "S3_DEFAULT_ENCRYPTION": {
        "id": "CIS-AWS-2.1.1",
        "title": "Ensure S3 Bucket Server-Side Encryption is Enabled",
        "service": "S3",
        "severity": "TINGGI",
        "description": "S3 buckets should encrypt sensitive data at rest using AES-256 or AWS KMS.",
        "remediable": False,
    },
    "S3_SERVER_LOGGING": {
        "id": "CIS-AWS-2.1.2",
        "title": "Ensure S3 Bucket Access Logging is Enabled",
        "service": "S3",
        "severity": "SEDANG",
        "description": "Server access logging records requests made to an S3 bucket for security audits.",
        "remediable": False,
    },
    # Security Group Rules
    "SG_UNRESTRICTED_INBOUND": {
        "id": "CIS-AWS-5.2",
        "title": "Ensure No Security Groups Allow Inbound 0.0.0.0/0 on Sensitive Ports",
        "service": "EC2/VPC",
        "severity": "KRITIS",
        "description": "Security Groups must not expose sensitive ports (22, 3389, 5432, 27017) to 0.0.0.0/0.",
        "remediable": True,
    },
    # IAM Rules
    "IAM_ROOT_USAGE": {
        "id": "CIS-AWS-1.1",
        "title": "Avoid Root User Access Key Usage and Active Root Account",
        "service": "IAM",
        "severity": "KRITIS",
        "description": "The root account should not have active access keys or be used for everyday tasks.",
        "remediable": False,
    },
    "IAM_MFA_ENABLED": {
        "id": "CIS-AWS-1.5",
        "title": "Ensure MFA is Enabled for All IAM Users with Console Access",
        "service": "IAM",
        "severity": "TINGGI",
        "description": "Multi-Factor Authentication (MFA) adds a vital layer of security to IAM user accounts.",
        "remediable": False,
    },
    "IAM_UNUSED_KEYS": {
        "id": "CIS-AWS-1.12",
        "title": "Ensure Credentials Unused for 90 Days Or Greater Are Disabled",
        "service": "IAM",
        "severity": "TINGGI",
        "description": "Access keys older than 90 days or unused should be rotated or deactivated.",
        "remediable": False,
    },
    "IAM_ADMIN_DIRECT_POLICY": {
        "id": "CIS-AWS-1.16",
        "title": "Ensure IAM Policies Are Attached Only to Groups/Roles, Not Directly to Users",
        "service": "IAM",
        "severity": "SEDANG",
        "description": "Attach permissions to IAM groups or roles rather than individual users for proper RBAC.",
        "remediable": False,
    },
    # CloudTrail Rules
    "LOGGING_CLOUDTRAIL_GLOBAL": {
        "id": "CIS-AWS-3.1",
        "title": "Ensure CloudTrail is Enabled Across All Regions",
        "service": "CloudTrail",
        "severity": "KRITIS",
        "description": "CloudTrail must be active in all regions to capture multi-region API activity.",
        "remediable": False,
    },
    "LOGGING_CLOUDTRAIL_VALIDATION": {
        "id": "CIS-AWS-3.2",
        "title": "Ensure CloudTrail Log File Validation is Enabled",
        "service": "CloudTrail",
        "severity": "TINGGI",
        "description": "Log file validation guarantees that log files are tamper-evident and unchanged.",
        "remediable": False,
    },
}

# Sensitive Port Mapping
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    27017: "MongoDB",
}

# Key Age Thresholds
ACCESS_KEY_MAX_AGE_DAYS: int = 90

# Risk Levels & Color Codes
RISK_LEVEL_COLORS: Dict[str, str] = {
    "KRITIS": "bold red",
    "TINGGI": "bold orange3",
    "SEDANG": "bold yellow",
    "RENDAH": "bold green",
}
