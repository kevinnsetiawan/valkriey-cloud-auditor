"""
Mock AWS Data for VALKRIEY --dry-run and testing modes.
Contains realistic AWS configurations including vulnerable resources.
"""

from typing import List, Dict, Any

# Mock S3 Buckets
MOCK_S3_BUCKETS: List[Dict[str, Any]] = [
    {
        "name": "prod-customer-data-bucket",
        "public_access_block": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        },
        "encryption": {"enabled": True, "type": "aws:kms"},
        "logging": {"enabled": True, "TargetBucket": "prod-s3-logs-bucket"},
    },
    {
        "name": "staging-assets-public",
        "public_access_block": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        },
        "encryption": {"enabled": False},
        "logging": {"enabled": False},
    },
    {
        "name": "secure-finance-records-2026",
        "public_access_block": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
        "encryption": {"enabled": True, "type": "AES256"},
        "logging": {"enabled": True, "TargetBucket": "secure-audit-logs"},
    },
]

# Mock EC2 Security Groups
MOCK_SECURITY_GROUPS: List[Dict[str, Any]] = [
    {
        "id": "sg-0123456789abcdef0",
        "name": "web-server-public-sg",
        "ip_permissions": [
            {
                "from_port": 80,
                "to_port": 80,
                "ip_protocol": "tcp",
                "ip_ranges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "from_port": 22,
                "to_port": 22,
                "ip_protocol": "tcp",
                "ip_ranges": [{"CidrIp": "0.0.0.0/0"}],  # VULNERABLE SSH
            },
        ],
    },
    {
        "id": "sg-0987654321fedcba0",
        "name": "db-cluster-sg",
        "ip_permissions": [
            {
                "from_port": 5432,
                "to_port": 5432,
                "ip_protocol": "tcp",
                "ip_ranges": [{"CidrIp": "0.0.0.0/0"}],  # VULNERABLE Postgres
            },
            {
                "from_port": 27017,
                "to_port": 27017,
                "ip_protocol": "tcp",
                "ip_ranges": [{"CidrIp": "0.0.0.0/0"}],  # VULNERABLE Mongo
            },
        ],
    },
    {
        "id": "sg-0aaa1bbb2ccc3ddd4",
        "name": "internal-app-sg",
        "ip_permissions": [
            {
                "from_port": 443,
                "to_port": 443,
                "ip_protocol": "tcp",
                "ip_ranges": [{"CidrIp": "10.0.0.0/16"}],
            },
        ],
    },
]

# Mock IAM Root Account Status
MOCK_ROOT_ACCOUNT: Dict[str, Any] = {
    "has_access_keys": True,  # VULNERABLE
    "mfa_enabled": False,     # VULNERABLE
}

# Mock IAM Users
MOCK_IAM_USERS: List[Dict[str, Any]] = [
    {
        "username": "alice_admin",
        "mfa_enabled": True,
        "access_keys": [
            {"id": "AKIAIOSFODNN7EXAMPLE", "age_days": 120},  # STALE KEY (>90 days)
        ],
        "attached_policies": ["AdministratorAccess"],  # DIRECT ADMIN POLICY ATTACHED
    },
    {
        "username": "bob_developer",
        "mfa_enabled": False,  # NO MFA
        "access_keys": [
            {"id": "AKIAI44444444EXAMPLE", "age_days": 45},
        ],
        "attached_policies": ["PowerUserAccess"],
    },
    {
        "username": "charlie_readonly",
        "mfa_enabled": True,
        "access_keys": [
            {"id": "AKIAI88888888EXAMPLE", "age_days": 15},
        ],
        "attached_policies": ["ReadOnlyAccess"],
    },
]

# Mock CloudTrail Status
MOCK_CLOUDTRAILS: List[Dict[str, Any]] = [
    {
        "name": "organization-global-trail",
        "is_multi_region": True,
        "is_logging": True,
        "log_file_validation": True,
    },
    {
        "name": "dev-regional-trail",
        "is_multi_region": False,  # VULNERABLE: Not Multi-Region
        "is_logging": True,
        "log_file_validation": False,  # VULNERABLE: Log Validation disabled
    },
]
