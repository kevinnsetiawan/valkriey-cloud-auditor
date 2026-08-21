"""
S3 Auto-Remediator for VALKRIEY.
Enables Public Access Block on vulnerable S3 buckets.
"""

from typing import Dict, Any
import boto3
from botocore.exceptions import ClientError
from valkriey.engine.mock_data import MOCK_S3_BUCKETS


class S3Remediator:
    """Remediates S3 Public Access Block misconfigurations."""

    def __init__(self, region_name: str = "us-east-1", dry_run: bool = False):
        self.region_name = region_name
        self.dry_run = dry_run

    def block_public_access(self, bucket_name: str) -> Dict[str, Any]:
        """Apply Public Access Block configuration to target bucket."""
        if self.dry_run:
            # Simulate remediation on mock data
            for bucket in MOCK_S3_BUCKETS:
                if bucket["name"] == bucket_name:
                    bucket["public_access_block"] = {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    }
            return {
                "status": "SUCCESS",
                "message": f"[DRY-RUN SIMULATION] Enabled Public Access Block on S3 bucket '{bucket_name}'.",
                "bucket": bucket_name,
            }

        try:
            s3_client = boto3.client("s3", region_name=self.region_name)
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            return {
                "status": "SUCCESS",
                "message": f"Successfully applied Public Access Block configuration to S3 bucket '{bucket_name}'.",
                "bucket": bucket_name,
            }
        except ClientError as e:
            return {
                "status": "FAILED",
                "message": f"Failed to enable Public Access Block on '{bucket_name}': {e.response.get('Error', {}).get('Message', str(e))}",
                "bucket": bucket_name,
            }
        except Exception as e:
            return {
                "status": "FAILED",
                "message": f"Error remediating S3 bucket '{bucket_name}': {str(e)}",
                "bucket": bucket_name,
            }
