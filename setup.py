from setuptools import setup, find_packages

setup(
    name="valkriey",
    version="1.0.0",
    description="Multi-Cloud Security Hardening & Compliance Auditor CLI Tool",
    author="Senior Cloud Security Engineer",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.28.0",
        "botocore>=1.31.0",
        "typer[all]>=0.9.0",
        "rich>=13.5.0",
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "valkriey=valkriey.main:app",
        ],
    },
    python_requires=">=3.10",
)
