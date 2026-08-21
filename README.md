# 🛡️ VALKRIEY - Multi-Cloud Security Hardening & Compliance Auditor

**VALKRIEY** is a modular, high-performance open-source Python CLI tool designed for Multi-Cloud (AWS) security hardening and CIS Benchmark compliance auditing. It scans cloud infrastructure for critical misconfigurations, calculates real-time compliance scores, exports audit results in JSON and Markdown formats, and provides optional auto-remediation mode.

---

## 🚀 Features

- **CIS Benchmark Auditing**:
  - **S3 Security**: Public Access Block enforcement (CIS 2.1.5), default server-side encryption (CIS 2.1.1), and server access logging (CIS 2.1.2).
  - **Security Group Hardening**: Unrestricted `0.0.0.0/0` ingress detection on sensitive ports (`22` SSH, `3389` RDP, `5432` Postgres, `27017` MongoDB) (CIS 5.2).
  - **IAM Governance**: Root account access key usage & MFA check (CIS 1.1), IAM user MFA status (CIS 1.5), stale access keys older than 90 days (CIS 1.12), and direct Administrator policy attachments (CIS 1.16).
  - **CloudTrail Logging**: Global multi-region CloudTrail auditing (CIS 3.1) and log file validation check (CIS 3.2).
- **Compliance Score & Risk Categorization**:
  - Compliance Score = `(Passed Checks / Total Checks) * 100%`.
  - Risk Levels: `KRITIS` (<50%), `TINGGI` (50-74%), `SEDANG` (75-89%), `RENDAH` (90-100%).
- **Interactive Rich Terminal Dashboard**: Progress spinners, status badges, color-coded severity tables, and dashboard summary panels.
- **Auto-Remediation Engine**: Safely block public S3 buckets and revoke dangerous `0.0.0.0/0` ingress rules automatically.
- **Dry-Run Mode (`--dry-run`)**: Test VALKRIEY offline using realistic mock AWS datasets without needing active AWS credentials.
- **Comprehensive Reporting**: Export reports in **JSON** (`results.json`) and **Markdown** (`report.md`) with Pre-Hardening vs Post-Hardening score comparison tables.

---

## 📁 Directory Structure

```
Project Cyber/
├── valkriey/
│   ├── __init__.py
│   ├── main.py                  # Entrypoint for CLI commands (scan, remediate, report)
│   ├── config/
│   │   ├── __init__.py
│   │   └── rules.py             # CIS Benchmark rule mappings & severity metadata
│   ├── auditors/
│   │   ├── __init__.py
│   │   ├── base.py              # Base Auditor class & Pydantic finding models
│   │   ├── s3_auditor.py        # S3 Public Access, Encryption, Logging auditor
│   │   ├── sg_auditor.py        # Security Group sensitive port ingress auditor
│   │   ├── iam_auditor.py       # IAM Root, MFA, key age (>90d), admin policies
│   │   └── logging_auditor.py   # CloudTrail Global & log validation auditor
│   ├── remediators/
│   │   ├── __init__.py
│   │   ├── s3_remediator.py     # S3 Public Access Block auto-remediator
│   │   └── sg_remediator.py     # SG 0.0.0.0/0 sensitive rule revoker
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── score_calculator.py  # Score formula & risk level categorizer
│   │   └── mock_data.py         # Mock AWS dataset generator for --dry-run
│   └── reporters/
│       ├── __init__.py
│       ├── terminal_reporter.py # Rich terminal visualizer
│       ├── json_reporter.py     # JSON export reporter
│       └── markdown_reporter.py # Markdown report generator with Pre vs Post comparison
├── requirements.txt             # Project dependencies
├── setup.py                     # CLI setup script
└── README.md                    # Documentation & manual
```

---

## 🔧 Installation

### Prerequisites
- Python **3.10+**
- AWS CLI configured (if performing live AWS scans): `aws configure`

### Setup Instructions

1. Clone or navigate to the repository:
   ```bash
   cd "Project Cyber"
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   # On Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. Install VALKRIEY in editable mode:
   ```bash
   pip install -e .
   ```

---

## 💻 CLI Usage

VALKRIEY provides three main commands: `scan`, `remediate`, and `report`.

### 1. Security Scan (`scan`)

Scan your infrastructure and view the Rich Terminal Dashboard:

```bash
# Run scan against live AWS (us-east-1)
valkriey scan

# Run scan against live AWS in a specific region
valkriey scan --region ap-southeast-1

# Run scan in DRY-RUN mode (No AWS credentials needed)
valkriey scan --dry-run
```

### 2. Auto-Remediation (`remediate`)

Perform an audit and automatically remediate fixable misconfigurations (e.g., S3 Public Access Block & SG sensitive ingress revocation):

```bash
# Run auto-remediation in DRY-RUN simulation mode
valkriey remediate --dry-run

# Run auto-remediation against live AWS infrastructure
valkriey remediate --region us-east-1 --auto-remediate
```

### 3. Generate Reports (`report`)

Audit infrastructure, apply optional remediations, and export **Markdown** and **JSON** reports:

```bash
# Generate report in DRY-RUN mode
valkriey report --dry-run --output report.md --json-output results.json

# Audit live AWS, auto-remediate, and generate Pre vs Post score report
valkriey report --region us-east-1 --auto-remediate --output final_report.md
```

---

## 📊 Pre vs Post Score Comparison Example

When running auto-remediation and generating reports, VALKRIEY produces a Pre-Hardening vs Post-Hardening comparison table:

| Metric | Pre-Hardening Audit | Post-Hardening Audit | Delta |
| :--- | :---: | :---: | :---: |
| **Compliance Score** | `53.85%` | `69.23%` | `+15.38%` |
| **Overall Risk Category** | `KRITIS` | `TINGGI` | `Improved` |
| **Total Checks** | `26` | `26` | `0` |
| **Passed Checks** | `14` | `18` | `+4` |
| **Failed Checks** | `12` | `8` | `-4` |
| **Remediated Checks** | `0` | `4` | `+4` |

---

## 🔐 Error & Rate Limit Handling

VALKRIEY gracefully handles AWS API edge cases:
- **Rate Limit Throttling**: Captures `Throttling`, `RequestLimitExceeded`, and `TooManyRequestsException` and logs informative status badges instead of crashing.
- **Missing Credentials**: Warns users cleanly if AWS credentials or IAM permissions (`AccessDenied`) are missing, and suggests running with `--dry-run`.

---

## 📜 License
Released under the MIT Open Source License.
