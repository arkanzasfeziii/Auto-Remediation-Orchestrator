# Auto-Remediation Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A production-grade, safety-first CLI tool for automated remediation of cloud security misconfigurations across **AWS**, **Azure**, and **GCP**.

## ⚠️ Critical Warning

**This tool can MODIFY your cloud resources.** Misuse can cause outages, data loss, or security degradation.

- ✅ **Default Mode:** The tool runs in **DRY-RUN** mode by default. No changes are made unless explicitly requested.
- ✅ **Safety Locks:** Applying changes requires multiple confirmation flags (`--apply --confirm --i-understand-risk`).
- ✅ **Responsibility:** Use only on environments you own and have authorization to modify.

## Features

- **Multi-Cloud Support:** Unified interface for AWS, Azure, and Google Cloud Platform.
- **Safety-First Design:** Dry-run simulation is the default behavior.
- **Comprehensive Reporting:** Export results to Console, JSON, HTML, or TXT.
- **Automated Rules:** Detects and fixes common misconfigurations (Public S3 buckets, Open Security Groups, Wildcard IAM policies, etc.).
- **Rollback Hints:** Provides commands to revert changes if necessary.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/arkanzasfeziii/auto-remediation-orchestrator.git
   cd auto-remediation-orchestrator
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

Configuration
   
Ensure you are authenticated with the cloud providers you intend to scan:

AWS: Configure via aws configure or environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY).

Azure: Login via az login or use DefaultAzureCredential.

GCP: Set the project ID (export GOOGLE_CLOUD_PROJECT=your-project-id) and authenticate via gcloud auth application-default login.

Usage

1. Dry-Run (Safe Default)
   ```bash
   Simulate remediations without making any changes.
   ```

2. Simulate remediations without making any changes.
   ```bash
   # Only check S3 buckets
   python autoremediation.py --provider aws --resource-type s3 --dry-run

   # Filter by name pattern
   python autoremediation.py --provider azure --filter "prod-*" --dry-run
   ```

3. Apply Changes (Dangerous)
   To actually apply fixes, you must pass all safety flags.
   ```bash
   python autoremediation.py --provider aws --apply --confirm --i-understand-risk --resource-type s3
   ```

4. Export Reports
   Generate detailed reports in various formats.
   ```bash
   # JSON Report
   python autoremediation.py --provider all --dry-run --output json --output-file report.json

   # HTML Dashboard
   python autoremediation.py --provider gcp --dry-run --output html --output-file report.html
   ```

   Disclaimer
   
   The author (arkanzasfeziii) and contributors assume NO LIABILITY for any damage, loss, or consequences arising from the use of this tool. This software is provided "as is" for authorized remediation of your own environments only. Unauthorized modification of cloud resources is illegal.
