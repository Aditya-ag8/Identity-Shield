# Identity Shield — Self-Hosted Installation & Operating Guide

Identity Shield is an AWS CloudTrail detection-robustness testing and security validation framework. It operates out-of-band by generating controlled attack variations across eight fixed MITRE ATT&CK techniques, executing them in an authorized AWS lab environment, collecting CloudTrail telemetry via SQS/S3, and evaluating detection rules (Sigma and Python predicates) in an offline SQLite replay pipeline.

---

## 1. System Requirements & Prerequisites

### Runner Host
- **Operating System**: Linux (Ubuntu 22.04+, Amazon Linux 2023), macOS (13+), or Windows 10/11 with PowerShell.
- **Python**: 3.11.9+ with virtual environment support (`.venv`).
- **Dependencies**: `boto3`, `botocore`, `pySigma >= 0.11`, `pySigma-backend-python`, `PyYAML`, `sqlite3` (with WAL mode), `pandas`, `Plotly`, `Streamlit`, `allpairspy`, `scipy`, `pytest`.
- **Infrastructure Tools**:
  - AWS CLI v2 (`aws --version >= 2.15`).
  - Terraform CLI (`terraform >= 1.9.8`).
- **Storage**: At least 5 GB free disk space for SQLite database, reports, and CloudTrail event caches.
- **Memory**: 2 GB RAM minimum; 4 GB recommended for concurrent replay analysis.

---

## 2. Supported Deployment & Credential Architectures

Identity Shield supports three runtime environments:

### Model 1: Local Development / Operator CLI (Self-Hosted)
- The operator runs Identity Shield from their terminal using an authorized AWS CLI profile (`--profile <name>`).
- Cross-account access uses STS AssumeRole with `trusted_principal_arns = ["arn:aws:iam::<account_id>:user/<operator>"]`.
- The customer never provides permanent AWS secret access keys.

### Model 2: Customer-Hosted Automation (EC2 / Container / Tooling Role)
- Identity Shield runs on a customer-hosted EC2 instance or ECS task attached to an IAM instance profile (`arn:aws:iam::<tooling_account>:role/identity-shield-runner`).
- Target lab roles trust this runner role ARN.
- Ephemeral credentials are held strictly in process memory and automatically refreshed via STS.

### Model 3: Future Vendor-Hosted SaaS
- Multi-tenant runner assumes the customer's cross-account roles using a customer-specific `ExternalId`.
- The customer retains full custody over IAM role definitions, permission boundaries, and CloudTrail audit logs.

---

## 3. Customer IAM Onboarding

Customers deploy the integration roles using the provided Terraform templates:

### Single-Account Deployment
```bash
cd infra/customer/single-account
# Edit terraform.tfvars:
# trusted_principal_arns = ["arn:aws:iam::<runner_account_id>:user/<runner_name>"]
# cloudtrail_bucket_arn  = "arn:aws:s3:::your-lab-cloudtrail-bucket"
# data_bucket_arn        = "arn:aws:s3:::is-lab-crown-jewels"
terraform init
terraform apply
```

### AWS Organizations Deployment
```bash
cd infra/customer/organization
# Edit terraform.tfvars
terraform init
terraform apply
```
*Note: If deployed in an ordinary member account, Identity Shield automatically confirms organization membership via `describe_organization()` and gracefully falls back to single-account evaluation when `organizations:ListAccounts` is restricted.*

---

## 4. Estimated AWS Costs & Cost Controls

Identity Shield is engineered to operate strictly within AWS Free Tier limits wherever possible:

| Resource | Scope / Setting | Default State | Estimated Cost (Monthly) |
| :--- | :--- | :--- | :--- |
| **AWS CloudTrail Management Events** | 1 multi-region trail | Enabled | **$0.00** (First copy of management events is free) |
| **AWS CloudTrail S3 Data Events** | T1530 S3 read monitoring | **Disabled** (`enable_data_events=false`) | $0.00 (Only $0.10/100k events if explicitly enabled) |
| **EC2 IMDS Target** (`t3.micro`) | T1552.005 metadata testing | **Disabled** (`enable_instance=false`) | $0.00 ($8.50/mo if explicitly enabled; stop after test) |
| **S3 Storage (Logs & Data)** | CloudTrail gzip logs | 30-day lifecycle expiration | < $0.05 / month |
| **SQS Notification Queue** | S3 event notifications | 1 queue | Free Tier (< 1M requests/mo) |
| **AWS Budgets Alarm** | Cost control alarm ($50 limit) | **Enabled** (`enable_budget=true`) | **$0.00** (First 2 budgets free) |
| **NAT Gateways** | Alternate egress testing | **Omitted / Disallowed** | **$0.00** (Zero provisioning) |

### Strict Cost Controls Enforced by Terraform
- `enable_data_events = false`: Prevents unbounded CloudTrail S3 data event fees. T1530 is marked unavailable live until explicitly enabled.
- `enable_instance = false`: Prevents compute charges when IMDS testing is inactive. T1552.005 is marked unavailable live until explicitly enabled.
- `enable_budget = true`: Alarms at 80% of budget limit ($50.00 threshold).
- `log_retention_days = 30`: Automatically purges old CloudTrail objects via S3 Lifecycle.
- `single-region deployment`: Lab resources are constrained to `eu-west-1` to prevent multi-region sprawl.
- `enable_scps = false`: Guardrail SCPs are never provisioned or modified.

---

## 5. Local Installation & Verification

```bash
# 1. Clone repository
git clone https://github.com/your-org/identity-shield.git
cd identity-shield

# 2. Set up Python virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Initialize SQLite database
python -m identity_shield.cli lab init-db

# 5. Run test suite to verify installation
pytest

# 6. Run offline performance benchmark
python -m identity_shield.cli bench
```

---

## 6. Teardown, Cleanup & Access Revocation

### Lab Resource Cleanup
Identity Shield tracks all created test credentials, keys, and role attachments:
```bash
# Run post-campaign sweeper and census verification
python -m identity_shield.cli runner sweep
python -m identity_shield.cli lab census
```

To destroy Terraform lab resources:
```bash
python -m identity_shield.cli lab down
```

### Revoking Cross-Account Access
To immediately terminate Identity Shield's ability to access your AWS account:
1. Delete the Terraform stack in `infra/customer/single-account/` or `infra/customer/organization/`:
   ```bash
   terraform destroy
   ```
2. Or immediately revoke the IAM role sessions in the AWS Console:
   - Go to **IAM** -> **Roles**.
   - Select `${role_prefix}-execution-role` and `${role_prefix}-telemetry-role`.
   - Click **Revoke sessions** -> **Revoke active sessions**.
