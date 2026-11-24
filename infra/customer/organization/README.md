# Identity Shield — Customer AWS Organizations Deployment

This Terraform template deploys the two least-privilege IAM roles required for Identity Shield to validate AWS CloudTrail detection engineering in an AWS Organizations environment.

## Supported Runtime Environments

This template supports all three operational modes:

1. **Local Development (AWS CLI profile)**:
   ```hcl
   trusted_principal_arns = ["arn:aws:iam::123456789012:user/your-dev-user"]
   external_id            = "" # Optional within same account
   ```
2. **Customer-Hosted Identity Shield (EC2 / Container / Tooling Role)**:
   ```hcl
   trusted_principal_arns = ["arn:aws:iam::123456789012:role/identity-shield-runner"]
   external_id            = "" # Or set if running from a separate tooling account
   ```
3. **Future Vendor-Hosted SaaS**:
   ```hcl
   trusted_principal_arns = ["arn:aws:iam::VENDOR_ACCOUNT_ID:role/identity-shield-saas"]
   external_id            = "customer-unique-cryptographic-external-id" # Mandatory
   ```

## AWS Organizations Integration & Graceful Fallback

- **No Service Control Policies (SCPs)**: Identity Shield **never** provisions, modifies, or detaches Service Control Policies (SCPs).
- **Graceful Account Enumeration Fallback**:
  - `organizations:ListAccounts` requires management-account or delegated-administrator privileges in AWS Organizations.
  - When deployed in an ordinary member account, `organizations:ListAccounts` will return `AccessDeniedException`.
  - Identity Shield's account classifier automatically recognizes this, confirms organization membership via `organizations:DescribeOrganization`, and **gracefully falls back to single-account assessment** of that authorized member account without error.
- **Strict Role Separation**:
  - **Telemetry Role**: Read-only S3, SQS (`sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes`, `sqs:GetQueueUrl`), CloudTrail status, and read-only Organizations APIs. **Receives zero attack execution permissions.**
  - **Execution Role**: Strictly bounded by resource ARNs (`is-test-user*`, `is-admin-role*`, tagged SSM EC2 instances, and the target data bucket). **Has zero unrestricted production access.**

## Deployment Steps

1. Configure `terraform.tfvars`:
   ```hcl
   trusted_principal_arns   = ["arn:aws:iam::123456789012:user/aditya"]
   external_id              = "" # Set if using cross-account/vendor mode
   cloudtrail_bucket_arn    = "arn:aws:s3:::your-organization-cloudtrail-bucket"
   cloudtrail_sqs_queue_arn = "arn:aws:sqs:eu-west-1:your-account:your-queue" # Optional
   data_bucket_arn          = "arn:aws:s3:::is-lab-crown-jewels"
   ```

2. Initialize and apply:
   ```bash
   terraform init
   terraform apply
   ```

3. Provide the output role ARNs to Identity Shield:
   - `telemetry_role_arn`
   - `execution_role_arn`
