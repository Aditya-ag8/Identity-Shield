# Identity Shield — Customer Single-Account Deployment

This Terraform template deploys the two least-privilege IAM roles required for Identity Shield to validate AWS CloudTrail detection engineering in your dedicated lab or test account.

## Supported Runtime Environments

This template supports all three operational modes:

1. **Local Development (AWS CLI profile)**:
   ```hcl
   trusted_principal_arns = ["arn:aws:iam::123456789012:user/your-dev-user"]
   external_id            = "" # Optional when running within your own account
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

## Security Model & Least-Privilege Guarantees

1. **No Permanent Secret Disclosure**: Customers never share permanent AWS access key IDs or secret access keys. All access uses AWS STS (`sts:AssumeRole`) with temporary session credentials that expire automatically within 1 hour.
2. **Confused-Deputy Defense**: When `external_id` is configured, cross-account assumption is strictly blocked without the matching external ID string.
3. **Strict Role Separation**:
   - **Telemetry Role**: Read-only access to CloudTrail logs (`s3:GetObject`, `s3:ListBucket`), queue notifications (`sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes`, `sqs:GetQueueUrl`), and CloudTrail status. **Receives zero attack execution permissions.**
   - **Execution Role**: Strictly bounded by resource ARNs (`is-test-user*`, `is-admin-role*`, tagged SSM EC2 instances, and the designated crown jewels data bucket). **Has zero unrestricted production access.**
4. **Customer Audit & Revocation**: You retain 100% control over the IAM roles and CloudTrail logs. All actions appear in CloudTrail under the assumed role ARN. You can revoke access instantly by deleting the roles or revoking active sessions in the AWS Console.

## Deployment Steps

1. Configure `terraform.tfvars`:
   ```hcl
   trusted_principal_arns   = ["arn:aws:iam::123456789012:user/aditya"]
   external_id              = "" # Set if using cross-account/vendor mode
   cloudtrail_bucket_arn    = "arn:aws:s3:::your-cloudtrail-bucket"
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
