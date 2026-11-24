# Identity Shield — Customer Integration Architecture & Deployment Model

## 1. Architectural Positioning: Out-of-Band Security Validation

Identity Shield is **NOT** an inline proxy, security sidecar, network firewall, or continuous SIEM. 

It is an **out-of-band security validation framework** designed to answer one rigorous research and engineering question:
> *When an attacker executes a controlled variation of an ATT&CK technique in AWS, does your CloudTrail-based detection rule reliably alert on it, or does the variation evade detection?*

```
+-----------------------------------------------------------------------------------------+
|                                  CUSTOMER AWS LAB ACCOUNT                               |
|                                                                                         |
|  [ CloudTrail Trail ] -------> [ S3 Log Bucket ] -------> [ SQS Notification Queue ]    |
|          ^                                                              |               |
|          | (Management & Data Events)                                   |               |
|          |                                                              |               |
|  [ Lab Execution Role ]                                       [ Telemetry Role ]        |
|    - is-test-user*                                              - s3:GetObject          |
|    - is-admin-role*                                             - s3:ListBucket         |
|    - tagged EC2 SSM instances                                   - sqs:ReceiveMessage    |
|    - crown jewels S3 bucket                                     - sqs:DeleteMessage     |
|                                                                 - organizations:Read    |
+----------^--------------------------------------------------------------^---------------+
           |                                                              |
           | (STS AssumeRole: ephemeral credentials)                      | (STS AssumeRole)
           |                                                              |
+----------+--------------------------------------------------------------+---------------+
|                               IDENTITY SHIELD RUNNER HOST                               |
|                                                                                         |
|  1. Preflight Verification (Trail status, regional allow-list, technique capability)   |
|  2. Variant Generation (OFAT, Pairwise, Sealed Holdout)                                 |
|  3. Controlled Attack Execution & Ground-Truth Verification                              |
|  4. Durable Telemetry Ingestion (Idempotent SQS -> SQLite, retrospective attribution)   |
|  5. Replay Engine (Sigma + Python predicates against Frozen Cryptographic Manifests)   |
|  6. Statistical Analysis (Wilson score intervals, exact McNemar test, Kaplan-Meier)     |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Supported Customer Runtime Architectures

Identity Shield is designed primarily for **self-hosted operation**, while cleanly providing forward compatibility for future vendor-hosted SaaS:

### Model A: Local Development / Operator CLI
- **Runner Environment**: Security engineer's workstation using an existing authorized AWS CLI profile (`~/.aws/credentials`).
- **Trust Configuration**: `trusted_principal_arns = ["arn:aws:iam::<account_id>:user/<operator-name>"]`.
- **External ID**: Optional when running within the customer's own AWS account.

### Model B: Customer-Hosted Automation (EC2 / Container / Tooling Account)
- **Runner Environment**: Dedicated EC2 instance, ECS container, or CI/CD runner operating inside a customer security tooling account.
- **Trust Configuration**: `trusted_principal_arns = ["arn:aws:iam::<tooling_account_id>:role/identity-shield-runner"]`.
- **External ID**: Recommended for customer cross-account access between the tooling account and the lab account.

### Model C: Future Vendor-Hosted SaaS
- **Runner Environment**: Multi-tenant vendor execution engine.
- **Trust Configuration**: `trusted_principal_arns = ["arn:aws:iam::<vendor_account_id>:role/identity-shield-saas-runner"]`.
- **External ID**: **Mandatory cryptographic secret** preventing confused-deputy vulnerabilities.

---

## 3. The Two-Role Least-Privilege Model

To enforce absolute separation of duties, Identity Shield requires two distinct IAM roles:

| Dimension | Telemetry Collection Role | Lab Attack Execution Role |
| :--- | :--- | :--- |
| **Operational Purpose** | Consume CloudTrail logs and verify trail status | Execute controlled ATT&CK variations |
| **Trust Condition** | `sts:AssumeRole` with customer-defined trust policy | `sts:AssumeRole` with customer-defined trust policy |
| **Max Session Duration** | 3600 seconds (1 hour) | 3600 seconds (1 hour) |
| **Write Permissions** | None (read-only S3 + SQS delete after write) | Scoped strictly to lab test objects |
| **IAM Scope** | Read-only CloudTrail/Organizations APIs | Bounded to `is-test-user*` and `is-admin-role*` |
| **Attack Execution** | **Zero attack execution permissions** | Strictly limited to the 8 ATT&CK techniques |
| **Secret Disclosure** | **Zero permanent secrets required** | **Zero permanent secrets required** |

### SQS Notification & Ingestion Permissions
The telemetry collection role requires explicit SQS permissions:
- `sqs:ReceiveMessage`: Poll notification queue for delivered S3 log chunk notices.
- `sqs:DeleteMessage`: Acknowledge message **only after** durable SQLite database persistence.
- `sqs:GetQueueAttributes`: Verify queue health and backlog depth during preflight checks.
- `sqs:GetQueueUrl`: Resolve queue URLs from configured queue names.

---

## 4. AWS Organizations Integration & Graceful Fallback

Identity Shield supports both individual accounts and AWS Organizations without making invalid privilege assumptions:

1. **The AWS Organizations Privilege Boundary**:
   - `organizations:DescribeOrganization`: Available to any member account in an organization.
   - `organizations:ListAccounts`: Available **only** to the management root account or authorized delegated administrators.
2. **Graceful Single-Account Fallback**:
   - When Identity Shield is deployed in a member account with `scope = organization`, calling `list_accounts()` will raise `AccessDeniedException`.
   - Identity Shield catches this error, verifies that the account is indeed an active member of an organization via `describe_organization()`, and **gracefully falls back to single-account assessment** of that authorized member account.
   - It records `effective_scope = single_account` and documents the fallback reason without crashing or assuming the account is standalone.
3. **No Service Control Policies (SCPs)**:
   - Identity Shield **never** provisions, modifies, or detaches Service Control Policies (SCPs).
   - `enable_scps` defaults to `false` and guardrails `count` evaluates to `0`.

---

## 5. Technique Capability Matrix

Before executing live attacks, Identity Shield evaluates a capability check for each of the eight ATT&CK techniques against the active lab configuration. If a required service or telemetry feature is disabled, the technique is marked as **unavailable** rather than mistakenly reported as an evasion or detection failure.

| Technique ID | Technique Name | Required Lab Configuration | Telemetry Surface | Behavior When Disabled |
| :--- | :--- | :--- | :--- | :--- |
| **T1087.004** | IAM User/Role Enumeration | Active CloudTrail trail | Management Events (`ListUsers`, `ListRoles`) | Fails preflight if CloudTrail trail is stopped. |
| **T1526** | Cloud Service Discovery | Active CloudTrail trail | Management Events (`GetCallerIdentity`, `DescribeInstances`) | Fails preflight if CloudTrail trail is stopped. |
| **T1580** | Cloud Infrastructure Discovery | Active CloudTrail trail | Management Events (`DescribeVpcs`, `DescribeSecurityGroups`) | Fails preflight if CloudTrail trail is stopped. |
| **T1078.004** | Valid Accounts | Authenticated AWS Session | Management Events (`GetCallerIdentity`, `ListUsers`) | Note: Evaluates active API session; web console login is not performed programmatically. |
| **T1098.001** | Additional Cloud Credentials | Target user `is-test-user` | Management Events (`CreateAccessKey`, `CreateLoginProfile`) | Confined to test user; cleaned up immediately. |
| **T1098.003** | Additional Cloud Roles | Target role `is-admin-role` | Management Events (`AttachRolePolicy`, `UpdateAssumeRolePolicy`) | Confined to test admin role; cleaned up immediately. |
| **T1552.005** | Instance Metadata API | `enable_instance = true` & `instance_id` | SSM Run Command output & IMDS credential use | **Marked Unavailable.** Preflight fails closed; excluded from evasion statistics. |
| **T1530** | Data from Cloud Storage Object | `enable_data_events = true` & `data_bucket` | CloudTrail S3 Data Events (`GetObject`) | **Marked Unavailable.** Preflight fails closed; excluded from evasion statistics. |

*Note: In synthetic rehearsal mode (`--synthetic`), all eight techniques are always 100% available via deterministic fixture replay.*

---

## 6. Live vs. Synthetic Factor Provenance

Every variant trial records explicit factor provenance in the database (`trial.attack_evidence` -> `factor_provenance`), distinguishing genuine live mutations from partial mutations and synthetic-only simulations:

| Factor Dimension | Level | Live Implementation Reality | Provenance Classification |
| :--- | :--- | :--- | :--- |
| **client_tool** | `boto3_default` | Default botocore User-Agent header | **Genuine** |
| **client_tool** | `aws_cli`, `terraform`, `non_sdk_http` | User-Agent header modified via `botocore.config.Config`. Underlying SDK remains boto3; does not invoke CLI binary. | **Partial** (Header mutation only) |
| **network_origin** | `alternate_endpoint` | Regional endpoint changed (e.g. `us-east-1` vs `eu-west-1`). Recorded in `awsRegion`. Client source IP unchanged. | **Partial** (Regional endpoint mutation) |
| **network_origin** | `nat_a`, `nat_b` | Direct runner host IP. Dedicated dual-NAT gateways with distinct Elastic IPs are excluded under cost controls. | **Synthetic-Only** |
| **network_origin** | `service_mediated` | Direct runner host IP. Lambda/ECS execution is excluded from lab scope. | **Synthetic-Only** |
| **identity_context** | `iam_user` | Long-term IAM user credentials verified in `userIdentity.arn` | **Genuine** |
| **identity_context** | `assumed_role` | STS AssumeRole session verified in `userIdentity.arn` | **Genuine** |
| **identity_context** | `instance_profile` | Live IMDS query on EC2 via SSM | **Genuine** (when `enable_instance=true`) |
| **identity_context** | `federated_session` | OIDC/SAML live federation identity provider is excluded from lab scope. | **Synthetic-Only** |
| **timing** | `business_hours` | Executed during operational test window | **Genuine** |
| **timing** | `off_hours`, `burst`, `spread` | Live trials run synchronously. Off-hours and timing intervals are evaluated deterministically in synthetic replay. | **Synthetic-Only** |
| **api_form** | `canonical`, `alternative_api`, `extra_parameters`, `hostile_identifier` | Genuinely executed alternative AWS API operations and parameter permutations. | **Genuine** |

---

## 7. CloudTrail Ingestion Latency & Delivery Semantics

CloudTrail is an asynchronous audit logging service with inherent operational characteristics:

1. **Delivery Latency (Lag)**:
   - CloudTrail batches events into gzip JSON files delivered to S3 typically every 5 to 15 minutes.
   - Identity Shield treats detection latency as **right-censored** and separates *AWS delivery lag* from *rule evaluation latency*.
2. **Event Attribution Window**:
   - The collector uses strict time windows (`window_start` to `window_end`).
   - Events delivered outside the active trial window are safely retained in SQLite with `trial_id = NULL` (unassigned retention) and are claimed retrospectively when subsequent trials match their timestamps.
3. **SQS Notification Idempotency**:
   - SQS provides at-least-once delivery. Duplicate notifications are processed idempotently using SQLite `ON CONFLICT(event_id) DO UPDATE`.
   - Messages are acknowledged (`sqs:DeleteMessage`) **strictly after** durable database transaction commit.

---

## 8. Customer Access Revocation Procedures

Customers maintain complete sovereign control over Identity Shield's access:

1. **Immediate Session Invalidation**:
   In the AWS Management Console:
   - Navigate to **IAM** -> **Roles**.
   - Select `${role_prefix}-telemetry-role` and `${role_prefix}-execution-role`.
   - Click the **Revoke sessions** tab and select **Revoke active sessions**. All temporary STS credentials expire instantly.
2. **Permanent Infrastructure Teardown**:
   ```bash
   cd infra/customer/single-account  # or infra/customer/organization
   terraform destroy
   ```
   Deleting the Terraform stack deletes both IAM roles and removes all trust relationships.
