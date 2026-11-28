# Identity Shield — Multi-Cloud Architecture (AWS, GCP, Azure)

Identity Shield extends its self-hosted detection-engineering lab, inline security proxy, 5-factor evasion framework, and closed-loop validation engine across **Amazon Web Services (AWS)**, **Google Cloud Platform (GCP)**, and **Microsoft Azure & Entra ID**.

## 1. Offline-First & Backward Compatibility
- All core features work **100% offline** with zero mandatory cloud SDKs or CLIs (`google-cloud-*`, `azure-*`, `gcloud`, `az`, `stratus`, `cloudfox`, `scout` are detected lazily when installed).
- AWS remains a first-class provider: frozen rulesets (`baseline-v1`, `improved-v1`), 24 CloudTrail replay fixtures, and 8 core ATT&CK techniques remain untouched.
- SQLite uses additive versioned migrations (`schema_migration`), preserving legacy rows while isolating cross-cloud behavioral baselines via `profile_key = <cloud_provider>:<account_scope>:<principal>`.

## 2. Proxy Traffic Classification & Inspection Capabilities
Stage-1 classifier ([classifier.py](../src/identity_shield/clouds/classifier.py)) separates **cloud provider** (`aws`, `gcp`, `azure`, `unknown`) from **traffic type** (`cloud_api`, `http_app`, `connect_tunnel`) using hostnames, protocol headers, and URL/body structure without logging raw credentials.

- **Inspectable HTTP / Custom Endpoint Mode**: AWS (`--endpoint-url`), GCP (`CLOUDSDK_API_ENDPOINT_OVERRIDES_*`), Azure SDK base URLs, and Cloud Web Apps receive full L7 inspection, credential redaction, behavioral scoring, and policy-controlled HTTP `403` enforcement.
- **Metadata-Only `CONNECT` Tunnel Mode (Default)**: Without TLS interception enabled, `CONNECT` inspects destination authority and connection metadata only (`policy_decision = "observed"`); payloads are never fabricated.
- **Explicit Opt-In TLS Inspection ([tls.py](../src/identity_shield/proxy/tls.py))**: Disabled by default. Uses local on-disk CA storage only when OpenSSL is available, enforces pinned/mTLS passthrough exclusions (`login.microsoftonline.com`, `accounts.google.com`, `signin.aws.amazon.com`), and never stores CA private keys in SQLite or API telemetry.

## 3. Canonical Normalization & Cloud Rulesets
- **Canonical Event Schema v1.0** ([models.py](../src/identity_shield/clouds/models.py)): Normalizes AWS CloudTrail, GCP Cloud Audit Logs (Admin Activity, Data Access, System Event, Policy Denied), and Azure (Activity Logs, Entra Sign-In Logs, Entra Audit Logs) into one redacted contract while preserving native payload structure.
- **Rulesets**:
  - `gcp-baseline-v1`: GCP Cloud Audit rules (`conf/rules/gcp/`).
  - `azure-baseline-v1`: Azure Activity & Entra ID rules (`conf/rules/azure/`).
  - `multicloud-v1`: Combined AWS + GCP + Azure bundle scoped strictly by `logsource.product`.
- **Policy Evaluation ([policy.py](../src/identity_shield/detect/policy.py))**: Separates rule scoring from enforcement. New providers (`gcp`, `azure`) default to `observe` until explicitly switched in proxy configuration.

## 4. Portable Multi-Cloud SIEM Exports
[siem_export.py](../src/identity_shield/detect/siem_export.py) exports Sigma rules to:
- **AWS CloudWatch Logs Insights** (`aws_cloudwatch`)
- **Google Cloud Logging Filters** (`gcp_logging`)
- **Google SecOps YARA-L 2.0** (`gcp_secops`)
- **Microsoft Sentinel KQL** (`azure_sentinel`)

Any unsupported Sigma condition (such as non-trivial `N of ...` counts or Python-only callables) or cross-cloud schema mismatch is flagged explicitly in `warnings` and `unsupported_conditions`.
