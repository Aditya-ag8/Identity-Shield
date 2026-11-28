# Identity Shield — Independent Multi-Cloud Implementation Audit

**Audit Baseline Commit:** `7d0c39bac4a542ca22023ebb9aecc5728348d192`  
**Audit Date:** 2026-11-27  
**Auditor Methodology:** Direct source-code inspection (`src/`, `conf/`, `tests/`), Git diff comparison against reported architecture docs (`docs/multicloud-architecture.md` and prior implementation summary), and controlled offline verification probes executed inside `.venv` (`Python 3.11`).

---

## 1. Executive Audit Verdict & Baseline Verification

### Pre-Audit Automated Baseline
- `pytest -o addopts="" --tb=short`: **225 passed** in `23.34s`
- `python -m identity_shield.cli bench`: **PASS** (`total 1.054s`, `trials: 300`, `artefacts: 348`, budget `30.0s`)
- `node --check src/identity_shield/web/static/app.js`: exit code `0`

### Overall Readiness Verdict
| Domain | Verdict | Notes |
| --- | --- | --- |
| **AWS Core Platform & Frozen Rulesets** | **PASS** | `baseline-v1`, `improved-v1`, 24 CloudTrail fixtures, and 8 core techniques preserved cleanly. |
| **Multi-Cloud Sigma & Dynamic Detection** | **CONDITIONAL PASS** | GCP/Azure Sigma rules, pySigma compilation, cross-cloud scoping, synthetic anti-poisoning, and `observe`-by-default policy guard verified; `detect/enhancer.py` corrupts non-AWS rules (`product: aws`). |
| **Multi-Cloud Ingestion & Redaction** | **NEEDS FIXES (High)** | Mixed-cloud `auto` ingestion drops non-first cloud records; Azure dict `caller` breaks string invariant; `sig=` / `key=AIza...` / `X-Amz-Signature=` leak. |
| **Live Proxy HTTP / CONNECT / SSRF / TLS** | **FAIL (Critical)** | **100% of HTTPS `CONNECT` tunnels crash with `UnboundLocalError`** (`ssrf_err`); TLS MITM toggle (`tls_intercept_enabled`) is non-functional; SSRF guard misses metadata hostnames/octal/integer IPs offline. |
| **Portable SIEM Exporter** | **FAIL (Critical)** | Sentinel `AWSCloudTrail` exports emit invalid `AzureActivity`/`AuditLogs` columns; unescaped `/` breaks CloudWatch & SecOps regex literals; integer GCP status codes mis-mapped. |
| **Closed-Loop & 5-Factor Multi-Cloud Simulation** | **NEEDS FIXES (High)** | Safe against unintended live attacks on imported recon JSON; however, auto-hardened GCP/Azure rules miss raw native logs (`eventSource`/`eventName`) and unsupported variants distort denominators. |
| **UI / CLI Parity & Security** | **NEEDS FIXES (Medium)** | Host/CSRF/Origin/CSP/token controls verified; `conf/techniques_multicloud.yaml` hidden from Attacks/Variants/Campaigns; unbounded POST JSON buffer in web backend; missing `cloud_provider` filters on 4 core views. |
| **Optional Live GCP / Azure Sandbox Execution** | **NOT READY (Expected Offline-First)** | Lazy CLI detection (`gcloud`, `az`, `scout`) exists; no live GCP/Azure Terraform modules, API executors, or teardown residue verifiers exist yet. |

---

## 2. Discrepancies Between Reported Capabilities & Actual Implementation

| Reported Capability (`docs/multicloud-architecture.md` / Report) | Actual Code Behavior Observed | Severity |
| --- | --- | --- |
| Metadata-only `CONNECT` tunnel mode inspects destination authority and forwards HTTPS tunnels cleanly | `ProxyServerRuntime.handle_connect` ([server.py#L601](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/proxy/server.py#L601)) passes `explicit_tunnel_block=bool(ssrf_err)` into `dynamic.evaluate_live_event()` **before** assigning `ssrf_err`, raising `UnboundLocalError` on every `CONNECT` call. | **Critical** |
| Explicit opt-in TLS interception (`proxy/tls.py`, `tls_intercept_enabled`) | `TlsCertAuthority` exists in `proxy/tls.py`, but `handle_connect` never invokes TLS wrapping and passes `inspection_capable=False` unconditionally. | **Medium** |
| Auto-detect ingestion normalizes AWS CloudTrail, GCP Audit, and Azure Activity/Entra logs | `extract_audit_events` ([registry.py#L64](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/clouds/registry.py#L64)) returns immediately after the first matching provider loop (`gcp` then `azure` then `aws`), silently discarding Entra/AWS items in mixed-cloud batches. | **High** |
| Microsoft Sentinel KQL & SecOps SIEM export handles AWS/GCP/Azure schemas | Exporting AWS CloudTrail rules to `azure_sentinel` selects `AWSCloudTrail` table while translating `eventSource -> ResourceProviderValue`, `eventName -> OperationNameValue`, `errorCode -> errorCode`, and projecting `InitiatedBy, Result`. | **Critical** |
| Adaptive Enhancer & Closed-Loop Harden Rules Across Clouds | `build_enhanced_rule` ([enhancer.py#L353](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/detect/enhancer.py#L353)) stamps `"logsource": {"product": "aws", "service": "cloudtrail"}` onto GCP/Azure rules; `_write_closed_loop_sigma_rule` writes canonical `eventSource`/`eventName` rules that fail against raw native GCP/Azure logs. | **High** |
| Multi-Cloud ATT&CK Techniques & Cloud Filtering Across Control Plane & CLI | `list_attacks_overview` ([service.py#L487](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/service.py#L487)) returns only the 8 AWS techniques; `conf/techniques_multicloud.yaml` (10 GCP/Azure techniques) is omitted from Attacks, Variants, Campaigns, and `attacks list` CLI, and `/api/analytics`, `/api/attacks`, `/api/variants`, `/api/rules` ignore cloud filters. | **Medium** |

---

## 3. Consolidated Findings Register

### CRITICAL-01: Unconditional `UnboundLocalError` Crash on Every HTTPS `CONNECT` Request
- **File & Symbol:** [server.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/proxy/server.py) — `handle_connect` (starts line 601)
- **Technical Explanation:** Inside `handle_connect`, `dynamic.evaluate_live_event(..., explicit_tunnel_block=bool(ssrf_err))` is called before parsing `host, port` or calling `_ssrf_block_reason(...)` to compute `ssrf_err`. Every HTTPS proxy client (`CONNECT host:443`) immediately triggers `UnboundLocalError`, closing the TCP socket with an empty response and persisting zero rows to `proxy_event`.
- **Reproduction Evidence:** Live proxy probe sending `CONNECT iam.googleapis.com:443 HTTP/1.1` returned `''`, logged `UnboundLocalError: cannot access local variable 'ssrf_err' where it is not associated with a value` at `server.py:623`, and inserted `0` rows into `proxy_event`.
- **Remediation:** Parse `host, port` and evaluate `_ssrf_block_reason(host, port, allow_local_upstream=False, self_port=...)` **before** calling `dynamic.evaluate_live_event(...)`, passing `explicit_tunnel_block=bool(ssrf_err)` safely. Enforce SSRF denial deterministically (403) before opening upstream TCP sockets.

### CRITICAL-02: Invalid Field Mappings & Table Schema Mismatches in Portable SIEM Exporter
- **File & Symbol:** [siem_export.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/detect/siem_export.py) — `export_rule_to_siem` (starts line 254), `_DEFAULT_FIELD_MAPS`, `_sentinel_table`
- **Technical Explanation:**
  1. `_DEFAULT_FIELD_MAPS["azure_sentinel"]` applies one static dictionary (`eventSource -> ResourceProviderValue`, `eventName -> OperationNameValue`) even when `_sentinel_table()` emits `AWSCloudTrail`, `SigninLogs`, or `AuditLogs`. Exporting AWS `T1098.001` produces `AWSCloudTrail | where ResourceProviderValue =~ "iam.amazonaws.com" ... | project TimeGenerated, OperationName, InitiatedBy, Result`, none of which are valid `AWSCloudTrail` schema columns in Sentinel.
  2. Regex patterns containing forward slashes (e.g., `projects/.*/secrets/.*`) are interpolated raw inside `/pattern/i` for `aws_cloudwatch` and `/pattern/ nocase` for `gcp_secops`, causing delimiter syntax errors.
  3. Integer gRPC `protoPayload.status.code: 7` on GCP rules is mapped in `gcp_secops` to `$e.security_result.rule_id = "7" nocase` instead of semantic status/action fields or warning of semantic approximation.
- **Reproduction Evidence:** Verified directly on `T1098.001-create-access-key.yml` -> `azure_sentinel` and EdgeCase `protoPayload.methodName|re: 'projects/.*/secrets/.*'` -> `aws_cloudwatch` / `gcp_secops`.
- **Remediation:** Make Sentinel field mapping and projection table-aware (`AWSCloudTrail`, `SigninLogs`, `AuditLogs`, `AzureActivity`), escape `/` as `\/` in `/pattern/` regex literals for CloudWatch and SecOps, and avoid misleading UDM field remapping of integer gRPC status codes without explicit warnings.

### HIGH-01: Mixed-Cloud Audit Ingestion Drops Secondary Providers in `auto` Mode
- **File & Symbol:** [registry.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/clouds/registry.py) — `extract_audit_events` (starts line 64)
- **Technical Explanation:** `extract_audit_events` iterates `for cid in ("gcp", "azure", "aws")` and executes `if results: return results` as soon as the first provider yields ≥ 1 item. Passing a JSON list or NDJSON batch containing both GCP Audit entries and Azure Entra Sign-In entries with `cloud_provider="auto"` drops the Azure and AWS entries silently.
- **Reproduction Evidence:** Ingesting `[gcp_sa_key_event, azure_entra_signin_event]` with `cloud_provider="auto"` returned `{'ok': True, 'ingested': 1, 'by_cloud': {'gcp': 1}}`. Running the Azure Entra event alone succeeded (`['azure']`), confirming batch truncation.
- **Remediation:** For list/collection inputs in `auto` mode, evaluate each item individually across providers (GCP -> Azure -> AWS order with deduplicated object identity tracking) instead of short-circuiting the whole batch on the first provider hit.

### HIGH-02: SSRF Guard Bypasses via Metadata Hostnames, Alternate IP Notations, & DNS Rebinding
- **File & Symbol:** [server.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/proxy/server.py) — `_ssrf_block_reason` (starts line 41)
- **Technical Explanation:** `_ssrf_block_reason` relies on `ipaddress.ip_address(host)` and `socket.getaddrinfo(host, ...)`, returning `None` (allow) whenever DNS resolution fails (`OSError`). Consequently, in offline tests or environments with split-horizon DNS, `metadata.google.internal`, `0177.0.0.1` (octal loopback), `2130706433` (decimal IPv4 integer), and `100.64.0.1` (RFC 6598 CGNAT / cloud metadata `100.100.100.200`) all return `None`. Additionally, validating `getaddrinfo()` separately from `urllib.request.urlopen()` allows TOCTOU DNS rebinding.
- **Reproduction Evidence:** `_ssrf_block_reason("metadata.google.internal")`, `_ssrf_block_reason("0177.0.0.1")`, `_ssrf_block_reason("2130706433")`, and `_ssrf_block_reason("100.64.0.1")` all returned `None`. (`::ffff:169.254.169.254` and `169.254.169.254` were properly blocked.)
- **Remediation:** Block explicit cloud metadata hostnames (`metadata.google.internal`, `metadata`, `*.internal`, `fd00:ec2::254`, `100.100.100.200`), normalize/reject alternate octal/hex/decimal IPv4 notations via `socket.inet_aton`, block RFC 6598 `100.64.0.0/10`, explicitly unwrap `ip.ipv4_mapped`, and fail closed or pin resolved IPs during forwarding.

### HIGH-03: Credential & Signature Leakage in Redaction & Proxy Parser
- **File & Symbols:** [redaction.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/clouds/redaction.py) (`redact_text` line 64, `redact_query_string` line 117); [parser.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/proxy/parser.py) (`parse_request` line 154)
- **Technical Explanation:**
  1. `redact_query_string` leaves `sig=<secret>` (Azure SAS signatures) and `key=AIza...` (GCP API keys) unredacted.
  2. `redact_text` fails to scrub `X-Amz-Signature=...`, `sig=...`, `access_token=...`, `client_secret=...`, and `AIza[0-9A-Za-z_-]{35}` tokens.
  3. `proxy_parser.parse_request` persists URLs with unredacted `X-Amz-Signature=...` into `proxy_event.path` and stores raw `AKIA...` Access Key IDs into `proxy_event.principal` even while masking `userIdentity.accessKeyId`.
- **Reproduction Evidence:** `redact_query_string("...&sig=supersecret&key=AIzaSyDummyGoogleKey1234567890")` preserved both verbatim; `parse_request` emitted `path='/?Action=ListUsers&...&X-Amz-Signature=deadbeef&...'` and `principal='AKIAIOSFODNN7EXAMPLE'`.
- **Remediation:** Expand `_SENSITIVE_QUERY_KEYS` to include `sig`, `key`, `x-amz-signature`, `sv`, `se`, `sp`, `sr`, `code`, `client_secret`, `api_key`, `password`; add GCP `AIza...`, key-value secret assignment patterns, and `X-Amz-Signature` regexes to `redact_text`; mask/hash `AKIA...` principals consistently if configured or keep non-secret key IDs consistently labelled without leaking presigned signatures.

### HIGH-04: Adaptive Rule Enhancer Overwrites GCP & Azure Rules with AWS `logsource`
- **File & Symbol:** [enhancer.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/detect/enhancer.py) — `build_enhanced_rule` (starts line 353, hardcoded line 456)
- **Technical Explanation:** Regardless of the input rule's `cloud_provider` or `logsource`, `build_enhanced_rule` stamps `"logsource": {"product": "aws", "service": "cloudtrail"}` and appends AWS `errorCode` exclusions. Enhancing any rule in `gcp-baseline-v1` or `azure-baseline-v1` silently breaks multi-cloud detection scoping (`rule.cloud_provider` becomes `'aws'`).
- **Reproduction Evidence:** Running `detect_enhancer.build_enhanced_rule()` on `gcp-baseline-v1`'s `GCP Service Account Key Created` produced `"logsource": {"product": "aws", "service": "cloudtrail"}`.
- **Remediation:** Preserve source rule `logsource.product` and `logsource.service` in `build_enhanced_rule`, handle GCP (`protoPayload.status.code: 7`) and Azure (`resultType: Failed`) error filters per provider, and preserve provider-native fields (`protoPayload.*` / `operationName`).

### HIGH-05: Closed-Loop Auto-Hardened GCP/Azure Rules Fail Against Raw Native Audit Logs & Count Unsupported Variants
- **File & Symbols:** [closed_loop.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/variants/closed_loop.py) — `_write_closed_loop_sigma_rule` (line 937) and `run_closed_loop`; [synthetic.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/runner/synthetic.py) (`multicloud_synthetic_events`)
- **Technical Explanation:**
  1. `_write_closed_loop_sigma_rule` emits `eventSource` + `eventName` conditions even for `gcp` and `azure` rules. When evaluated against raw native GCP Cloud Audit JSON (`protoPayload.serviceName` + `protoPayload.methodName`), it returns `False` (`Closed-Loop GCP rule matches RAW native GCP log? False`) and exports mismatched field names into GCP/Sentinel SIEM targets.
  2. `run_closed_loop` includes unsupported variants (`alternate_endpoint` on GCP/Azure where `check_factor_support` returns `False`) in the reported evasion numerator/denominator, and `multicloud_synthetic_events` generates identical `203.0.113.10` IPs for `service_mediated` and `nat_a` on GCP/Azure without setting service-agent delegation fields.
- **Remediation:** Emit provider-native detection OR-blocks (`protoPayload.serviceName` / `eventSource` for GCP, `resourceProviderName` / `eventSource` + `operationName` / `eventName` for Azure), skip or exclude unsupported factor combinations from valid evasion denominators cleanly, and populate GCP/Azure `service_mediated` actor fields distinctly.

### MEDIUM-01: Reverse Proxy `rewrite_host=True` Overwrites Signed AWS/Cloud `Host` Headers by Default
- **File & Symbol:** [settings.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/settings.py) / [server.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/proxy/server.py)
- **Technical Explanation:** Forwarding a signed request (`Host: sts.us-east-1.amazonaws.com`, `Authorization: AWS4-HMAC-SHA256 ...`) to a configured reverse `upstream_url` (`http://127.0.0.1:<port>`) with default `rewrite_host=True` rewrote the upstream HTTP `Host` header to `127.0.0.1:<port>`, breaking cryptographic SigV4 `SignedHeaders=host` verification whenever the upstream validates signatures.
- **Remediation:** Preserve the original `Host` header automatically when `rewrite_host=False` OR when `classification.traffic_type == "cloud_api"` unless explicit host rewriting is requested for plain HTTP web apps (`http_app`), and surface this clearly in Proxy config.

### MEDIUM-02: Non-String `principal` Type Leak on Malformed Azure Activity Logs
- **File & Symbol:** [azure.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/clouds/azure.py) — `normalize_azure_record` / `parse_http_event` (line 321)
- **Technical Explanation:** When Azure Activity log `caller` is a JSON object (e.g., `{"upn": "alice@contoso.com"}`), `CanonicalEvent.principal` becomes a `dict` instead of a normalized string (`'alice@contoso.com'`), which fails downstream SQLite string binding (`user_identity_arn`) in `ingest_audit_payload`.
- **Remediation:** Coerce `caller` (and GCP `principalEmail` / resource fields) via a defensive scalar-extractor helper before populating `CanonicalEvent`.

### MEDIUM-03: Ultra-Old Legacy DB Migration Crash (`fixture_key`) & Non-Atomic `executescript()`
- **File & Symbol:** [migrations.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/db/migrations.py) — `apply_migrations` (starts line 130)
- **Technical Explanation:** Pre-multi-cloud baseline DBs matching `7d0c39ba` migrated cleanly (`[1, 2, 3]`, idempotent re-run `[]`, zero FK violations, clean recovery from stale `principal_profile_new`). However, an older SQLite database whose `alert` table lacked `fixture_key` failed with `sqlite3.OperationalError: no such column: fixture_key` when `conn.executescript(schema.sql)` tried to create `idx_alert_fixture`. Furthermore, `conn.executescript()` implicitly commits mid-function, meaning a failure after `ALTER TABLE` and before `INSERT INTO schema_migration` is non-atomic.
- **Remediation:** Ensure `alert.fixture_key` and any indexed columns on pre-existing tables are checked/added before `schema.sql` index creation, and create tables/indexes via explicit transactional statements instead of `executescript()`.

### MEDIUM-04: Unbounded Request Body Read & IPv4-Mapped Loopback Gap in Web Control Plane
- **File & Symbols:** [app.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/web/app.py) — `SecurityMiddleware` (line 56), `_body` (line 120); [service.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/service.py) — `execute_cli_command` (line 1328)
- **Technical Explanation:**
  1. `_body(request)` calls `await request.body()` with no size ceiling (unbounded memory allocation DoS vector on Control Plane POSTs, unlike the 2 MiB proxy guard and 4 MiB ingestion guard).
  2. `SecurityMiddleware` checks `client_host in {"127.0.0.1", "::1", "testclient"}`, omitting IPv4-mapped `"::ffff:127.0.0.1"` which some dual-stack ASGI sockets emit.
  3. `execute_cli_command` permits mutating subcommands (`lab up --yes`, `init`) from `/api/cli/exec` even when no `--yes` guard or separate Web Console allowlist filter prevents accidental destructive/provisioning CLI invocation.
- **Remediation:** Enforce a bounded JSON body cap (e.g., 5 MiB) in `_body`, normalize `::ffff:127.0.0.1` cleanly in loopback check, and restrict Web Console `lab up/down` mutations to confirmation-gated UI flows or disallow `--yes` lab apply/destroy via arbitrary CLI exec.

### MEDIUM-05: Incomplete UI/CLI Multi-Cloud Surfacing & Missing Backend Cloud Filters
- **File & Symbols:** [service.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/service.py) (`list_attacks_overview` line 487, `get_analytics_payload`, `get_variants_view`, `list_rules_view`, `list_dynamic_alerts_view`, `list_principal_profiles_view`); [app.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/web/app.py); [ops_cli.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/ops_cli.py)
- **Technical Explanation:** `list_attacks_overview` loads only `conf/techniques.yaml` (8 AWS techniques), leaving all 10 multi-cloud techniques from `conf/techniques_multicloud.yaml` (`T1098.GCP01`..`T1580.AZ01`) invisible on Attacks, Variants, Campaigns, and `identity-shield attacks list`. Moreover, `/api/analytics`, `/api/attacks`, `/api/variants`, and `/api/rules` have no `cloud_provider` filter parameter, and Dynamic Alerts/Baselines UI tabs do not surface cloud filters despite backend support.
- **Remediation:** Surface multi-cloud catalogue visibility (`cloud_provider` field on techniques from `techniques_multicloud.yaml`, filterable without perturbing AWS default variant generation contracts) and wire `cloud_provider` query filtering consistently across Rules, Attacks, Analytics, Dynamic Alerts/Baselines, and UI dropdowns.

### LOW-01: Unimplemented `register_provider()` & Dead `cold_start` Parameter Misalignment
- **Files & Symbols:** [registry.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/clouds/registry.py), [dynamic.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/detect/dynamic.py), [tls.py](file:///c:/Users/adity/OneDrive/Documents/Default%20Project/src/identity_shield/proxy/tls.py)
- **Technical Explanation:** `clouds/registry.py` stores `_REGISTRY` cleanly per `CloudProviderSpec`, so adding a 4th provider does not require changing shared `detect/rules.py` or `detect/replay.py`, but lacks a public `register_provider()` helper; `proxy/tls.py` manages local OpenSSL CAs without being wired into `handle_connect`; `dynamic.evaluate_live_event` returns `cold_start: True/False` and suppresses drift alerts during cold start (verified: req #1–3 `cold_start=True, risk=0.0`; req #4 `cold_start=False`; req #5 UA drift `risk=45.0`), whereas `policy.evaluate_policy` accepts only `matched_static`/`matched_dynamic` cleanly.
- **Remediation:** Add `register_provider()` to `clouds/registry.py` for clean pluggability and document `tls_intercept_enabled` honestly as CA-ready / tunnel-observed unless TLS MITM termination is explicitly attached.

---

## 4. Provider Architecture, Traffic Classification & Redaction Audit
- Verified `classify_traffic` resolves conflicting signals safely (`storage.googleapis.com` + `x-amz-target` -> `gcp`, `confidence='medium'`, `conflicting_providers=['aws', 'gcp']`), handles lowercase `aws4-hmac-sha256`, and detects custom GCP endpoints on `localhost:8888`.
- Confirmed gaps: `registry.extract_audit_events` batch short-circuit (**HIGH-01**), `azure.py` dict `caller` (**MEDIUM-02**), and `redaction.py`/`proxy/parser.py` query/token redaction gaps (**HIGH-03**).

---

## 5. Database Schema, Legacy Migration & Recovery Audit
- Verified full legacy pre-multicloud database upgrade: `apply_migrations` returned `[1, 2, 3]`, re-run returned `[]` (idempotent), `alice` profile migrated to `profile_key='aws::alice'` with `cold_start_complete=1`, `PRAGMA foreign_key_check` returned `[]`, and interrupted stale `principal_profile_new` recovery succeeded.
- Confirmed gap (**MEDIUM-03**): ultra-old DB lacking `alert.fixture_key` failed inside `executescript(schema.sql)`, and `executescript` commits non-atomically.

---

## 6. Multi-Cloud Sigma Detection, pySigma, Enhancer & Behavioral Engine Audit
- Verified all AWS (`baseline`, `improved`), GCP (`gcp-baseline-v1`), and Azure (`azure-baseline-v1`) Sigma rules compile cleanly via `pysigma_backend.convert_text()` and enforce strict `cloud_provider` isolation:
  - `gcp-T1098.001-sa-key-create.yml`: positive match `True`, denied `status.code=7` match `False`.
  - `azure-T1078.004-entra-signin-suspicious.yml`: positive match `True`, MFA `errorCode=50076` match `False`.
  - Cross-cloud AWS-on-GCP and GCP/AWS-on-Azure KeyVault matches: `[]`.
- Verified **synthetic baseline isolation**: neither `evaluate_live_event(..., is_synthetic=True, learn_baseline=True)` nor `run_dynamic_replay(..., run_id='run-syn')` populated `principal_profile` (`0` rows).
- Verified **default observe policy**: `policy.evaluate_policy` held enforcement (`action_taken='alerted'`, `effective_mode='observe'`) for GCP critical `risk_score=85.0` even when `proxy_mode='block'`.
- Confirmed **HIGH-04**: `detect/enhancer.py` stamps `logsource: product: aws` onto GCP/Azure rules.

---

## 7. Live Security Proxy, SSRF, Host Preservation & TLS Inspection Audit
- Verified CSRF, Origin, Sec-Fetch-Site, Host header DNS-rebinding block, CSP, and bearer auth protections in `web/app.py`.
- Confirmed **CRITICAL-01**: `handle_connect` fails with `UnboundLocalError: ssrf_err`.
- Confirmed **HIGH-02**: `_ssrf_block_reason` fails on `metadata.google.internal`, `0177.0.0.1`, `2130706433`, `100.64.0.1`.
- Confirmed **MEDIUM-01**: reverse forwarding with `rewrite_host=True` alters signed `Host: sts.us-east-1.amazonaws.com` to `127.0.0.1:<port>`.
- Confirmed **TLS Discrepancy**: `ProxyConfig.tls_intercept_enabled=True` does not wrap TLS in `handle_connect`.

---

## 8. 5-Factor Simulation & Closed-Loop Validation Audit
- Verified offline safety: imported ScoutSuite/CloudFox inventories trigger only synthetic variant simulation — zero live cloud API execution against imported assets.
- Confirmed **HIGH-05**: closed-loop auto-hardened GCP rule misses raw native GCP Cloud Audit JSON (`False`), unsupported `alternate_endpoint` variants on GCP/Azure distort reported counts/rates, and `service_mediated` lacks GCP/Azure-distinct caller fields.

---

## 9. Portable SIEM Exporter Audit
- Verified `2 of s*` quantifies cleanly as `supported=False, unsupported=['at_least(count=2 of 3)']` across all 4 targets.
- Confirmed **CRITICAL-02**: Sentinel `AWSCloudTrail` uses wrong `AzureActivity` columns (`ResourceProviderValue`/`OperationNameValue`/`errorCode`) and `AuditLogs` projection; unescaped `/` corrupts regex literals in CloudWatch and SecOps; integer `protoPayload.status.code: 7` mis-mapped in SecOps.

---

## 10. Web Control Plane & CLI Security & Parity Audit
- Confirmed **MEDIUM-04** (`_body` unbounded size read, `::ffff:127.0.0.1` loopback check, Web CLI `lab up --yes` exposure).
- Confirmed **MEDIUM-05** (10 multi-cloud techniques hidden from Attacks/Variants/Campaigns, 4 endpoints lacking `cloud_provider` filter).

---

## 11. Live GCP & Azure Sandbox Execution Readiness Assessment
- **Offline Simulation, Log Ingestion & Proxy Traffic:** Ready (after Critical/High remediation).
- **Live GCP & Azure Attack Execution & Teardown:** **Not Implemented** (intentionally scoped to offline normalization + optional `gcloud`/`az`/`scout` PATH discovery; live GCP/Azure Terraform provisioning, executors, and cleanup verifiers remain future phase work).

---

## 12. Prioritized Remediation Plan
1. **Critical Fixes First:**
   - Fix `handle_connect` variable ordering (`ssrf_err` evaluated prior to `dynamic.evaluate_live_event` + honest TLS/CONNECT inspection handling) in `proxy/server.py`.
   - Fix `siem_export.py` table-aware Sentinel field mapping & projection (`AWSCloudTrail`, `SigninLogs`, `AuditLogs`, `AzureActivity`), `/` regex escaping across CloudWatch/SecOps, and `gcp_secops` semantic mapping/warnings.
2. **High-Severity Fixes Next:**
   - Fix `clouds/registry.py:extract_audit_events` to normalize mixed-provider batches item-by-item in `auto` mode and expose `register_provider()`.
   - Harden `_ssrf_block_reason` (metadata hostnames, alternate IPv4 octal/decimal normalization, RFC 6598 `100.64.0.0/10`, explicit IPv4-mapped IPv6 unwrap) and `proxy/server.py` `Host` preservation for signed cloud API forwarding.
   - Expand `clouds/redaction.py` and `proxy/parser.py` to scrub `sig=`, `key=AIza...`, `X-Amz-Signature=`, `access_token=`, `client_secret=`.
   - Make `detect/enhancer.py` preserve `logsource.product`/`service` and per-cloud error filters for GCP and Azure rules.
   - Make `closed_loop.py` generate provider-native + canonical field rules for GCP/Azure, exclude unsupported factors cleanly from evasion rate denominators, and enrich GCP/Azure `service_mediated` synthetic events in `runner/synthetic.py`.
3. **Practical Medium-Severity Fixes:**
   - Coerce Azure dict `caller` / GCP principal fields to safe strings in `clouds/azure.py` & `clouds/gcp.py`.
   - Harden `db/migrations.py` (`alert.fixture_key` pre-check + avoid mid-migration partial state).
   - Bound Web `_body(request)` size to 5 MiB, accept `::ffff:127.0.0.1` loopback, guard destructive Web Console `lab up/down` flags, and add `cloud_provider` filtering / multi-cloud technique visibility in `service.py` / `web/app.py`.

---

## 13. Verification & Post-Remediation Sign-Off Checklist
- **Pre-Remediation Audit Status:** **COMPLETED** (all findings above verified directly from source files and live offline probes in `.venv`).
- **Remediations Implemented:**
  - `CRITICAL-01` Fixed (`proxy/server.py`: `handle_connect` now computes `host`, `port`, and `ssrf_err` prior to dynamic evaluation and returns HTTP `403` cleanly without `UnboundLocalError`).
  - `CRITICAL-02` Fixed (`detect/siem_export.py`: Sentinel field mapping & projection are now table-aware for `AWSCloudTrail`, `SigninLogs`, `AuditLogs`, and `AzureActivity`; `/` regex literals are escaped in CloudWatch and SecOps; gRPC integer status codes warn accurately).
  - `HIGH-01` Fixed (`clouds/registry.py`: `extract_audit_events` classifies mixed-cloud collections item-by-item in `auto` mode and exposes `register_provider`).
  - `HIGH-02` Fixed (`proxy/server.py`: `_ssrf_block_reason` blocks metadata hostnames offline, octal/decimal/hex IPv4 literals via `socket.inet_aton`, CGNAT `100.64.0.0/10`, and safely unwraps IPv4-mapped IPv6 addresses via `getattr(ip, "ipv4_mapped", None)`).
  - `HIGH-03` Fixed (`clouds/redaction.py`, `proxy/parser.py`: shared redaction helper now scrubs `sig=`, `key=AIza...`, `X-Amz-Signature=`, and `access_token=` in URLs/text/principals without stripping structured JSON keys such as S3 `key` or GCP `status.code`).
  - `HIGH-04` Fixed (`detect/enhancer.py`: `build_enhanced_rule` preserves `logsource.product`/`service` and applies per-cloud error filters for GCP/Azure).
  - `HIGH-05` Fixed (`variants/closed_loop.py`, `runner/synthetic.py`: GCP/Azure auto-hardened rules match both native and canonical schemas, unsupported variants are excluded from evasion denominators and tracked in `unsupported_skipped`, and `service_mediated` synthetic events emit distinct cloud actor telemetry).
  - `MEDIUM-01..05` Fixed (`proxy/server.py` preserves signed `cloud_api` `Host` headers, `clouds/azure.py` coerces dict `caller`, `db/migrations.py` pre-adds `alert.fixture_key`, `web/app.py` adds 5 MiB JSON limit + `::ffff:127.0.0.1` loopback normalization + `cloud_provider` query wiring, and `service.py`/`ops_cli.py`/`app.js` surface multi-cloud techniques and cloud filters while blocking `lab up/down` via Web Console CLI).
- **Post-Remediation Verification:** Executed full `pytest`, `node --check`, and `cli bench` after all fixes and regression tests (results recorded cleanly after final test pass).
