# Identity Shield — Refined Technical Plan

Status: draft for review
Scope: AWS only. No GuardDuty, no Docker, no Athena.
Baseline assumption: dedicated lab account exists; CloudTrail trail, SCPs and guardrails still to be built.

---

## 0. What changed from the original spec

The original design is sound in intent. Five things need to change for the results to be
defensible:

| # | Original | Change | Why |
|---|---|---|---|
| 1 | Re-run attacks in round 2 to test improved rules | **Replay stored CloudTrail** against new rulesets | Deterministic, free, apples-to-apples input, removes 5–15 min ingest lag from the loop |
| 2 | "4–5 variations per attack" generated pairwise | **OFAT primary + pairwise secondary**, explicit coverage claim | Pairwise over 5 factors needs ~10–13 rows; OFAT allows attribution of a miss to one axis |
| 3 | Variations assumed to vary | **Variant validity gate** | A variant whose CloudTrail record is byte-identical to baseline proves nothing |
| 4 | Detection time = time to alert | **Three separate latencies**, latency treated as censored | Most of the naive number is AWS delivery lag, not rule quality |
| 5 | IAM permission boundaries for safety | **Deny-list boundary + preflight policy simulation**, plus account SCPs and region lock | A naive boundary blocks the privilege-escalation primitives under test, converting "attack blocked" into a false "evaded" |
| 6 | 8–10 techniques including Defense Evasion | **Exactly the 8 techniques in the workflow diagram**; Defense Evasion dropped, Initial Access added | Diagram is now authoritative; dropping T1562.008 removes the log-tampering risk and the need for a tamper-proof evidence sink |

Additional decisions adopted:

- **Replay architecture** (user-confirmed): live attacks are executed once per variant; rule
  iteration happens entirely on captured logs. Hold-out variants run live once against the
  improved ruleset.
- **Pre-registration**: the round-1 ruleset is frozen and timestamped before any variant result
  is inspected.
- **Baseline ruleset source**: see open question Q1. Default assumption is SigmaHQ
  `rules/cloud/aws/` plus a small number of authored rules for gaps.
- **Technique set**: fixed to the 8 techniques in the workflow diagram (§5). Defense Evasion is
  out, so the log-tampering risk disappears.

---

## 1. Architecture

```
                 ┌──────────────┐
   Terraform ───▶│ AWS lab acct │  dedicated account, SCP, region lock, trail → S3
                 └──────┬───────┘
                        │ CloudTrail (mgmt + optional data events)
                        ▼
  M1 Discovery ──┐   ┌── S3 bucket ──▶ SQS ──▶ collector
  M2 Weakness  ──┤   │                              │
                 ├──▶│ M6 Parser ──▶ SQLite ◀───────┘
  M3 Techniques ─┘   │                 │
                     │                 ├──▶ M6 Rule engine (Python + pySigma)
  M4 Variant gen ──▶ M5 Runner ────────┘         │
                     │  (boto3/Stratus)          ▼
                     │                     alerts + verdicts
                     ▼                           │
                  cleanup                   M7 Replay / re-tune
                                                 │
                                                 ▼
                                          M8 Dashboard + report
```

### Module contracts (the interfaces that keep the team unblocked)

| Module | Input | Output | Contract |
|---|---|---|---|
| M1 Discovery | AWS creds | `inventory.json` (accounts, principals, resources, trail config) | read-only |
| M2 Weakness | `inventory.json` | `findings.json` (rule id, resource, severity, evidence) | read-only |
| M3 Techniques | `inventory.json` | `techniques.yaml` (ATT&CK id, stratus id or boto3 executor, required perms) | static |
| M4 Variants | `techniques.yaml` + `factors.yaml` | `variants.jsonl` (variant_id, factor levels, seed, spec hash) | deterministic, no AWS |
| M5 Runner | `variants.jsonl` | `trials` rows + raw CloudTrail in S3 | writes AWS state, must self-clean |
| M6 Detection | raw CloudTrail | `events`, `alerts` rows | read-only w.r.t. cloud |
| M7 Replay | `events` + `ruleset` | `alerts` rows for new ruleset | read-only w.r.t. cloud |
| M8 Report | SQLite | dashboard + PDF/markdown | read-only |

Every module reads/writes SQLite or JSON files. No module imports another module's internals.
M6 and M8 must be runnable against fixtures before the lab exists (see §9, M0).

---

## 2. Repository layout

```
identity-shield/
  pyproject.toml
  README.md
  Makefile                    # task aliases, no shell loops on Windows
  infra/
    terraform/                # account guardrails, trail, bucket, SQS, roles
      modules/trail/
      modules/guardrails/
      envs/lab/
  conf/
    factors.yaml              # factor + level definitions
    techniques.yaml           # technique catalogue
    variants/<technique>.yaml # per-technique variant specs
    rules/
      baseline/               # frozen round-1 ruleset (Sigma YAML)
      improved/               # round-2 ruleset
      rulesets.yaml           # version → path → frozen_at
  src/identity_shield/
    inventory/                # M1
    weakness/                 # M2
    techniques/               # M3 (loader/validator only)
    variants/                 # M4  generator, resolver, coverage report
    runner/                   # M5  preflight, execute, verify, collect, sweep
    detect/                   # M6  parser, matcher, pysigma backend, evaluator
    replay/                   # M7
    report/                   # M8
    db/                       # schema.sql, migrations, helpers
    aws/                      # session factory, tagging, pagination helpers
  fixtures/
    cloudtrail/               # synthetic + captured JSON, one dir per technique
    expected_alerts.json
  tests/
  dashboard/
    app.py
    pages/
  data/
    identity_shield.db        # gitignored
```

---

## 3. Data model (SQLite)

SQLite is sufficient; volume is tens of thousands of events, not millions. PostgreSQL only if
the team wants concurrent writers.

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE lab_run (
  run_id            TEXT PRIMARY KEY,        -- ULID; used as AWS resource tag value
  started_at        TEXT NOT NULL,
  ended_at          TEXT,
  aws_account_id    TEXT NOT NULL,
  region            TEXT NOT NULL,
  git_sha           TEXT,
  ruleset_version   TEXT NOT NULL,
  collector_lag_ms  INTEGER,                 -- measured, see §7
  notes             TEXT
);

CREATE TABLE technique (
  technique_id      TEXT PRIMARY KEY,        -- T1136.003
  name              TEXT NOT NULL,
  tactic            TEXT NOT NULL,           -- discovery | persistence | ...
  executor          TEXT NOT NULL,           -- stratus | boto3
  executor_ref      TEXT,                    -- stratus id, or python callable path
  event_names       TEXT NOT NULL,           -- JSON array of expected CloudTrail eventName
  requires_data_events INTEGER NOT NULL DEFAULT 0,
  requires_evidence_sink INTEGER NOT NULL DEFAULT 0,  -- e.g. StopLogging
  success_check     TEXT NOT NULL,           -- JSON: how attack success is verified
  required_actions  TEXT NOT NULL            -- JSON array: IAM actions preflight must simulate
);

CREATE TABLE variant (
  variant_id        TEXT PRIMARY KEY,        -- <technique>-<set>-<nnn>
  technique_id      TEXT NOT NULL REFERENCES technique,
  variant_set       TEXT NOT NULL CHECK (variant_set IN
                      ('baseline','ofat','pairwise','holdout','benign')),
  factor_levels     TEXT NOT NULL,           -- JSON {"identity_context":"assumed_role",...}
  seed              INTEGER NOT NULL,
  spec_sha256       TEXT NOT NULL,
  notes             TEXT
);

CREATE TABLE trial (
  trial_id          TEXT PRIMARY KEY,
  run_id            TEXT NOT NULL REFERENCES lab_run,
  variant_id        TEXT NOT NULL REFERENCES variant,
  repetition        INTEGER NOT NULL,
  window_start      TEXT NOT NULL,
  window_end        TEXT,
  attack_succeeded  INTEGER,                 -- 0 | 1 | NULL (not verified)
  attack_evidence   TEXT,                    -- JSON
  variant_changed   INTEGER,                 -- 0 | 1  (validity gate)
  variant_diff      TEXT,                    -- JSON {"userAgent":["boto3/1.34", "aws-cli/2.15"]}
  error             TEXT,
  UNIQUE (run_id, variant_id, repetition)
);

CREATE TABLE event (
  event_id          TEXT PRIMARY KEY,        -- CloudTrail eventID
  trial_id          TEXT REFERENCES trial,
  event_time        TEXT NOT NULL,           -- ISO8601 UTC
  received_at       TEXT NOT NULL,           -- when our collector saw it
  event_source      TEXT,
  event_name        TEXT,
  aws_region        TEXT,
  source_ip         TEXT,
  user_agent        TEXT,
  user_identity_type TEXT,
  user_identity_arn TEXT,
  error_code        TEXT,
  raw               TEXT NOT NULL            -- full JSON
);
CREATE INDEX idx_event_trial ON event(trial_id);
CREATE INDEX idx_event_lookup ON event(event_name, event_time);

CREATE TABLE ruleset (
  ruleset_version   TEXT PRIMARY KEY,
  created_at        TEXT NOT NULL,
  frozen_at         TEXT,                    -- pre-registration timestamp
  description       TEXT,
  source            TEXT                     -- sigmahq | authored | mixed
);

CREATE TABLE rule (
  rule_id           TEXT PRIMARY KEY,
  ruleset_version   TEXT NOT NULL REFERENCES ruleset,
  title             TEXT,
  level             TEXT,
  sigma_yaml        TEXT NOT NULL,
  technique_id      TEXT,
  authored_by       TEXT
);

CREATE TABLE alert (
  alert_id          TEXT PRIMARY KEY,
  rule_id           TEXT NOT NULL REFERENCES rule,
  event_id          TEXT NOT NULL REFERENCES event,
  trial_id          TEXT,
  evaluated_at      TEXT NOT NULL,
  latency_ms        INTEGER,                 -- evaluated_at - event_time
  matched_fields    TEXT
);

-- Derived view: one row per trial with the outcome variables
CREATE VIEW v_trial_outcome AS
SELECT t.trial_id, t.run_id, t.variant_id, v.technique_id, v.variant_set,
       t.attack_succeeded,
       CASE WHEN EXISTS (SELECT 1 FROM alert a WHERE a.trial_id = t.trial_id)
            THEN 1 ELSE 0 END AS detected,
       (SELECT MIN(a.latency_ms) FROM alert a WHERE a.trial_id = t.trial_id) AS latency_ms
FROM trial t JOIN variant v USING (variant_id);
```

Invariants enforced in code, not just schema:

- Every `trial` has at least one `event` on its technique's `event_names`, or the error is recorded.
- `attack_succeeded IS NULL` trials never enter detection metrics (they are infrastructure failures).
- `variant_changed = 0` trials are excluded from evasion metrics and flagged in the report.

---

## 4. Variant model (Module 4)

### 4.1 Factors

Five axes, matching the five change types in the workflow diagram (*who, where, which tool,
timing, API settings*), defined once in `conf/factors.yaml`:

| Factor | Levels | Detection surface in CloudTrail |
|---|---|---|
| `identity_context` | IAM user; same-account assumed role; assumed role via instance profile / Lambda exec role; federated session | `userIdentity.type`, `.arn`, `.sessionContext`, `.invokedBy` |
| `client_tool` | boto3 default UA; aws-cli UA; Terraform UA; non-SDK HTTP client | `userAgent` |
| `network_origin` | NAT gateway A (EIP1); NAT gateway B (EIP2); service-mediated (Lambda/ECS/CFN so `sourceIPAddress` is a service principal); alternate regional endpoint | `sourceIPAddress`, `awsRegion` |
| `timing` | business hours; off-hours; burst (N calls < 10 s); spread (calls > 10 min apart) | `eventTime` spacing |
| `api_form` | canonical call; alternative API reaching the same objective; extra optional parameters; batched/paginated; **identifier shape** (conventional `backup-…` vs attacker-typical `TempAdmin`) | `eventName`, `requestParameters.*` (incl. `userName`, `roleName`, `policyName`) |

**Wire-level constraints (important, and worth stating in the report):**
SigV4 canonicalisation means boto3 parameter dict ordering is not observable. "Different
parameter form" must therefore mean *different parameter values, optionality, or API path* — not
JSON key order or whitespace. Do not claim more than the logs can show.

**`userAgent` depth:** boto3 `Config(user_agent_extra=…)` appends rather than replaces, so a
genuinely distinct UA requires a non-SDK HTTP client or a patched UA hook. Budget one day for
this; it is one of the highest-value evasion axes.

### 4.2 Variant sets

- **baseline** — canonical form of the technique, one per technique. Calibration anchor.
- **OFAT** — 4–5 variants, each changing exactly one factor from baseline. Primary set.
- **pairwise** — strength-2 covering array across all six factors, ~10–13 variants per technique.
  Secondary set; used to show coverage claims, not per-axis attribution.
- **holdout** — 1 variant per technique, generated by a different seed, **never inspected** until
  the improved ruleset is evaluated.
- **benign** — 10–15 normal-activity variants matched to the same factor levels, for false alarms.

Total for 8 techniques: 8 × (1 + 5 + 12 + 1) = 152 variants, plus ~12 benign.

Live execution budget (everything else is replay-only):

| Set | Variants | Reps | Live trials |
|---|---|---|---|
| baseline + OFAT | 48 | 3 | 144 |
| pairwise | 96 | 1 | 96 |
| holdout | 8 | 1 | 8 |
| benign | 12 | 3 | 36 |
| **total** | | | **284** |

284 live trials is the real cost and runtime driver. Every rule iteration after the first capture
is free, which is the whole reason for the replay architecture.

### 4.3 Generation

```python
# allpairspy with constraint filtering
from allpairspy import AllPairs

def valid(combo) -> bool:
    lv = dict(zip(FACTORS, combo))
    if lv["network_origin"] == "lambda_mediated" and lv["identity_context"] == "iam_user":
        return False                      # contradictory
    if lv["api_form"] == "batched" and not TECHNIQUE.supports_batching:
        return False
    return True

for i, combo in enumerate(AllPairs(LEVELS, filter_func=valid)):
    ...
```

Output is `variants.jsonl` plus a **coverage report** (`pairwise_coverage.md`) stating, per
technique: factor count, level count, generated rows, pairwise coverage %, and every rejected
combination with its reason. This report is a deliverable, not a debug artifact.

Determinism: `seed` is derived from `sha256(technique_id + variant_set + index)` so the same
spec always regenerates the same variants.

### 4.4 Validity gate (the novelty, and the thing that keeps the study honest)

A variant counts only if both hold:

1. **Effectiveness** — the attack still achieved its objective (`success_check` passes). Otherwise
   it is an infrastructure failure, not an evasion.
2. **Observable difference** — at least one CloudTrail field named by the varied factor differs
   from the baseline trial, with the expected values. Implementation: diff the event tuple
   `(eventName, eventSource, userAgent, sourceIPAddress, userIdentity.type, userIdentity.arn,
   eventTime bucket, requestParameters)` against baseline; assert the intended field is in the
   diff set.

Trials failing (2) are kept in the database with `variant_changed = 0` and excluded from evasion
metrics. Report the count — "we generated 152 variants and 9 were not actually distinct in the
logs" is a finding, not a failure.

---

## 5. Technique catalogue (Module 3)

The eight techniques are fixed by the workflow diagram. What this section adds is the
**execution mapping** — how each one is actually simulated, which CloudTrail fields it produces,
and how success is verified. Nothing here is asserted from memory; confirm each `executor_ref`
against `stratus list` before writing `techniques.yaml`.

| # | ATT&CK | Technique | Tactic | Simulated action | Executor | CloudTrail surface | Success check |
|---|---|---|---|---|---|---|---|
| 1 | T1087.004 | Cloud Account Discovery | Discovery | `iam:ListUsers`, `ListRoles`, `ListAccessKeys`, `GetAccountAuthorizationDetails` | boto3 (no Stratus equivalent) | `ListUsers`, `ListRoles`, `GetAccountAuthorizationDetails` | principal inventory returns ≥ expected number of principals |
| 2 | T1526 | Cloud Service Discovery | Discovery | `sts:GetCallerIdentity` then per-service `Describe*`/`List*` sweep across services and regions | boto3 | `GetCallerIdentity`, `DescribeInstances`, `ListBuckets`, … | ≥ N distinct services answered without `AccessDenied` |
| 3 | T1580 | Cloud Infrastructure Discovery | Discovery | `ec2:DescribeInstances/SecurityGroups/Subnets/Vpcs`, `s3:ListAllMyBuckets`, `elbv2:DescribeLoadBalancers` | Stratus `aws.discovery.ec2-enumerate-from-instance` (partial) + boto3 | `DescribeInstances`, `DescribeSecurityGroups`, `ListBuckets` | inventory snapshot contains ≥1 resource for ≥3 services |
| 4 | T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | authenticate as a pre-provisioned valid principal (console **and** API), then perform one benign permitted action | boto3 / console | `ConsoleLogin` (+ `additionalEventData.MFAUsed`), `GetCallerIdentity`, `AssumeRole` | session established and the benign action succeeded |
| 5 | T1098.001 | Additional Cloud Credentials | Persistence | `iam:CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `iam:UpdateAssumeRolePolicy`, inject an SSH key | Stratus `aws.persistence.iam-create-access-key`, `…iam-create-user-login-profile` | `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `UpdateAssumeRolePolicy` | the new credential actually authenticates |
| 6 | T1098.003 | Additional Cloud Roles | Persistence / PrivEsc | `iam:AttachRolePolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, or `iam:PassRole` into Lambda/EC2 to reach a higher-privilege role | Stratus `aws.persistence.iam-backdoor-role` + boto3 PassRole path | `AttachRolePolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, `PassRole`, then `AssumeRole` | escalated principal can call an action that was denied before |
| 7 | T1552.005 | Cloud Instance Metadata API | Credential Access | fetch the instance-profile credentials from IMDS (v1 and v2), then use them | Stratus `aws.credential-access.ec2-steal-instance-credentials` | **no IMDS event exists**; evidence is the subsequent API calls as the instance role, with `sourceIPAddress` = instance EIP/NAT | stolen credentials authenticate |
| 8 | T1530 | Data from Cloud Storage | Collection | `s3:ListObjectsV2` + `s3:GetObject` against a lab bucket | boto3 | `ListBucket`, `GetObject` — **data events, not management events** | retrieved bytes match the expected checksum |

### 5.1 Consequences of this specific set

**Defense Evasion is gone.** No `cloudtrail:StopLogging` / `DeleteTrail`. The evidence-integrity
risk disappears, and a single in-account trail with log-file validation on is sufficient. §6.1's
"second account / Object Lock" control is downgraded to optional.

**T1530 forces a data-events decision.** Management events do not include `GetObject`. A second
trail (or an additional selector on the main trail) must log S3 data events for **one lab bucket
prefix only**, or technique #8 has no observable evidence at all. This is not optional — it is a
prerequisite for 1/8 of the corpus.

**T1552.005 is a detection gap by construction.** AWS does not log IMDS access. The only detectable
signal is the *stolen identity's* subsequent behaviour, so detection rules for #7 must be
behavioural (new geo/UA/first-use of an instance role for human-shaped API calls). This makes #7
one of the more interesting techniques rather than a straightforward one.

**T1078.004 is the highest-value variant target.** A valid account doing permitted things is
indistinguishable from normal activity except on `sourceIPAddress`, `userAgent`, `eventTime`, MFA
state and session provenance — which is exactly the factor set. Expect the largest evasion
variance here, and expect the biggest false-alarm pressure from it too.

**Three of eight are Discovery.** Rules for enumeration are volume/threshold-shaped and will
probably be caught most of the time. Expect low variance and high detection rate for #1–#3, with
the informative results concentrated in #4–#8. Do not let the aggregate detection rate be dominated
by the easy third — report per tactic.

**Technique #6 is what the permission-limit design has to accommodate.** See §6.1.


---

## 6. Lab infrastructure (Terraform)

### 6.1 Guardrails (blast radius, not capability restriction)

| Control | Implementation | Rationale |
|---|---|---|
| Account isolation | Dedicated account in an AWS Organization | hard boundary |
| Region lock | SCP `Deny` when `aws:RequestedRegion` not in `[eu-west-1]` (plus `us-east-1` for global services) | prevents accidental global sprawl |
| Service deny-list | SCP deny `organizations:*`, `account:*`, `billing:*`, `route53domains:*`, `support:*`, and all `.amazonaws.com` third-party writes | cost + scope |
| Spend guard | SCP deny instance classes above t3.small; budget alarm at a low threshold | cost |
| **IAM permission limit (as specified)** | deny-list `PermissionsBoundary` on test principals: permits the eight techniques' primitives; denies any action on resources outside `arn:aws:*:<lab-acct>:*`; denies `organizations:*`, `account:*`, `billing:*`, `support:*`; pins IAM resource names to an `is-` prefix | satisfies the "IAM permission limit" step without silently blocking the escalation primitives under test |
| **Boundary-vs-technique validation** | preflight runs `iam:SimulatePrincipalPolicy` over the technique's `required_actions` and **aborts if any is denied** | makes "blocked by the lab" impossible to mistake for "evaded the rules" |
| Credential hygiene | STS assume-role with ≤1 h session, MFA on the operator principal, no long-lived keys on disk | safety |
| Trail integrity | single in-account trail, multi-region, log-file validation on, plus one data-event selector scoped to the T1530 bucket | Defense Evasion is out of scope, so tamper-proofing is not required; log-file validation still catches accidental corruption |

### 6.2 Logging pipeline

```
CloudTrail (management events, multi-region, log-file validation on)
  + data-event selector: s3:GetObject / s3:ListBucket on arn:aws:s3:::is-lab-data-*/*   (T1530)
  → S3 bucket  s3://lab-cloudtrail-<acct>-<run>/
      prefix: AWSLogs/<acct>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/
  → S3 event notification → SQS → collector (boto3, DeleteMessage on commit)
```

Polling S3 alone is acceptable but adds up to ~5 min of avoidable latency on top of AWS delivery.
S3→SQS is the smallest thing that makes collection responsive. If the team wants to avoid SQS,
poll every 60 s and record the added lag honestly.

Data events (S3 object-level): **off by default**. If the Collection technique requires them,
enable for one prefix only, and note in the report that the log model differs from management-only.

### 6.3 Resource discipline

- Every AWS resource created by M5 carries tags: `identity-shield:run-id`, `:trial-id`, `:variant-id`.
- `sweep --run-id` enumerates via `resourcegroupstaggingapi` and deletes by tag, idempotently.
- Runner asserts after every trial that tagged resources = 0 (except deliberate persistence
  artifacts, which are recorded and cleaned at end of trial batch).
- Cleanup API calls are themselves evidence — collect logs *after* cleanup as well as before.

---

## 7. Runner (Module 5)

Per-trial state machine:

```
preflight → execute → verify_success → collect_logs → diff_variant → cleanup → record
```

**Preflight (hard aborts, not warnings):**

1. `sts:GetCallerIdentity` account == expected lab account, else abort.
2. Session is assumed-role with expiry > 15 min.
3. Target region ∈ allow-list.
4. Trail status `is-logging == true` and last delivery < 15 min ago.
5. S3 sink reachable and writable.
6. Estimated API cost of the trial < per-trial budget.
7. No resource with this `run_id` already exists (prevents duplicate trials).
8. `iam:SimulatePrincipalPolicy` returns `allowed` for every action in the technique's
   `required_actions`. A boundary that blocks the attack would otherwise be recorded as an
   evasion (see §6.1).

**Execution:** Stratus (`stratus detonate <id> --profile lab`) or boto3 callable, both behind one
`Executor` interface. Stratus's own `cleanup` is invoked, then our tag sweeper as a second pass.

**Verification:** per-technique `success_check` JSON, e.g.

```json
{"type": "resource_exists", "service": "iam", "query": "list_access_keys",
 "args": {"UserName": "{created_user}"}, "expect": "non_empty"}
{"type": "assume_role_succeeds", "role_arn": "{backdoored_role}"}
```

"No exception raised" is never sufficient.

**Collection:** wait for all `event_names` matching the trial window to appear in the sink, with a
hard timeout (default 20 min). Record `received_at` per event so AWS delivery lag is measurable.
On timeout: record `error`, keep trial, exclude from metrics.

---

## 8. Detection (Modules 6 + 7)

### 8.1 Matching engine

Two-stage design:

1. **Storage**: SQLite (§3). Raw JSON retained verbatim.
2. **Evaluation**: rules compile to Python predicates over parsed event dicts, not SQL. Volume
   (~50 k events) makes a Python scan trivial, and it avoids SQLite `REGEXP`/JSON-path portability
   problems. SQLite stores; Python evaluates.

### 8.2 Sigma on CloudTrail

`pySigma` has no first-party CloudTrail backend — this is real work, and it is one of the
project's own contributions. Design:

```
Sigma YAML
  → sigma.collection.SigmaCollection
  → pySigma processing pipeline (reuse SigmaHQ pipelines/aws/cloudtrail.yml for field normalisation)
  → custom IdentityShieldBackend(Backend)
        field mapping:  eventName → e["eventName"]
                        userIdentity.type → e["userIdentity"]["type"]
                        requestParameters.userName → e["requestParameters"]["userName"]
        modifiers:      contains/startswith/endswith → substring
                        re → re.search
                        all/any list values
        output:         Python predicate source + compiled callable
  → matcher.signature(rule) -> bool
```

Backend scope for v1: `str`, `num`, `bool` field types; `eq`, `contains`, `startswith`, `endswith`,
`re`, `in`, `all`; and/or/not conditions. That covers the large majority of SigmaHQ AWS rules.
Track uncompileable rules explicitly — "12 of 78 SigmaHQ AWS rules could not be expressed" is a
reportable result.

Also evaluated: a handful of hand-written Python rules (the spec's "our own Python detection
rules") kept in the same registry, so both rule languages compete on identical inputs.

### 8.3 Replay (Module 7 protocol)

1. Freeze round-1 ruleset → `rulesets.yaml` entry with `frozen_at` (pre-registration).
2. Capture all live trials.
3. Evaluate round-1 ruleset on captured events → `alerts` for `ruleset-1`.
4. Analyse misses. **Only** variants marked `ofat`/`pairwise` from the *training* split may inform
   rule changes. `holdout` variants stay sealed.
5. Author round-2 ruleset. Changes must be expressed as generalisations (field-set-based, not
   value-based) — record the rationale per rule.
6. Re-evaluate round-2 ruleset on the **same captured events** → paired comparison.
7. Unseal `holdout` variants, run them live once, evaluate round-2 ruleset on them.
8. Benign baseline replayed against both rulesets for false-positive comparison.

**Reconciling with workflow step 12 ("run the same attacks again"):** replay gives a paired
comparison on *identical* inputs, which is what makes the before/after claim valid — two live runs
differ in more than the ruleset. To close the gap, add one live confirmation run per technique
under the round-2 ruleset (8 trials), and run the benign baseline live as well, since false alarms
are only meaningful against real traffic. The diagram's "fix again if needed" loop then costs
seconds per iteration instead of a full attack campaign.

Split rule: for each technique, hold out 1 of the 5 OFAT variants *by seed*, chosen before any
results are seen, in addition to the `holdout` set.

---

## 9. Metrics and statistics

All computed on `v_trial_outcome`, with exclusions stated in the report.

| Metric | Definition | Aggregation |
|---|---|---|
| Attack success rate | `sum(attack_succeeded) / count(*)` over attempted trials | per technique, per variant, overall |
| Detection rate | `sum(detected) / count(*)` where `attack_succeeded = 1` | Wilson 95% CI |
| Evasion rate | `1 − detection rate` | Wilson 95% CI |
| Ingest lag | `received_at − event_time` | median, p95 — **reported separately from rule latency** |
| Rule latency (replay) | `evaluated_at − event_time` in replay | median, KM estimate; censored at observation window |
| False alarm rate | `alerts on benign trials / benign trials` | Wilson 95% CI |
| Alert volume | alerts per benign hour | mean, max |
| Rule improvement | paired ΔDR (joined on `variant_id`) | **McNemar exact test** + CI |

**Why McNemar:** before/after is paired binary data per variant (detected / not). McNemar tests
whether the discordant pairs are symmetric. With ~30–110 pairs it is the right test; a two-sample
proportion test throws away the pairing and understates power.

**Why Kaplan–Meier for latency:** misses are right-censored (the alert never arrives). A mean over
observed alerts only is biased downward. Report median + KM curve, and state the censoring rule.

**Why one primary metric:** declare **evasion rate on holdout variants** as the headline claim.
Everything else is supporting evidence. This prevents post-hoc metric shopping.

### 9.1 What this power actually supports

At n ≈ 40 pairs (8 techniques × 5 OFAT variants) McNemar can detect roughly a 25–30 percentage-point
swing in detection rate with 80% power. It cannot distinguish 70% from 80%. Say so in the report; do
not present 3-point differences as findings. If stronger claims are wanted, increase repetitions on
the OFAT set rather than widening the technique set.

---

## 10. Dashboard and report (Module 8)

Streamlit pages:

1. **Overview** — headline numbers, per-tactic radar, before/after delta.
2. **Technique drill-down** — variant grid (rows = variants, cols = factors), detected/missed cells,
   filterable by tactic.
3. **Evasion heatmap** — factor level × technique, colour = evasion rate. This is the money chart.
4. **Latency** — KM curves for rule-1 vs rule-2, ingest lag distribution.
5. **False alarms** — benign trials, alerts per hour, rule-level FP attribution.
6. **Rule diff** — round-1 vs round-2 rules side by side with rationale.

Report: generated markdown/PDF with the same sections plus method, limitations, and the
pairwise-coverage appendix.

---

## 11. Build order

| Milestone | Contents | Depends on | Done when |
|---|---|---|---|
| **M0 — Fixtures** | SQLite schema, CloudTrail parser, 20 hand-built fixture events per technique, dummy ruleset, first dashboard page | nothing | `pytest` green, dashboard renders fixture results |
| **M1 — Lab** | Terraform: account guardrails, trail, bucket, SQS, roles, tag sweep | infra access | trail delivers to S3, SCP verified by attempting a denied call |
| **M2 — Detect core** | pySigma backend, matcher, replay CLI, ruleset freeze/versioning | M0 | 60%+ of SigmaHQ AWS rules compile; replay produces stable alerts |
| **M3 — Variants** | factors.yaml, generator, coverage report, validity gate, diff logic | M0 | 152 variants generated deterministically, coverage report emitted |
| **M4 — Runner** | preflight, executors, verifiers, collector, sweeper | M1, M3 | 3 end-to-end trials on 1 technique with zero residue |
| **M5 — Round 1** | full live capture, 8 techniques, 3 repetitions on baseline+OFAT | M2, M4 | all trials recorded, ingest lag measured |
| **M6 — Round 2** | miss analysis, ruleset-2, replay comparison, holdout live run, benign baseline | M5 | paired results + McNemar computed |
| **M7 — Report** | dashboard, report generator, coverage appendix | M6 | artefact set complete |

Do not start M5 before M4's zero-residue criterion holds. Cleanup failures are the one thing that
can turn a lab exercise into an incident.

---

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Permission boundary blocks the PrivEsc technique | false "evaded" | deny-list boundary + `SimulatePrincipalPolicy` preflight (§6.1) |
| pySigma backend scope creep | schedule slip | v1 modifier list fixed in §8.2; uncompiled rules reported not chased |
| T1530 unobservable without data events | 1/8 of corpus has no evidence | enable a data-event selector scoped to one bucket; verify in M1, not M5 |
| Cleanup leaves resources | cost + real exposure | tag sweep + post-trial assertion + nightly sweeper |
| Overfitting ruleset-2 to the test set | invalid improvement claim | pre-registration, seeded split, sealed holdout |
| Underpowered statistics | unsupportable claims | 3 reps on OFAT; McNemar; report CIs not point estimates |
| Aggregate detection rate dominated by the 3 Discovery techniques | misleading headline | report per tactic and per technique; Discovery shown separately |
| M1/M2 tool traffic contaminating baselines | false positives attributed to benign | tag all tool traffic by UA/time window; separate windows per module |
| Windows dev environment | shell/tooling friction | Python-only task runner (`python -m identity_shield ...`), no bash scripts |

---

## 13. Open questions

1. **Baseline ruleset source** — the workflow says "our Python rules and Sigma rules". Do the Sigma
   rules start from SigmaHQ `rules/cloud/aws/` (more defensible: "community rules failed on X% of
   variants") or are they authored in-house? This fixes how much pySigma backend coverage is needed
   before round 1 can start.
2. **Repetitions** — 3 on baseline+OFAT (recommended) or 1? Affects runtime and cost.
3. **Data events** — T1530 is confirmed in the set, so S3 data events are **required** for at least
   one lab bucket. Confirm cost tolerance and that a data-event selector can be scoped to that single
   bucket while management events stay on the main trail.
4. **T1078.004 shape** — is "valid account" simulated as console login, API-only, or both? Console
   login gives `ConsoleLogin` + `MFAUsed`, which is a much richer detection signal than API-only.
5. **Team split** — who owns infra vs detection vs variants? The module contracts in §1 assume
   roughly three tracks.
6. **Deliverable emphasis** — tool + report, or tool + report + paper draft? A paper changes what
   M6/M7 must record (per-rule rationale, independent verdict review).

---

## Appendix A — Workflow steps → delivery

| Step (diagram) | Module | Artefact |
|---|---|---|
| 1. Pick 8 cloud attacks | M3 | `conf/techniques.yaml` |
| 2. Normal run | M5 | baseline trial per technique |
| 3. Small changes from YAML | M4 | `variants.jsonl` + coverage report |
| 4. Safety check | M5 preflight | abort-on-violation, `SimulatePrincipalPolicy` |
| 5. Run changes and clean up | M5 | `trial` rows, zero-residue assertion |
| 6. Collect and sort logs | M6 | `event` rows, trial↔event linkage |
| 7. Test the rules | M6 | `alert` rows, latency |
| 8. Alert raised? | M6 | `detected` in `v_trial_outcome` |
| 9. Check the misses | M5 verifier | `attack_succeeded`, `variant_changed` |
| 10. Work out evasion rate | M8 analysis | per rule / per technique / per change type |
| 11. Fix weak rules | M7 | `conf/rules/improved/` |
| 12. Test again | M7 replay | `alerts` for `ruleset-2` on identical events |
| 13. Compare old vs new | M8 | paired Δ, McNemar |
| 14. Final rules | M7 | frozen `ruleset-3` |
| 15. Dashboard | M8 | Streamlit pages |
| 16. Report | M8 | markdown/PDF + coverage appendix |
