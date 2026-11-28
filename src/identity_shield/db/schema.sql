-- Identity Shield schema.
-- SQLite is storage only; rule evaluation happens in Python.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Lab runs and test definition
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS lab_run (
  run_id             TEXT PRIMARY KEY,        -- ULID; also the AWS tag value
  started_at         TEXT NOT NULL,
  ended_at           TEXT,
  aws_account_id     TEXT NOT NULL,
  region             TEXT NOT NULL,
  git_sha            TEXT,
  ruleset_version    TEXT NOT NULL,
  collector_lag_ms   INTEGER,
  synthetic          INTEGER NOT NULL DEFAULT 0,  -- 1 = offline rehearsal, never a finding
  notes              TEXT
);

CREATE TABLE IF NOT EXISTS technique (
  technique_id       TEXT PRIMARY KEY,        -- e.g. T1098.001
  name               TEXT NOT NULL,
  tactic             TEXT NOT NULL,
  executor           TEXT NOT NULL,           -- stratus | boto3
  executor_ref       TEXT,                    -- stratus id or python callable path
  event_names        TEXT NOT NULL,           -- JSON array
  requires_data_events INTEGER NOT NULL DEFAULT 0,
  success_check      TEXT NOT NULL,           -- JSON
  required_actions   TEXT NOT NULL            -- JSON array of IAM actions
);

CREATE TABLE IF NOT EXISTS variant (
  variant_id         TEXT PRIMARY KEY,
  technique_id       TEXT NOT NULL REFERENCES technique(technique_id),
  variant_set        TEXT NOT NULL CHECK (variant_set IN
                       ('baseline','ofat','pairwise','holdout','benign','fixture')),
  factor_levels      TEXT NOT NULL,           -- JSON object
  seed               INTEGER NOT NULL,
  spec_sha256        TEXT NOT NULL,
  notes              TEXT
);

CREATE TABLE IF NOT EXISTS trial (
  trial_id           TEXT PRIMARY KEY,
  run_id             TEXT NOT NULL REFERENCES lab_run(run_id),
  variant_id         TEXT NOT NULL REFERENCES variant(variant_id),
  repetition         INTEGER NOT NULL,
  window_start       TEXT NOT NULL,
  window_end         TEXT,
  attack_succeeded   INTEGER,                 -- 0 | 1 | NULL = not verified
  attack_evidence    TEXT,                    -- JSON
  variant_changed    INTEGER,                 -- 0 | 1  (validity gate)
  variant_diff       TEXT,                    -- JSON
  error              TEXT,
  UNIQUE (run_id, variant_id, repetition)
);

-- ---------------------------------------------------------------------------
-- Fixtures: synthetic or captured CloudTrail used by the M0 harness
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fixture (
  fixture_key        TEXT PRIMARY KEY,        -- e.g. T1098.001/catch
  technique_id       TEXT REFERENCES technique(technique_id),
  flavour            TEXT NOT NULL CHECK (flavour IN ('catch','obvious','hard','benign')),
  path               TEXT NOT NULL,
  expected_detected  INTEGER                  -- 0 | 1 | NULL = unasserted
);

-- ---------------------------------------------------------------------------
-- Logs
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS schema_migration (
  version            INTEGER PRIMARY KEY,
  name               TEXT NOT NULL,
  applied_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS technique_cloud_map (
  technique_id       TEXT NOT NULL REFERENCES technique(technique_id),
  cloud_provider     TEXT NOT NULL,
  service            TEXT NOT NULL DEFAULT '',
  operations_json    TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (technique_id, cloud_provider)
);

CREATE TABLE IF NOT EXISTS event (
  event_id           TEXT PRIMARY KEY,        -- CloudTrail eventID / GCP insertId / Azure eventDataId
  trial_id           TEXT REFERENCES trial(trial_id),
  fixture_key        TEXT REFERENCES fixture(fixture_key),
  event_time         TEXT NOT NULL,           -- ISO8601 UTC, 'YYYY-MM-DDTHH:MM:SSZ'
  received_at        TEXT NOT NULL,           -- collector (or receiptTime) timestamp
  cloud_provider     TEXT NOT NULL DEFAULT 'aws',
  account_scope      TEXT NOT NULL DEFAULT '',
  source_type        TEXT NOT NULL DEFAULT 'cloudtrail',
  schema_version     TEXT NOT NULL DEFAULT '1.0',
  event_source       TEXT,
  event_name         TEXT,
  aws_region         TEXT,
  source_ip          TEXT,
  user_agent         TEXT,
  user_identity_type TEXT,
  user_identity_arn  TEXT,
  error_code         TEXT,
  raw                TEXT NOT NULL            -- sanitized full JSON
);

CREATE INDEX IF NOT EXISTS idx_event_trial   ON event(trial_id);
CREATE INDEX IF NOT EXISTS idx_event_fixture ON event(fixture_key);
CREATE INDEX IF NOT EXISTS idx_event_lookup  ON event(event_name, event_time);

-- ---------------------------------------------------------------------------
-- Detection
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ruleset (
  ruleset_version    TEXT PRIMARY KEY,
  created_at         TEXT NOT NULL,
  frozen_at          TEXT,
  description        TEXT,
  source             TEXT,                    -- sigmahq | authored | mixed
  manifest_sha256    TEXT,                    -- SHA-256 cryptographic manifest hash
  git_sha            TEXT                     -- Git commit SHA-1 at freeze time
);

CREATE TABLE IF NOT EXISTS rule (
  rule_id            TEXT PRIMARY KEY,        -- '<ruleset_version>:<native id>'
  ruleset_version    TEXT NOT NULL REFERENCES ruleset(ruleset_version),
  native_id          TEXT NOT NULL,
  title              TEXT,
  level              TEXT,
  technique_id       TEXT,
  loader             TEXT NOT NULL,           -- python | sigma | sigma-fallback
  path               TEXT,
  body               TEXT NOT NULL,           -- YAML/source, for audit
  authored_by        TEXT
);

CREATE TABLE IF NOT EXISTS alert (
  alert_id           TEXT PRIMARY KEY,
  rule_id            TEXT NOT NULL REFERENCES rule(rule_id),
  event_id           TEXT NOT NULL REFERENCES event(event_id),
  trial_id           TEXT,
  fixture_key        TEXT,
  cloud_provider     TEXT NOT NULL DEFAULT 'aws',
  evaluated_at       TEXT NOT NULL,
  latency_ms         INTEGER,                 -- evaluated_at - event_time
  matched_fields     TEXT
);

CREATE INDEX IF NOT EXISTS idx_alert_event ON alert(event_id);
CREATE INDEX IF NOT EXISTS idx_alert_rule  ON alert(rule_id);

-- Compile status of each rule the loader attempted. Not every rule in the
-- corpus becomes an executable rule; the ones that do not are findings.
CREATE TABLE IF NOT EXISTS rule_compile (
  rule_id            TEXT PRIMARY KEY,
  ruleset_version    TEXT NOT NULL,
  path               TEXT,
  title              TEXT,
  status             TEXT NOT NULL CHECK (status IN
                       ('pysigma','fallback','unsupported','parse_error')),
  reason             TEXT,
  checked_at         TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Derived view: one row per fixture, with the outcome variables
-- ---------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_fixture_outcome AS
SELECT f.fixture_key,
       f.technique_id,
       f.flavour,
       f.expected_detected,
       COUNT(DISTINCT e.event_id) AS events,
       CASE WHEN EXISTS (
         SELECT 1 FROM alert a
         JOIN event e2 ON e2.event_id = a.event_id
         WHERE e2.fixture_key = f.fixture_key
       ) THEN 1 ELSE 0 END AS detected,
       (SELECT GROUP_CONCAT(DISTINCT r.native_id) FROM alert a
          JOIN event e3 ON e3.event_id = a.event_id
          JOIN rule  r  ON r.rule_id  = a.rule_id
         WHERE e3.fixture_key = f.fixture_key) AS fired_rules
FROM fixture f
LEFT JOIN event e ON e.fixture_key = f.fixture_key
GROUP BY f.fixture_key;

-- ---------------------------------------------------------------------------
-- Trial outcome view. Detection is intentionally not baked in here: alerts
-- belong to a rule set, so analysis queries join the selected ruleset. The
-- view surfaces the variant metadata once so the dashboard does not repeat
-- the join in every panel.
-- ---------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_trial_outcome AS
SELECT t.trial_id,
       t.run_id,
       t.variant_id,
       t.repetition,
       t.window_start,
       t.window_end,
       t.attack_succeeded,
       t.attack_evidence,
       t.variant_changed,
       t.variant_diff,
       t.error,
       v.technique_id,
       v.variant_set,
       v.factor_levels,
       v.spec_sha256,
       te.tactic,
       te.name AS technique_name,
       lr.synthetic,
       lr.ruleset_version AS primary_ruleset
FROM trial t
JOIN variant v ON v.variant_id = t.variant_id
JOIN lab_run lr ON lr.run_id = t.run_id
LEFT JOIN technique te ON te.technique_id = v.technique_id;

-- ---------------------------------------------------------------------------
-- Indexes used by replay, collection and every dashboard query.
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_event_trial_time ON event(trial_id, event_time);
CREATE INDEX IF NOT EXISTS idx_event_name_time  ON event(event_source, event_name, event_time);
CREATE INDEX IF NOT EXISTS idx_alert_trial      ON alert(trial_id);
CREATE INDEX IF NOT EXISTS idx_alert_fixture    ON alert(fixture_key);
CREATE INDEX IF NOT EXISTS idx_rule_ruleset     ON rule(ruleset_version);
CREATE INDEX IF NOT EXISTS idx_trial_variant    ON trial(variant_id);
CREATE INDEX IF NOT EXISTS idx_trial_run        ON trial(run_id);
CREATE INDEX IF NOT EXISTS idx_variant_technique ON variant(technique_id, variant_set);

-- ---------------------------------------------------------------------------
-- Live Security Proxy & Adaptive Dynamic Detection Engine
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS proxy_event (
  proxy_event_id            TEXT PRIMARY KEY,
  timestamp                 TEXT NOT NULL,
  cloud_provider            TEXT NOT NULL DEFAULT 'unknown',
  account_scope             TEXT NOT NULL DEFAULT '',
  traffic_type              TEXT NOT NULL DEFAULT 'http_app',
  traffic_kind              TEXT NOT NULL,         -- legacy compat: aws_api | gcp_api | azure_api | http_app | connect_tunnel
  classification_confidence TEXT NOT NULL DEFAULT 'high',
  classification_reason     TEXT NOT NULL DEFAULT '',
  mode                      TEXT NOT NULL,         -- observe | block
  action_taken              TEXT NOT NULL,         -- allowed | observed | alerted | blocked
  policy_decision           TEXT NOT NULL DEFAULT 'allowed',
  policy_reason             TEXT NOT NULL DEFAULT '',
  client_ip                 TEXT,
  principal                 TEXT,
  method                    TEXT,
  target_host               TEXT,
  path                      TEXT,
  service                   TEXT,
  operation                 TEXT,
  user_agent                TEXT,
  aws_region                TEXT,
  params_json               TEXT,
  status_code               INTEGER,
  latency_ms                REAL,
  risk_score                REAL NOT NULL DEFAULT 0.0,
  matched_static            TEXT,                  -- JSON array of matched rules
  matched_dynamic           TEXT,                  -- JSON array of dynamic rule hits
  event_json                TEXT NOT NULL          -- Sanitized normalized JSON event
);

CREATE TABLE IF NOT EXISTS dynamic_rule (
  rule_id         TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  kind            TEXT NOT NULL,         -- velocity | sequence | drift | app_anomaly
  enabled         INTEGER NOT NULL DEFAULT 1,
  severity        TEXT NOT NULL DEFAULT 'medium',
  window_seconds  INTEGER NOT NULL DEFAULT 60,
  threshold       INTEGER NOT NULL DEFAULT 5,
  config_json     TEXT NOT NULL,
  description     TEXT,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dynamic_alert (
  alert_id        TEXT PRIMARY KEY,
  rule_id         TEXT NOT NULL,
  rule_name       TEXT NOT NULL,
  source          TEXT NOT NULL,         -- proxy | batch
  ref_id          TEXT NOT NULL,         -- proxy_event_id | event_id
  cloud_provider  TEXT NOT NULL DEFAULT 'aws',
  account_scope   TEXT NOT NULL DEFAULT '',
  ruleset_version TEXT,
  timestamp       TEXT NOT NULL,
  severity        TEXT NOT NULL,
  principal       TEXT,
  summary         TEXT NOT NULL,
  evidence_json   TEXT,
  action_taken    TEXT NOT NULL DEFAULT 'alerted'
);

CREATE TABLE IF NOT EXISTS principal_profile (
  profile_key         TEXT PRIMARY KEY,
  cloud_provider      TEXT NOT NULL DEFAULT 'aws',
  account_scope       TEXT NOT NULL DEFAULT '',
  principal           TEXT NOT NULL,
  known_user_agents   TEXT NOT NULL DEFAULT '[]',
  known_regions       TEXT NOT NULL DEFAULT '[]',
  known_services      TEXT NOT NULL DEFAULT '[]',
  known_operations    TEXT NOT NULL DEFAULT '[]',
  known_hours         TEXT NOT NULL DEFAULT '[]',
  request_count       INTEGER NOT NULL DEFAULT 0,
  cold_start_complete INTEGER NOT NULL DEFAULT 0,
  last_seen           TEXT NOT NULL,
  UNIQUE (cloud_provider, account_scope, principal)
);

CREATE INDEX IF NOT EXISTS idx_event_cloud_time        ON event(cloud_provider, event_time);
CREATE INDEX IF NOT EXISTS idx_proxy_event_time        ON proxy_event(timestamp);
CREATE INDEX IF NOT EXISTS idx_proxy_event_cloud       ON proxy_event(cloud_provider, timestamp);
CREATE INDEX IF NOT EXISTS idx_proxy_event_principal   ON proxy_event(principal, timestamp);
CREATE INDEX IF NOT EXISTS idx_proxy_event_action      ON proxy_event(action_taken);
CREATE INDEX IF NOT EXISTS idx_dynamic_alert_time      ON dynamic_alert(timestamp);
CREATE INDEX IF NOT EXISTS idx_dynamic_alert_cloud     ON dynamic_alert(cloud_provider, timestamp);
CREATE INDEX IF NOT EXISTS idx_dynamic_alert_source    ON dynamic_alert(source, timestamp);
CREATE INDEX IF NOT EXISTS idx_principal_profile_lookup ON principal_profile(cloud_provider, account_scope, principal);
