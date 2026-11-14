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

CREATE TABLE IF NOT EXISTS event (
  event_id           TEXT PRIMARY KEY,        -- CloudTrail eventID
  trial_id           TEXT REFERENCES trial(trial_id),
  fixture_key        TEXT REFERENCES fixture(fixture_key),
  event_time         TEXT NOT NULL,           -- ISO8601 UTC, 'YYYY-MM-DDTHH:MM:SSZ'
  received_at        TEXT NOT NULL,           -- collector (or receiptTime) timestamp
  event_source       TEXT,
  event_name         TEXT,
  aws_region         TEXT,
  source_ip          TEXT,
  user_agent         TEXT,
  user_identity_type TEXT,
  user_identity_arn  TEXT,
  error_code         TEXT,
  raw                TEXT NOT NULL            -- full JSON, verbatim
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
  source             TEXT                     -- sigmahq | authored | mixed
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
