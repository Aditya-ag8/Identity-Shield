from __future__ import annotations

import gzip
import json

import pytest

from identity_shield.contracts import Variant, spec_hash
from identity_shield.db.connection import connect
from identity_shield.db.init import init_db
from identity_shield.detect import loader
from identity_shield.lab.aws import GuardedSession, LabSession, ReadOnlyViolation
from identity_shield.runner import collector, diff, sweeper
from identity_shield.runner.orchestrator import _redact
from identity_shield.variants.benign import generate_benign, load_benign
from identity_shield.variants.loader import load_catalogue


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def delete_access_key(self, **kwargs):
        self.calls.append(("delete_access_key", kwargs))
        return {}

    def detach_role_policy(self, **kwargs):
        self.calls.append(("detach_role_policy", kwargs))
        return {}


class FakeSession:
    def __init__(self) -> None:
        self._client = FakeClient()

    def client(self, service, **kwargs):
        return self._client

    def get_credentials(self):
        return object()


def test_s3_notification_parsing_handles_direct_and_sns_wrapped_messages() -> None:
    direct = {
        "Records": [
            {"s3": {"bucket": {"name": "trail-bucket"}, "object": {"key": "AWSLogs/1.json.gz"}}}
        ]
    }
    assert collector.parse_s3_notifications(json.dumps(direct)) == [
        ("trail-bucket", "AWSLogs/1.json.gz")
    ]
    wrapped = json.dumps({"Message": json.dumps(direct)})
    assert collector.parse_s3_notifications(wrapped) == [
        ("trail-bucket", "AWSLogs/1.json.gz")
    ]
    assert collector.parse_s3_notifications("not json") == []


def test_diff_reports_changed_fields_and_event_names() -> None:
    baseline = [{"eventName": "GetObject", "userAgent": "Boto3"}]
    variant = [{"eventName": "ListBucket", "userAgent": "Boto3"}]
    result = diff.compare(baseline, variant, ["eventName", "userAgent"])
    assert result["variant_changed"] is True
    assert result["changed_fields"] == ["eventName"]
    assert result["baseline_event_names"] == ["GetObject"]
    assert result["variant_event_names"] == ["ListBucket"]


def test_cleanup_actions_are_executed_and_unknown_actions_are_reported() -> None:
    session = FakeSession()
    report = sweeper.sweep(
        session,
        [
            {"kind": "iam_access_key", "user": "is-test-user", "key_id": "AKIA1"},
            {"kind": "mystery"},
        ],
        region="eu-west-1",
    )
    assert report.cleaned == ["iam_access_key"]
    assert report.failed and report.failed[0]["kind"] == "mystery"
    assert report.ok is False
    assert session._client.calls[0][0] == "delete_access_key"


def test_read_only_guard_blocks_mutation_but_lab_session_allows_it() -> None:
    class Inner:
        def get_credentials(self):
            return object()

        def client(self, service, **kwargs):
            return FakeClient()

    guarded = GuardedSession(session=Inner(), region_name="eu-west-1")
    with pytest.raises(ReadOnlyViolation):
        guarded.client("iam").create_access_key(UserName="x")

    writable = LabSession(session=Inner(), region_name="eu-west-1")
    assert writable.client("iam").delete_access_key(UserName="x") == {}
    assert writable.has_credentials()


def test_evidence_redaction_removes_secret_material() -> None:
    evidence = {
        "access_key_id": "AKIAEXAMPLE",
        "secret_access_key": "secret",
        "verification": {"evidence": {"stolen_secret_access_key": "secret"}},
        "cleanup": [{"kind": "iam_access_key", "key_id": "AKIAEXAMPLE"}],
    }
    redacted = _redact(evidence)
    assert redacted["access_key_id"] == "AKIAEXAMPLE"
    assert redacted["secret_access_key"] == "[redacted]"
    assert redacted["verification"]["evidence"]["stolen_secret_access_key"] == "[redacted]"
    assert redacted["cleanup"][0]["key_id"] == "AKIAEXAMPLE"


def test_bulk_insert_links_events_to_trials(db_path) -> None:
    init_db(db_path, drop=True)
    conn = connect(db_path)
    try:
        loader.load_techniques(conn)
        loader.load_fixtures(conn)
        events = [
            {
                "eventID": "event-1",
                "eventTime": "2026-11-19T10:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "awsRegion": "eu-west-1",
                "sourceIPAddress": "203.0.113.10",
                "userAgent": "Boto3",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/x"},
                "requestParameters": {"bucketName": "is-lab-crown-jewels", "key": "a"},
                "responseElements": None,
            }
        ]
        # event references a trial; the schema requires the parent row.
        conn.execute(
            "INSERT INTO lab_run (run_id, started_at, aws_account_id, region, ruleset_version)"
            " VALUES ('r', '2026-11-19T09:00:00Z', '123456789012', 'eu-west-1', 'baseline-v1')"
        )
        catalogue = load_catalogue()
        technique = catalogue.technique("T1530")
        conn.execute(
            "INSERT INTO variant (variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256)"
            " VALUES ('v', 'T1530', 'baseline', ?, 1, ?)",
            (json.dumps(catalogue.baseline_for(technique)), spec_hash("T1530", catalogue.baseline_for(technique))),
        )
        conn.execute(
            "INSERT INTO trial (trial_id, run_id, variant_id, repetition, window_start)"
            " VALUES ('t', 'r', 'v', 1, '2026-11-19T09:00:00Z')"
        )
        assert collector.insert_events(conn, events, trial_id="t") == 1
        row = conn.execute(
            "SELECT trial_id, event_name, raw FROM event WHERE event_id = 'event-1'"
        ).fetchone()
        assert row["trial_id"] == "t"
        assert row["event_name"] == "GetObject"
        assert json.loads(row["raw"])["eventID"] == "event-1"
    finally:
        conn.close()


def test_cloudtrail_collector_reads_gzipped_object_and_marks_expected_event(db_path) -> None:
    class S3:
        def get_object(self, Bucket, Key):
            payload = json.dumps(
                {
                    "Records": [
                        {
                            "eventID": "event-1",
                            "eventTime": "2026-11-19T10:00:00Z",
                            "eventSource": "s3.amazonaws.com",
                            "eventName": "GetObject",
                            "awsRegion": "eu-west-1",
                            "sourceIPAddress": "203.0.113.10",
                            "userAgent": "Boto3",
                            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/x"},
                            "requestParameters": {"bucketName": "b", "key": "k"},
                            "responseElements": None,
                        }
                    ]
                }
            ).encode("utf-8")
            return {"Body": Body(gzip.compress(payload))}

    class Body:
        def __init__(self, data):
            self.data = data

        def read(self):
            return self.data

    class SQS:
        def __init__(self):
            self.sent = False

        def receive_message(self, **kwargs):
            if self.sent:
                return {"Messages": []}
            self.sent = True
            return {
                "Messages": [
                    {
                        "Body": json.dumps(
                            {
                                "Records": [
                                    {
                                        "s3": {
                                            "bucket": {"name": "trail"},
                                            "object": {"key": "k.json.gz"},
                                        }
                                    }
                                ]
                            }
                        ),
                        "ReceiptHandle": "rh",
                    }
                ]
            }

        def delete_message(self, **kwargs):
            return {}

    init_db(db_path, drop=True)
    conn = connect(db_path)
    try:
        loader.load_techniques(conn)
        loader.load_fixtures(conn)
        conn.execute(
            "INSERT INTO lab_run (run_id, started_at, aws_account_id, region, ruleset_version)"
            " VALUES ('r', '2026-11-19T09:00:00Z', '123456789012', 'eu-west-1', 'baseline-v1')"
        )
        catalogue = load_catalogue()
        technique = catalogue.technique("T1530")
        conn.execute(
            "INSERT INTO variant (variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256)"
            " VALUES ('v', 'T1530', 'baseline', ?, 1, ?)",
            (json.dumps(catalogue.baseline_for(technique)), spec_hash("T1530", catalogue.baseline_for(technique))),
        )
        conn.execute(
            "INSERT INTO trial (trial_id, run_id, variant_id, repetition, window_start)"
            " VALUES ('t', 'r', 'v', 1, '2026-11-19T09:00:00Z')"
        )
        trail = collector.CloudTrailCollector(SQS(), S3(), "queue")
        result = trail.collect(
            conn,
            trial_id="t",
            start="2026-11-19T09:00:00Z",
            end="2026-11-19T11:00:00Z",
            expected_event_names=["GetObject"],
            timeout=0,
            sleep=lambda _: None,
        )
        assert result.events == 1
        assert result.missing == ()
        assert result.timed_out is False
    finally:
        conn.close()


def test_benign_generation_is_stable_and_separate_from_attack_coverage() -> None:
    catalogue = load_catalogue()
    first = generate_benign(catalogue)
    second = generate_benign(catalogue)
    assert len(first) == 16
    assert [row.variant_id for row in first] == [row.variant_id for row in second]
    assert all(row.variant_set == "benign" for row in first)
    assert len({row.spec_sha256 for row in first}) == len(first)
    activities = {row.notes for row in first}
    assert "BENIGN-DATA-READ" in activities
    assert len(load_benign()) == 8
