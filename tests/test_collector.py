"""Dedicated tests for CloudTrail collection correctness.

Validates:
1. Late-arriving events
2. Multiple trial windows within one S3 object
3. Duplicate SQS notifications
4. Idempotent S3 object processing
5. SQS acknowledgement only after durable database persistence
6. Unassigned event retention
7. Retrospective attribution
8. Collector failure and retry behavior
"""

from __future__ import annotations

import gzip
import json
from typing import Any

import pytest

from identity_shield.contracts import spec_hash
from identity_shield.runner import collector
from identity_shield.variants.loader import load_catalogue


class MockBody:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self) -> bytes:
        return self.data


class MockS3:
    def __init__(self, objects: dict[tuple[str, str], bytes] | None = None) -> None:
        self.objects = objects or {}
        self.fail_keys: set[tuple[str, str]] = set()

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:
        if (Bucket, Key) in self.fail_keys:
            raise RuntimeError(f"Simulated S3 read failure for {Bucket}/{Key}")
        if (Bucket, Key) not in self.objects:
            raise KeyError(f"NoSuchKey: {Bucket}/{Key}")
        return {"Body": MockBody(self.objects[(Bucket, Key)])}


class MockSQS:
    def __init__(self, messages: list[dict[str, Any]] | None = None) -> None:
        self.messages = list(messages or [])
        self.deleted_handles: list[str] = []
        self.fail_receive = False

    def receive_message(self, **_kwargs) -> dict[str, Any]:
        if self.fail_receive:
            raise RuntimeError("Simulated SQS receive error")
        if not self.messages:
            return {"Messages": []}
        # Pop up to MaxNumberOfMessages
        batch = self.messages[:10]
        self.messages = self.messages[10:]
        return {"Messages": batch}

    def delete_message(self, QueueUrl: str, ReceiptHandle: str) -> dict[str, Any]:
        self.deleted_handles.append(ReceiptHandle)
        return {}


def _make_ct_event(
    event_id: str,
    event_time: str,
    event_name: str = "GetObject",
    source: str = "s3.amazonaws.com",
) -> dict[str, Any]:
    return {
        "eventID": event_id,
        "eventTime": event_time,
        "eventSource": source,
        "eventName": event_name,
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "Boto3/1.26.0",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": {"bucketName": "is-lab-crown-jewels", "key": "finance/q4.csv"},
        "responseElements": None,
    }


def _compress_events(events: list[dict[str, Any]]) -> bytes:
    payload = json.dumps({"Records": events}).encode("utf-8")
    return gzip.compress(payload)


def _setup_run_and_trials(conn, trial_ids: list[str]) -> None:
    conn.execute(
        "INSERT INTO lab_run (run_id, started_at, aws_account_id, region, ruleset_version)"
        " VALUES ('r1', '2026-11-19T09:00:00Z', '123456789012', 'eu-west-1', 'baseline-v1')"
    )
    catalogue = load_catalogue()
    technique = catalogue.technique("T1530")
    conn.execute(
        "INSERT INTO variant (variant_id, technique_id, variant_set, factor_levels, seed, spec_sha256)"
        " VALUES ('v1', 'T1530', 'baseline', ?, 1, ?)",
        (json.dumps(catalogue.baseline_for(technique)), spec_hash("T1530", catalogue.baseline_for(technique))),
    )
    for i, tid in enumerate(trial_ids, start=1):
        conn.execute(
            "INSERT INTO trial (trial_id, run_id, variant_id, repetition, window_start)"
            " VALUES (?, 'r1', 'v1', ?, '2026-11-19T09:00:00Z')",
            (tid, i),
        )
    conn.commit()


def test_collector_unassigned_event_retention(conn) -> None:
    """Events outside the trial window are kept with trial_id=None, not dropped."""
    _setup_run_and_trials(conn, ["t-retention"])
    ev1 = _make_ct_event("ev-ret-inside", "2026-11-19T10:02:00Z")
    ev2 = _make_ct_event("ev-ret-before", "2026-11-19T09:50:00Z")
    ev3 = _make_ct_event("ev-ret-after", "2026-11-19T10:20:00Z")

    inserted = collector.insert_events(
        conn,
        [ev1, ev2, ev3],
        trial_id="t-retention",
        only_between=("2026-11-19T10:00:00Z", "2026-11-19T10:05:00Z"),
    )
    assert inserted == 1

    rows = conn.execute("SELECT event_id, trial_id FROM event WHERE event_id LIKE 'ev-ret-%' ORDER BY event_id").fetchall()
    assert len(rows) == 3
    event_map = {r["event_id"]: r["trial_id"] for r in rows}
    assert event_map["ev-ret-inside"] == "t-retention"
    assert event_map["ev-ret-before"] is None
    assert event_map["ev-ret-after"] is None


def test_collector_retrospective_attribution(conn) -> None:
    """Unassigned events matching a subsequent trial window are claimed upon collect()."""
    _setup_run_and_trials(conn, ["t-first", "t-second"])

    # Batch inserted during t-first includes an event that belongs to t-second's future window
    ev1 = _make_ct_event("ev-first", "2026-11-19T10:02:00Z")
    ev2 = _make_ct_event("ev-second", "2026-11-19T10:12:00Z")

    collector.insert_events(
        conn,
        [ev1, ev2],
        trial_id="t-first",
        only_between=("2026-11-19T10:00:00Z", "2026-11-19T10:05:00Z"),
    )

    # ev-second is stored with trial_id=None
    row = conn.execute("SELECT trial_id FROM event WHERE event_id = 'ev-second'").fetchone()
    assert row["trial_id"] is None

    # Now t-second runs collect() with no new SQS messages
    sqs = MockSQS([])
    s3 = MockS3({})
    c = collector.CloudTrailCollector(sqs, s3, "https://sqs.queue")
    result = c.collect(
        conn,
        trial_id="t-second",
        start="2026-11-19T10:10:00Z",
        end="2026-11-19T10:15:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )

    assert result.events == 1
    assert result.expected_seen == ("GetObject",)
    assert result.missing == ()

    row = conn.execute("SELECT trial_id FROM event WHERE event_id = 'ev-second'").fetchone()
    assert row["trial_id"] == "t-second"


def test_collector_multiple_trial_windows_within_one_s3_object(conn) -> None:
    """One S3 object containing events for two trials correctly assigns and preserves both."""
    _setup_run_and_trials(conn, ["t-win1", "t-win2"])

    ev_a = _make_ct_event("ev-a", "2026-11-19T10:01:00Z", "GetObject")
    ev_b = _make_ct_event("ev-b", "2026-11-19T10:11:00Z", "GetObject")

    s3_data = _compress_events([ev_a, ev_b])
    s3 = MockS3({("trail-bucket", "logs/chunk.json.gz"): s3_data})

    sqs_body = json.dumps(
        {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "trail-bucket"},
                        "object": {"key": "logs/chunk.json.gz"},
                    }
                }
            ]
        }
    )
    sqs = MockSQS([{"Body": sqs_body, "ReceiptHandle": "handle-1"}])

    c = collector.CloudTrailCollector(sqs, s3, "https://sqs.queue")

    # Trial 1 collects
    res1 = c.collect(
        conn,
        trial_id="t-win1",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )
    assert res1.events == 1
    assert "handle-1" in sqs.deleted_handles

    # Check database state: ev-a assigned to t-win1, ev-b unassigned
    assert conn.execute("SELECT trial_id FROM event WHERE event_id = 'ev-a'").fetchone()["trial_id"] == "t-win1"
    assert conn.execute("SELECT trial_id FROM event WHERE event_id = 'ev-b'").fetchone()["trial_id"] is None

    # Trial 2 collects - queue is empty, event is already in DB
    res2 = c.collect(
        conn,
        trial_id="t-win2",
        start="2026-11-19T10:10:00Z",
        end="2026-11-19T10:15:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )
    assert res2.events == 1
    assert conn.execute("SELECT trial_id FROM event WHERE event_id = 'ev-b'").fetchone()["trial_id"] == "t-win2"


def test_collector_duplicate_sqs_notifications(conn) -> None:
    """Duplicate SQS notifications do not cause primary key conflicts or duplicate counts."""
    _setup_run_and_trials(conn, ["t-dup"])

    ev = _make_ct_event("ev-dup-1", "2026-11-19T10:02:00Z")
    s3_data = _compress_events([ev])
    s3 = MockS3({("trail-bucket", "logs/dup.json.gz"): s3_data})

    sqs_body = json.dumps(
        {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "trail-bucket"},
                        "object": {"key": "logs/dup.json.gz"},
                    }
                }
            ]
        }
    )
    # Deliver the exact same message twice
    sqs = MockSQS(
        [
            {"Body": sqs_body, "ReceiptHandle": "h-1"},
            {"Body": sqs_body, "ReceiptHandle": "h-2"},
        ]
    )

    c = collector.CloudTrailCollector(sqs, s3, "https://sqs.queue")
    result = c.collect(
        conn,
        trial_id="t-dup",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )

    assert result.missing == ()
    total_events = conn.execute("SELECT COUNT(*) FROM event WHERE trial_id = 't-dup'").fetchone()[0]
    assert total_events == 1
    assert "h-1" in sqs.deleted_handles
    assert "h-2" in sqs.deleted_handles


def test_collector_idempotent_s3_object_processing(conn) -> None:
    """Re-processing identical events produces exact same persistent state."""
    _setup_run_and_trials(conn, ["t-idem"])
    events = [
        _make_ct_event(f"ev-idem-{i}", f"2026-11-19T10:0{i}:00Z")
        for i in range(1, 4)
    ]

    count1 = collector.insert_events(
        conn, events, trial_id="t-idem", only_between=("2026-11-19T10:00:00Z", "2026-11-19T10:05:00Z")
    )
    assert count1 == 3

    # Re-insert the same events
    count2 = collector.insert_events(
        conn, events, trial_id="t-idem", only_between=("2026-11-19T10:00:00Z", "2026-11-19T10:05:00Z")
    )
    assert count2 == 3

    total = conn.execute("SELECT COUNT(*) FROM event WHERE trial_id = 't-idem'").fetchone()[0]
    assert total == 3


def test_collector_sqs_acknowledgement_only_after_durable_persistence(conn) -> None:
    """SQS message must NOT be deleted if reading object or persistence fails."""
    _setup_run_and_trials(conn, ["t-ack"])

    ev = _make_ct_event("ev-ack-1", "2026-11-19T10:02:00Z")
    s3_data = _compress_events([ev])
    s3 = MockS3({("trail-bucket", "logs/fail.json.gz"): s3_data})
    # Simulate S3 download failure
    s3.fail_keys.add(("trail-bucket", "logs/fail.json.gz"))

    sqs_body = json.dumps(
        {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "trail-bucket"},
                        "object": {"key": "logs/fail.json.gz"},
                    }
                }
            ]
        }
    )
    sqs = MockSQS([{"Body": sqs_body, "ReceiptHandle": "h-must-not-delete"}])

    c = collector.CloudTrailCollector(sqs, s3, "https://sqs.queue")
    result = c.collect(
        conn,
        trial_id="t-ack",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )

    # Message must NOT be acknowledged
    assert "h-must-not-delete" not in sqs.deleted_handles
    assert result.error is not None
    assert "Simulated S3 read failure" in result.error

    # Now recover S3 and retry: message should be successfully processed and deleted
    s3.fail_keys.clear()
    sqs.messages = [{"Body": sqs_body, "ReceiptHandle": "h-retry"}]

    retry_result = c.collect(
        conn,
        trial_id="t-ack",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )
    assert retry_result.error is None
    assert "h-retry" in sqs.deleted_handles
    assert retry_result.events == 1


def test_collector_late_arriving_events(conn) -> None:
    """Late arriving events are inserted safely and can be attributed to existing trials."""
    _setup_run_and_trials(conn, ["t-late"])

    # Initial collection runs and times out because event hasn't arrived
    sqs = MockSQS([])
    s3 = MockS3({})
    c = collector.CloudTrailCollector(sqs, s3, "https://sqs.queue")
    res1 = c.collect(
        conn,
        trial_id="t-late",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )
    assert res1.missing == ("GetObject",)

    # Event arrives late in SQS
    ev = _make_ct_event("ev-late", "2026-11-19T10:03:00Z")
    s3_data = _compress_events([ev])
    s3.objects[("trail-bucket", "logs/late.json.gz")] = s3_data
    sqs.messages.append(
        {
            "Body": json.dumps(
                {
                    "Records": [
                        {
                            "s3": {
                                "bucket": {"name": "trail-bucket"},
                                "object": {"key": "logs/late.json.gz"},
                            }
                        }
                    ]
                }
            ),
            "ReceiptHandle": "h-late",
        }
    )

    # Re-collect or second collection sweep
    res2 = c.collect(
        conn,
        trial_id="t-late",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )
    assert res2.events == 1
    assert res2.missing == ()
    assert "h-late" in sqs.deleted_handles


def test_collector_failure_and_retry_behavior(conn) -> None:
    """SQS receive failure returns error result, retry succeeds cleanly."""
    _setup_run_and_trials(conn, ["t-err"])
    sqs = MockSQS([])
    sqs.fail_receive = True
    s3 = MockS3({})

    c = collector.CloudTrailCollector(sqs, s3, "https://sqs.queue")
    res = c.collect(
        conn,
        trial_id="t-err",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )
    assert res.timed_out is True
    assert res.error is not None
    assert "Simulated SQS receive error" in res.error

    # Retry with error resolved
    sqs.fail_receive = False
    ev = _make_ct_event("ev-recovered", "2026-11-19T10:02:00Z")
    s3.objects[("trail", "rec.json.gz")] = _compress_events([ev])
    sqs.messages.append(
        {
            "Body": json.dumps(
                {
                    "Records": [
                        {"s3": {"bucket": {"name": "trail"}, "object": {"key": "rec.json.gz"}}}
                    ]
                }
            ),
            "ReceiptHandle": "h-rec",
        }
    )
    res_retry = c.collect(
        conn,
        trial_id="t-err",
        start="2026-11-19T10:00:00Z",
        end="2026-11-19T10:05:00Z",
        expected_event_names=["GetObject"],
        timeout=0,
        sleep=lambda _: None,
    )
    assert res_retry.events == 1
    assert res_retry.error is None
