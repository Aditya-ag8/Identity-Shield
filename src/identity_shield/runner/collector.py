"""CloudTrail collection.

CloudTrail writes gzip JSON objects to S3 and S3 notifies SQS. The collector's
only job is to move full objects into the event table and attach them to the
trial whose window they fall inside. It deliberately does not evaluate rules;
replay is a separate, repeatable step.
"""

from __future__ import annotations

import gzip
import io
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from identity_shield.detect.parser import extract_events, normalize

ISO = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class CollectionResult:
    events: int
    expected_seen: tuple[str, ...]
    missing: tuple[str, ...]
    timed_out: bool
    messages: int = 0
    error: str | None = None


def _parse_iso(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def parse_s3_notifications(body: str | bytes) -> list[tuple[str, str]]:
    """Return ``(bucket, key)`` pairs from an SQS message body.

    S3 can deliver either the event directly or wrapped in SNS. Both shapes are
    just JSON objects with a ``Records`` list, so we walk it defensively.
    """
    try:
        document = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return []
    if isinstance(document, str):
        return parse_s3_notifications(document)
    if isinstance(document, Mapping) and isinstance(document.get("Message"), str):
        return parse_s3_notifications(document["Message"])

    found: list[tuple[str, str]] = []
    for record in document.get("Records") or [] if isinstance(document, Mapping) else []:
        s3 = record.get("s3") if isinstance(record, Mapping) else None
        if not isinstance(s3, Mapping):
            continue
        bucket = (s3.get("bucket") or {}).get("name")
        key = (s3.get("object") or {}).get("key")
        if bucket and key:
            found.append((str(bucket), str(key)))
    return found


def insert_events(
    conn,
    events: Iterable[Mapping[str, Any]],
    *,
    trial_id: str | None,
    fixture_key: str | None = None,
    received_at: str | None = None,
    only_between: tuple[str, str] | None = None,
) -> int:
    """Normalise and bulk-insert events.

    Events falling outside only_between are stored with trial_id=None so they
    are never lost when an SQS notification is acknowledged, preserving them
    for subsequent trials or retrospective attribution. Returns the number
    attributed to trial_id.
    """
    received = received_at or datetime.now(timezone.utc).strftime(ISO)
    rows: list[tuple[Any, ...]] = []
    attributed = 0
    for event in events:
        explicit_cp = str(event.get("cloudProvider") or "").strip().lower()
        if explicit_cp in {"gcp", "azure"}:
            from identity_shield.clouds import detect_and_normalize_audit_payload

            canon_list = detect_and_normalize_audit_payload(event, cloud_provider=explicit_cp)
            if canon_list:
                cev = canon_list[0]
                sigma_doc = cev.to_sigma_event()
                ev_time = cev.event_time
                event_trial = trial_id
                if only_between and not (only_between[0] <= ev_time <= only_between[1]):
                    event_trial = None
                if event_trial == trial_id and trial_id is not None:
                    attributed += 1
                elif trial_id is None:
                    attributed += 1
                rows.append(
                    (
                        cev.event_id,
                        event_trial,
                        fixture_key,
                        cev.cloud_provider,
                        cev.account_scope,
                        cev.source_type,
                        cev.schema_version,
                        ev_time,
                        received,
                        sigma_doc.get("eventSource"),
                        cev.operation,
                        cev.region,
                        cev.source_ip,
                        cev.user_agent,
                        cev.principal_type,
                        cev.principal,
                        str(cev.request_metadata.get("error_code") or "") or None,
                        json.dumps(sigma_doc, ensure_ascii=False, sort_keys=True),
                    )
                )
                continue

        row = normalize(event)
        event_trial = trial_id
        if only_between and not (only_between[0] <= row.event_time <= only_between[1]):
            event_trial = None
        if event_trial == trial_id and trial_id is not None:
            attributed += 1
        elif trial_id is None:
            attributed += 1
        rows.append(
            (
                row.event_id,
                event_trial,
                fixture_key,
                "aws",
                str(event.get("recipientAccountId") or ""),
                "aws_cloudtrail",
                1,
                row.event_time,
                received,
                row.event_source,
                row.event_name,
                row.aws_region,
                row.source_ip,
                row.user_agent,
                row.user_identity_type,
                row.user_identity_arn,
                row.error_code,
                row.raw,
            )
        )
    if not rows:
        return 0
    conn.executemany(
        """
        INSERT INTO event (event_id, trial_id, fixture_key, cloud_provider, account_scope,
                           source_type, schema_version, event_time, received_at,
                           event_source, event_name, aws_region, source_ip,
                           user_agent, user_identity_type, user_identity_arn,
                           error_code, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(event_id) DO UPDATE SET
            trial_id=COALESCE(event.trial_id, excluded.trial_id),
            cloud_provider=excluded.cloud_provider,
            account_scope=excluded.account_scope,
            source_type=excluded.source_type,
            received_at=MIN(event.received_at, excluded.received_at)
        """,
        rows,
    )
    conn.commit()
    return attributed


class CloudTrailCollector:
    def __init__(self, sqs, s3, queue_url: str) -> None:
        self.sqs = sqs
        self.s3 = s3
        self.queue_url = queue_url

    def _read_object(self, bucket: str, key: str) -> list[dict[str, Any]]:
        response = self.s3.get_object(Bucket=bucket, Key=key)
        payload = response["Body"].read()
        if payload[:2] == b"\x1f\x8b":
            payload = gzip.decompress(payload)
        return extract_events(json.loads(payload.decode("utf-8")))

    def collect(
        self,
        conn,
        *,
        trial_id: str,
        start: str,
        end: str,
        expected_event_names: Iterable[str] = (),
        timeout: int = 120,
        poll_seconds: int = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> CollectionResult:
        expected = tuple(dict.fromkeys(str(name) for name in expected_event_names))
        seen: set[str] = set()
        inserted = 0
        messages = 0
        deadline = time.monotonic() + timeout

        # Claim any matching unassigned events already stored from earlier batches
        conn.execute(
            """
            UPDATE event SET trial_id = ?
            WHERE trial_id IS NULL AND event_time BETWEEN ? AND ?
            """,
            (trial_id, start, end),
        )
        conn.commit()
        for r in conn.execute("SELECT event_name FROM event WHERE trial_id = ?", (trial_id,)):
            name = str(r["event_name"] or "")
            if name in expected:
                seen.add(name)
        existing_count = conn.execute("SELECT COUNT(*) FROM event WHERE trial_id = ?", (trial_id,)).fetchone()[0]
        inserted += existing_count

        if expected and not (set(expected) - seen):
            return CollectionResult(inserted, tuple(sorted(seen)), (), False, 0)

        while True:
            try:
                response = self.sqs.receive_message(
                    QueueUrl=self.queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=min(10, max(0, int(deadline - time.monotonic()))),
                )
            except Exception as exc:  # noqa: BLE001
                return CollectionResult(
                    inserted, tuple(sorted(seen)), tuple(n for n in expected if n not in seen),
                    True, messages, f"{type(exc).__name__}: {exc}",
                )

            for message in response.get("Messages", []):
                messages += 1
                try:
                    for bucket, key in parse_s3_notifications(message.get("Body", "")):
                        events = self._read_object(bucket, key)
                        for event in events:
                            name = str(event.get("eventName") or "")
                            if name in expected:
                                seen.add(name)
                        inserted += insert_events(
                            conn,
                            events,
                            trial_id=trial_id,
                            only_between=(start, end),
                        )
                except Exception as exc:
                    # Do not acknowledge message on failure; leave on SQS for retry
                    return CollectionResult(
                        inserted,
                        tuple(sorted(seen)),
                        tuple(n for n in expected if n not in seen),
                        True,
                        messages,
                        f"{type(exc).__name__}: {exc}",
                    )

                # Acknowledge only after durable database persistence has succeeded
                try:
                    self.sqs.delete_message(
                        QueueUrl=self.queue_url,
                        ReceiptHandle=message["ReceiptHandle"],
                    )
                except Exception:  # noqa: BLE001 - message becomes visible again, safe due to idempotency
                    pass

            missing = tuple(name for name in expected if name not in seen)
            if expected and not missing:
                return CollectionResult(inserted, tuple(sorted(seen)), (), False, messages)
            if time.monotonic() >= deadline:
                return CollectionResult(inserted, tuple(sorted(seen)), missing, True, messages)
            sleep(poll_seconds)


class LocalCollector:
    """Rehearsal collector: events are already in hand."""

    def collect(self, conn, *, trial_id: str, events: list[dict[str, Any]], start: str, end: str) -> CollectionResult:
        inserted = insert_events(conn, events, trial_id=trial_id, only_between=(start, end))
        seen = tuple(sorted({str(event.get("eventName") or "") for event in events}))
        return CollectionResult(inserted, seen, (), False, 0)
