"""CloudTrail log parsing.

Handles the three shapes we actually encounter:

* a single event object (what `aws cloudtrail lookup-events` and most fixtures
  give you),
* an S3 log file's ``{"Records": [...]}`` envelope,
* a bare list of events (concatenated fixtures).

Both plain ``.json`` and ``.json.gz`` are accepted, because CloudTrail writes
gzip to S3 and it is not worth making callers care.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def normalize_time(value: str | None, fallback: datetime | None = None) -> str:
    """Return a fixed-width UTC timestamp so string comparison is chronological."""
    if not value:
        moment = fallback or datetime.now(timezone.utc)
        return moment.astimezone(timezone.utc).strftime(ISO_FORMAT)

    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return str(value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(ISO_FORMAT)


@dataclass(frozen=True, slots=True)
class EventRow:
    event_id: str
    event_time: str
    received_at: str
    event_source: str | None
    event_name: str | None
    aws_region: str | None
    source_ip: str | None
    user_agent: str | None
    user_identity_type: str | None
    user_identity_arn: str | None
    error_code: str | None
    raw: str

    def as_tuple(self) -> tuple[Any, ...]:
        return (
            self.event_id,
            self.event_time,
            self.received_at,
            self.event_source,
            self.event_name,
            self.aws_region,
            self.source_ip,
            self.user_agent,
            self.user_identity_type,
            self.user_identity_arn,
            self.error_code,
            self.raw,
        )


def extract_events(payload: Any) -> list[dict[str, Any]]:
    """Flatten any supported payload shape into a list of event dicts."""
    if isinstance(payload, list):
        collected: list[dict[str, Any]] = []
        for item in payload:
            collected.extend(extract_events(item))
        return collected

    if isinstance(payload, Mapping):
        records = payload.get("Records")
        if isinstance(records, list):
            collected = []
            for item in records:
                collected.extend(extract_events(item))
            return collected
        if "eventID" in payload or "eventName" in payload:
            return [dict(payload)]
    return []


def read_payload(path: str | Path) -> Any:
    path = Path(path)
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)
    return json.loads(path.read_text(encoding="utf-8"))


def normalize(event: Mapping[str, Any]) -> EventRow:
    raw = json.dumps(event, ensure_ascii=False, sort_keys=True)
    identity = event.get("userIdentity") or {}
    if not isinstance(identity, Mapping):
        identity = {}

    event_time = normalize_time(event.get("eventTime"))
    received_at = normalize_time(event.get("receiptTime"), fallback=_parse_iso(event_time))

    event_id = event.get("eventID")
    if not event_id:
        event_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    return EventRow(
        event_id=str(event_id),
        event_time=event_time,
        received_at=received_at,
        event_source=_opt(event.get("eventSource")),
        event_name=_opt(event.get("eventName")),
        aws_region=_opt(event.get("awsRegion")),
        source_ip=_opt(event.get("sourceIPAddress")),
        user_agent=_opt(event.get("userAgent")),
        user_identity_type=_opt(identity.get("type")),
        user_identity_arn=_opt(identity.get("arn")),
        error_code=_opt(event.get("errorCode")),
        raw=raw,
    )


def iter_events(path: str | Path) -> Iterator[dict[str, Any]]:
    for event in extract_events(read_payload(path)):
        yield event


def _parse_iso(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, ISO_FORMAT).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _opt(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None
