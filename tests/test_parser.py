from __future__ import annotations

import gzip
import json

import pytest

from identity_shield.detect import parser


def test_extract_single_event():
    events = parser.extract_events({"eventID": "abc", "eventName": "ListUsers"})
    assert len(events) == 1
    assert events[0]["eventName"] == "ListUsers"


def test_extract_records_envelope():
    payload = {"Records": [{"eventID": "a", "eventName": "A"}, {"eventID": "b", "eventName": "B"}]}
    assert [e["eventID"] for e in parser.extract_events(payload)] == ["a", "b"]


def test_extract_bare_list_is_flattened():
    payload = [{"eventID": "a", "eventName": "A"}, {"Records": [{"eventID": "b", "eventName": "B"}]}]
    assert len(parser.extract_events(payload)) == 2


def test_extract_ignores_non_events():
    assert parser.extract_events({"hello": "world"}) == []
    assert parser.extract_events("nonsense") == []


def test_read_gzip_payload(tmp_path):
    path = tmp_path / "log.json.gz"
    payload = {"Records": [{"eventID": "gz", "eventName": "GetObject"}]}
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)
    assert parser.extract_events(parser.read_payload(path))[0]["eventID"] == "gz"


def test_normalize_projects_the_columns_we_index():
    event = {
        "eventID": "e1",
        "eventTime": "2026-11-03T09:14:22Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "ListUsers",
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "52.94.13.7",
        "userAgent": "aws-cli/2.15.30",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/x"},
        "errorCode": "AccessDenied",
    }
    row = parser.normalize(event)
    assert row.event_time == "2026-11-03T09:14:22Z"
    assert row.event_source == "iam.amazonaws.com"
    assert row.user_identity_type == "IAMUser"
    assert row.source_ip == "52.94.13.7"
    assert row.error_code == "AccessDenied"
    assert json.loads(row.raw)["eventID"] == "e1"


def test_normalize_synthesises_missing_event_id():
    row = parser.normalize({"eventName": "ListUsers", "eventTime": "2026-11-03T09:14:22Z"})
    assert len(row.event_id) == 32


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-11-03T09:14:22Z", "2026-11-03T09:14:22Z"),
        ("2026-11-03T09:14:22+01:00", "2026-11-03T08:14:22Z"),
        ("2026-11-03T09:14:22.987Z", "2026-11-03T09:14:22Z"),
    ],
)
def test_normalize_time_is_fixed_width_utc(value, expected):
    assert parser.normalize_time(value) == expected


def test_received_at_falls_back_to_receipt_time():
    row = parser.normalize(
        {"eventID": "x", "eventTime": "2026-11-03T09:00:00Z", "receiptTime": "2026-11-03T09:04:10Z"}
    )
    assert row.received_at == "2026-11-03T09:04:10Z"
