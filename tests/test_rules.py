from __future__ import annotations

import pytest

from identity_shield.detect.rules import (
    BoolNode,
    FieldMatch,
    UnsupportedRule,
    evaluate,
    get_field,
    load_sigma_text,
    match_value,
    parse_condition,
    technique_from_tags,
)

EVENT = {
    "eventName": "CreateAccessKey",
    "eventSource": "iam.amazonaws.com",
    "userAgent": "Boto3/1.34.49",
    "sourceIPAddress": "52.94.13.7",
    "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/r/s"},
    "requestParameters": {"userName": "TempAdmin", "maxItems": 100},
}


def test_field_lookup_is_case_insensitive():
    assert get_field(EVENT, "eventname") == "CreateAccessKey"
    assert get_field(EVENT, "UserIdentity.Type") == "AssumedRole"
    assert get_field(EVENT, "requestParameters.userName") == "TempAdmin"


def test_field_lookup_missing_returns_none():
    assert get_field(EVENT, "nope.nothing") is None
    assert get_field(EVENT, "eventName.deeper") is None


@pytest.mark.parametrize(
    ("actual", "value", "op", "expected"),
    [
        ("CreateAccessKey", "createaccesskey", "eq", True),
        ("CreateAccessKey", "createaccesskey*", "eq", True),
        ("CreateAccessKey", "create*key", "eq", True),
        ("CreateAccessKey", "create", "eq", False),
        ("Boto3/1.34", "boto3", "contains", True),
        ("Boto3/1.34", "BOTO3", "contains", True),
        ("Boto3/1.34", "*boto3*", "contains", True),
        ("iam.amazonaws.com", "iam.", "startswith", True),
        ("TempAdmin", "Admin", "endswith", True),
        ("TempAdmin", "Admin$", "re", True),
        ("TempAdmin", "^Temp", "re", True),
        ("TempAdmin", "^Admin", "re", False),
        ("TempAdmin", "Temp.*", "regex", True),
        ("TempAdmin", "Temp", "regex", False),
        (100, "100", "eq", True),
        (True, "true", "eq", True),
        (None, "anything", "eq", False),
        (["a", "b"], "b", "eq", True),
    ],
)
def test_match_value(actual, value, op, expected):
    assert match_value(actual, value, op) is expected


def test_evaluate_and_or_not():
    node = BoolNode(
        "and",
        (
            FieldMatch("eventName", values=("CreateAccessKey",)),
            BoolNode("not", (FieldMatch("userAgent", "contains", ("boto3",)),)),
        ),
    )
    assert evaluate(node, EVENT) is False

    node = BoolNode(
        "and",
        (
            FieldMatch("eventName", values=("CreateAccessKey",)),
            FieldMatch("userIdentity.type", values=("AssumedRole",)),
        ),
    )
    assert evaluate(node, EVENT) is True


def test_evaluate_at_least_quantifier():
    node = BoolNode(
        "at_least",
        (
            FieldMatch("eventName", values=("Nope",)),
            FieldMatch("eventSource", values=("iam.amazonaws.com",)),
        ),
        count=1,
    )
    assert evaluate(node, EVENT) is True
    node = BoolNode("at_least", (node.children[0],), count=1)
    assert evaluate(node, EVENT) is False


def test_match_all_requires_every_value():
    node = FieldMatch("userAgent", "contains", ("boto3", "nope"), match_all=True)
    assert evaluate(node, EVENT) is False
    node = FieldMatch("userAgent", "contains", ("boto3", "1.34"), match_all=True)
    assert evaluate(node, EVENT) is True


def test_parse_condition_handles_one_of_pattern():
    selections = {
        "selection_users": FieldMatch("eventName", values=("ListUsers",)),
        "selection_roles": FieldMatch("eventName", values=("ListRoles",)),
    }
    node = parse_condition("1 of selection_*", selections)
    assert evaluate(node, {"eventName": "ListRoles"}) is True
    assert evaluate(node, {"eventName": "CreateAccessKey"}) is False


def test_parse_condition_handles_precedence():
    selections = {
        "a": FieldMatch("x", values=("1",)),
        "b": FieldMatch("y", values=("1",)),
        "c": FieldMatch("z", values=("1",)),
    }
    node = parse_condition("a or b and c", selections)
    # a or (b and c)
    assert evaluate(node, {"x": "1"}) is True
    assert evaluate(node, {"y": "1"}) is False
    assert evaluate(node, {"y": "1", "z": "1"}) is True


def test_parse_condition_rejects_unknown_selection():
    with pytest.raises(UnsupportedRule):
        parse_condition("missing", {})


def test_unsupported_modifier_is_reported():
    document = """
title: t
detection:
  selection:
    userAgent|base64: abc
  condition: selection
"""
    with pytest.raises(UnsupportedRule, match="base64"):
        load_sigma_text(document)


def test_technique_from_tags():
    assert technique_from_tags(["attack.discovery", "attack.t1087.004"]) == "T1087.004"
    assert technique_from_tags(["attack.persistence", "attack.t1098.001"]) == "T1098.001"
    assert technique_from_tags(["unrelated"]) is None
    assert technique_from_tags(None) is None
