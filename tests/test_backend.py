from __future__ import annotations

from pathlib import Path

import pytest

from identity_shield import config
from identity_shield.detect import pysigma_backend as backend
from identity_shield.detect.parser import iter_events
from identity_shield.detect.rules import load_sigma_text

BASELINE_DIR = config.CONF / "rules" / "baseline"
RULE_FILES = sorted(p for p in BASELINE_DIR.iterdir() if p.suffix in (".yml", ".yaml"))


def _all_fixture_events() -> list[dict]:
    events: list[dict] = []
    for path in sorted(config.FIXTURE_ROOT.rglob("*.json")):
        events.extend(iter_events(path))
    return events


pytestmark = pytest.mark.skipif(
    not backend.PYSIGMA_AVAILABLE, reason=f"pySigma unavailable: {backend.PYSIGMA_ERROR}"
)


def test_baseline_rules_use_pysigma_path():
    """The round-1 corpus is our own, so it must compile without the fallback."""
    assert RULE_FILES, "no baseline Sigma rules found"
    for path in RULE_FILES:
        rule = backend.convert_file(path)
        assert rule.loader == "pysigma"
        assert rule.node is not None


def test_compile_corpus_reports_every_rule():
    report = backend.compile_corpus(BASELINE_DIR)
    assert report.total == len(RULE_FILES)
    assert report.compile_rate == 1.0
    assert report.statuses.get("fallback", 0) == 0


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: Path(p).stem)
def test_backend_agrees_with_reference_parser(path):
    """The two implementations must produce identical verdicts.

    A disagreement means one of them is wrong, and the backend is the one a
    reviewer will trust, so this is the guard that keeps it honest.
    """
    events = _all_fixture_events()
    assert events

    via_pysigma = backend.convert_file(path)
    via_reference = load_sigma_text(path.read_text(encoding="utf-8"), path=str(path))

    disagreements = [
        event["eventID"]
        for event in events
        if via_pysigma.matches(event) != via_reference.matches(event)
    ]
    assert not disagreements, f"{path.name} disagrees on events: {disagreements}"


def test_unsupported_modifier_carries_a_reason():
    document = """
title: base64 rule
id: 22222222-2222-2222-2222-222222222222
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    userAgent|base64: abc
  condition: selection
"""
    with pytest.raises(Exception) as excinfo:
        backend.convert_text(document)
    assert "base64" in str(excinfo.value).lower()


def test_convert_text_rejects_malformed_yaml():
    with pytest.raises(Exception):
        backend.convert_text("title: [unclosed")
