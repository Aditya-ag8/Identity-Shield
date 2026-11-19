"""Runner value objects.

Kept deliberately small: the runner writes to SQLite through the existing
schema, and cross-module artefacts stay in :mod:`identity_shield.contracts`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from identity_shield.contracts import Variant, utc_now
from identity_shield.variants.loader import Technique


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    status: str  # ok | warn | fail
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class PreflightReport:
    checks: tuple[PreflightCheck, ...] = ()

    @property
    def failures(self) -> tuple[PreflightCheck, ...]:
        return tuple(check for check in self.checks if check.status == "fail")

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [check.to_dict() for check in self.checks]}


@dataclass
class ExecutionResult:
    ok: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    created: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class Verification:
    passed: bool
    detail: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrialContext:
    run_id: str
    variant: Variant
    technique: Technique
    repetition: int
    account_id: str
    region: str
    lab: Mapping[str, Any] = field(default_factory=dict)
    synthetic: bool = False
    session: Any = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def window_start(self) -> str:
        return self.started_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def baseline(self) -> Mapping[str, str]:
        return self.variant.factor_levels


@dataclass(frozen=True)
class TrialOutcome:
    trial_id: str
    attack_succeeded: bool
    variant_changed: bool
    detected: bool
    alerts: int
    events: int
    error: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=utc_now)
