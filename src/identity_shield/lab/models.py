"""Small value objects used inside the lab module.

Cross-module artefacts (census, teardown report, variants) live in
:mod:`identity_shield.contracts`; these types never leave the module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str
    remedy: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "remedy": self.remedy,
        }


@dataclass(frozen=True)
class DoctorReport:
    generated_at: str
    region: str
    checks: tuple[Check, ...] = ()

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(check for check in self.checks if check.status == "fail")

    @property
    def warnings(self) -> tuple[Check, ...]:
        return tuple(check for check in self.checks if check.status == "warn")

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "region": self.region,
            "ok": self.ok,
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass(frozen=True)
class TerraformRun:
    command: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def tail(self, lines: int = 20) -> str:
        text = (self.stderr or self.stdout or "").strip().splitlines()
        return "\n".join(text[-lines:])


@dataclass(frozen=True)
class Residue:
    """Outcome of comparing the census before and after teardown."""

    before: tuple = ()
    after: tuple = ()
    disappeared: tuple = ()
    appeared: tuple = ()

    @property
    def still_present(self) -> tuple:
        return self.after

    @property
    def passed(self) -> bool:
        return not self.after

    def to_dict(self) -> dict[str, Any]:
        return {
            "before": len(self.before),
            "after": len(self.after),
            "disappeared": len(self.disappeared),
            "appeared": len(self.appeared),
            "passed": self.passed,
        }
