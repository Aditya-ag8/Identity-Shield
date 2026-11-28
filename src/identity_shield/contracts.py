"""Cross-module artefact contracts.

Every artefact that crosses a module boundary is defined here, once. Modules
import these types instead of re-declaring their own, and ``tests/test_contracts.py``
round-trips each artefact so that a rename in one module fails the suite rather
than silently breaking the next one.

Artefacts
---------
``variants.jsonl``          Module 4 -> Module 5      one JSON object per line
``census.json``             Lab      -> Module 8      resources found in the account
``teardown-report.json``    Lab      -> Module 8      create/destroy residue proof

Design rules
------------
* Every artefact carries ``schema_version``. Bump it when a field is removed or
  its meaning changes; additive fields do not need a bump.
* Validation is hand-written rather than delegated to JSON Schema, so there is
  exactly one source of truth and every error names the offending field.
* ``spec_sha256`` is computed over the *semantic* content of a variant
  (technique + factor levels), never over its id or timestamps. Two variants
  that would produce the same attack therefore share a hash, which is how the
  generator detects duplicates.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_VERSION = 1

VARIANT_SETS = ("baseline", "ofat", "pairwise", "holdout")

#: Normal-activity variants live in their own file and are never part of the
#: attack-space coverage claim. They exist to measure false alarms.
BENIGN_SETS = ("benign",)
ALL_VARIANT_SETS = VARIANT_SETS + BENIGN_SETS

#: Sets that may be shown to analysis code before the holdout is unsealed.
VISIBLE_SETS = ("baseline", "ofat", "pairwise")

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.[A-Za-z0-9_]{1,16})?$")
_VARIANT_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ContractError(ValueError):
    """An artefact or a row inside one does not match the agreed shape."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(payload: Any) -> str:
    """Stable serialisation used for hashing. Never use plain ``json.dumps``."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def spec_hash(technique_id: str, factor_levels: Mapping[str, str]) -> str:
    """Hash of what the variant *does*, not what it is called."""
    payload = {"technique_id": technique_id, "factor_levels": dict(factor_levels)}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _as_str(value: Any, field_name: str) -> str:
    _require(isinstance(value, str) and value != "", f"{field_name} must be a non-empty string")
    return value


# ---------------------------------------------------------------------------
# Variants (Module 4 -> Module 5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Variant:
    variant_id: str
    technique_id: str
    variant_set: str
    factor_levels: Mapping[str, str]
    seed: int
    spec_sha256: str
    notes: str | None = None
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> None:
        _require(bool(_VARIANT_ID_RE.match(self.variant_id)), f"bad variant_id {self.variant_id!r}")
        _require(
            bool(_TECHNIQUE_RE.match(self.technique_id)),
            f"bad technique_id {self.technique_id!r} (expected T####[.###])",
        )
        _require(
            self.variant_set in ALL_VARIANT_SETS,
            f"bad variant_set {self.variant_set!r}; expected one of {ALL_VARIANT_SETS}",
        )
        _require(bool(self.factor_levels), "factor_levels must not be empty")
        for name, level in self.factor_levels.items():
            _require(isinstance(name, str) and name, "factor names must be non-empty strings")
            _require(isinstance(level, str) and level, f"level for {name!r} must be a non-empty string")
        _require(
            isinstance(self.seed, int) and self.seed >= 0,
            f"seed must be a non-negative integer, got {self.seed!r}",
        )
        _require(
            bool(_SHA256_RE.match(self.spec_sha256)),
            f"spec_sha256 must be 64 lowercase hex characters, got {self.spec_sha256!r}",
        )
        expected = spec_hash(self.technique_id, self.factor_levels)
        _require(
            expected == self.spec_sha256,
            f"{self.variant_id}: spec_sha256 does not match factor levels",
        )
        _require(
            self.schema_version == SCHEMA_VERSION,
            f"unsupported schema_version {self.schema_version!r}",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "variant",
            "variant_id": self.variant_id,
            "technique_id": self.technique_id,
            "variant_set": self.variant_set,
            "factor_levels": dict(self.factor_levels),
            "seed": self.seed,
            "spec_sha256": self.spec_sha256,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Variant":
        _require(isinstance(data, Mapping), "variant row must be an object")
        levels = data.get("factor_levels")
        _require(isinstance(levels, Mapping), "factor_levels must be an object")
        variant = cls(
            variant_id=_as_str(data.get("variant_id"), "variant_id"),
            technique_id=_as_str(data.get("technique_id"), "technique_id"),
            variant_set=_as_str(data.get("variant_set"), "variant_set"),
            factor_levels={str(k): str(v) for k, v in levels.items()},
            seed=int(data.get("seed", -1)),
            spec_sha256=_as_str(data.get("spec_sha256"), "spec_sha256"),
            notes=data.get("notes"),
            schema_version=int(data.get("schema_version", 0)),
        )
        variant.validate()
        return variant


def write_variants(path: str | Path, variants: Sequence[Variant]) -> Path:
    """Write one variant per line, in the order given. Deterministic."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(variant.to_dict(), sort_keys=True) for variant in variants]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path


def read_variants(
    path: str | Path,
    *,
    include_holdout: bool = True,
    techniques: Iterable[str] | None = None,
) -> list[Variant]:
    """Read a variants file, validating every row.

    ``include_holdout=False`` is the default posture for analysis code: the
    sealed set exists, but nothing may look at it until the round-2 rules are
    frozen. Module 7 passes ``include_holdout=True`` only at the very end.
    """
    wanted = {t.upper() for t in techniques} if techniques else None
    rows: list[Variant] = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            variant = Variant.from_dict(json.loads(line))
        except (json.JSONDecodeError, ContractError) as exc:
            raise ContractError(f"{path}:{number}: {exc}") from exc
        if not include_holdout and variant.variant_set == "holdout":
            continue
        if wanted and variant.technique_id not in wanted:
            continue
        rows.append(variant)
    return rows


# ---------------------------------------------------------------------------
# Census / teardown (Lab -> Module 8)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceRef:
    service: str
    kind: str
    identifier: str
    arn: str | None = None
    region: str | None = None
    tags: Mapping[str, str] = field(default_factory=dict)
    source: str = "unknown"

    def validate(self) -> None:
        for name in ("service", "kind", "identifier", "source"):
            _require(bool(getattr(self, name)), f"resource {name} must not be empty")
        _require(isinstance(self.tags, Mapping), "resource tags must be an object")

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "kind": self.kind,
            "identifier": self.identifier,
            "arn": self.arn,
            "region": self.region,
            "tags": dict(self.tags),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResourceRef":
        resource = cls(
            service=_as_str(data.get("service"), "service"),
            kind=_as_str(data.get("kind"), "kind"),
            identifier=_as_str(data.get("identifier"), "identifier"),
            arn=data.get("arn"),
            region=data.get("region"),
            tags={str(k): str(v) for k, v in (data.get("tags") or {}).items()},
            source=str(data.get("source") or "unknown"),
        )
        resource.validate()
        return resource

    @property
    def key(self) -> tuple[str, str]:
        return (self.service, self.identifier)


@dataclass(frozen=True)
class Census:
    generated_at: str
    account_id: str
    region: str
    resources: tuple[ResourceRef, ...] = ()
    errors: tuple[Mapping[str, Any], ...] = ()
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> None:
        _require(isinstance(self.account_id, str), "account_id must be a string")
        _require(isinstance(self.region, str) and self.region, "region must be a non-empty string")
        seen: set[tuple[str, str]] = set()
        for resource in self.resources:
            resource.validate()
            _require(resource.key not in seen, f"duplicate census entry {resource.key!r}")
            seen.add(resource.key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "census",
            "generated_at": self.generated_at,
            "account_id": self.account_id,
            "region": self.region,
            "resources": [resource.to_dict() for resource in self.resources],
            "errors": [dict(error) for error in self.errors],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Census":
        census = cls(
            generated_at=_as_str(data.get("generated_at"), "generated_at"),
            account_id=_as_str(data.get("account_id"), "account_id"),
            region=_as_str(data.get("region"), "region"),
            resources=tuple(ResourceRef.from_dict(row) for row in data.get("resources") or []),
            errors=tuple(dict(row) for row in data.get("errors") or []),
            schema_version=int(data.get("schema_version", 0)),
        )
        census.validate()
        return census


@dataclass(frozen=True)
class TeardownReport:
    run_id: str
    started_at: str
    finished_at: str
    account_id: str
    region: str
    before: tuple[ResourceRef, ...]
    after: tuple[ResourceRef, ...]
    residue: tuple[ResourceRef, ...]
    census_errors: tuple[Mapping[str, Any], ...]
    terraform_exit_code: int | None
    passed: bool
    notes: tuple[str, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "teardown-report",
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "account_id": self.account_id,
            "region": self.region,
            "before": [resource.to_dict() for resource in self.before],
            "after": [resource.to_dict() for resource in self.after],
            "residue": [resource.to_dict() for resource in self.residue],
            "census_errors": [dict(error) for error in self.census_errors],
            "terraform_exit_code": self.terraform_exit_code,
            "passed": self.passed,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TeardownReport":
        return cls(
            run_id=_as_str(data.get("run_id"), "run_id"),
            started_at=_as_str(data.get("started_at"), "started_at"),
            finished_at=_as_str(data.get("finished_at"), "finished_at"),
            account_id=_as_str(data.get("account_id"), "account_id"),
            region=_as_str(data.get("region"), "region"),
            before=tuple(ResourceRef.from_dict(row) for row in data.get("before") or []),
            after=tuple(ResourceRef.from_dict(row) for row in data.get("after") or []),
            residue=tuple(ResourceRef.from_dict(row) for row in data.get("residue") or []),
            census_errors=tuple(dict(row) for row in data.get("census_errors") or []),
            terraform_exit_code=data.get("terraform_exit_code"),
            passed=bool(data.get("passed")),
            notes=tuple(data.get("notes") or ()),
            schema_version=int(data.get("schema_version", 0)),
        )


# ---------------------------------------------------------------------------
# Miss findings (analysis -> report / dashboard)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """One missed variant, with the evidence needed to review the miss.

    A finding never claims *why* a rule missed beyond what the rule's own field
    list and the variant's expected surface prove. Anything stronger would be
    speculation and belongs in the rule-diff review, not the artefact.
    """

    finding_id: str
    technique_id: str
    variant_id: str
    variant_set: str
    factor_levels: Mapping[str, str]
    expected_surface: tuple[str, ...]
    fired_rules: tuple[str, ...]
    rule_fields: tuple[str, ...]
    rationale: str
    created_at: str
    synthetic: bool = False
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> None:
        _require(bool(self.finding_id), "finding_id must not be empty")
        _require(
            bool(_TECHNIQUE_RE.match(self.technique_id)),
            f"bad technique_id {self.technique_id!r}",
        )
        _require(
            self.variant_set in VISIBLE_SETS,
            f"finding variant_set must be a visible set, got {self.variant_set!r}",
        )
        _require(isinstance(self.factor_levels, Mapping), "factor_levels must be an object")
        _require(
            self.schema_version == SCHEMA_VERSION,
            f"unsupported schema_version {self.schema_version!r}",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "finding",
            "finding_id": self.finding_id,
            "technique_id": self.technique_id,
            "variant_id": self.variant_id,
            "variant_set": self.variant_set,
            "factor_levels": dict(self.factor_levels),
            "expected_surface": list(self.expected_surface),
            "fired_rules": list(self.fired_rules),
            "rule_fields": list(self.rule_fields),
            "rationale": self.rationale,
            "synthetic": self.synthetic,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        finding = cls(
            finding_id=_as_str(data.get("finding_id"), "finding_id"),
            technique_id=_as_str(data.get("technique_id"), "technique_id"),
            variant_id=_as_str(data.get("variant_id"), "variant_id"),
            variant_set=_as_str(data.get("variant_set"), "variant_set"),
            factor_levels={
                str(k): str(v)
                for k, v in (data.get("factor_levels") or {}).items()
            },
            expected_surface=tuple(str(v) for v in data.get("expected_surface") or ()),
            fired_rules=tuple(str(v) for v in data.get("fired_rules") or ()),
            rule_fields=tuple(str(v) for v in data.get("rule_fields") or ()),
            rationale=_as_str(data.get("rationale"), "rationale"),
            created_at=_as_str(data.get("created_at"), "created_at"),
            synthetic=bool(data.get("synthetic")),
            schema_version=int(data.get("schema_version", 0)),
        )
        finding.validate()
        return finding


@dataclass(frozen=True)
class FindingsArtifact:
    generated_at: str
    ruleset_version: str
    findings: tuple[Finding, ...]
    summary: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": "findings",
            "generated_at": self.generated_at,
            "ruleset_version": self.ruleset_version,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": dict(self.summary),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FindingsArtifact":
        return cls(
            generated_at=_as_str(data.get("generated_at"), "generated_at"),
            ruleset_version=_as_str(data.get("ruleset_version"), "ruleset_version"),
            findings=tuple(
                Finding.from_dict(row) for row in data.get("findings") or []
            ),
            summary=dict(data.get("summary") or {}),
            schema_version=int(data.get("schema_version", 0)),
        )

    def validate(self) -> None:
        _require(
            self.schema_version == SCHEMA_VERSION,
            f"unsupported schema_version {self.schema_version!r}",
        )
        seen: set[str] = set()
        for finding in self.findings:
            finding.validate()
            _require(
                finding.finding_id not in seen,
                f"duplicate finding {finding.finding_id!r}",
            )
            seen.add(finding.finding_id)


def write_findings(path: str | Path, artifact: FindingsArtifact) -> Path:
    artifact.validate()
    return write_json(path, artifact.to_dict())


def read_findings(path: str | Path) -> FindingsArtifact:
    artifact = FindingsArtifact.from_dict(read_json(path))
    artifact.validate()
    return artifact


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------


def write_json(path: str | Path, payload: Mapping[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path


def read_json(path: str | Path) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    _require(isinstance(document, dict), f"{path}: expected a JSON object")
    return document
