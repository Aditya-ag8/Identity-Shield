"""Load and validate the Module 4 catalogue.

Two YAML files define the entire variant space:

``conf/factors.yaml``      five factors, their levels, and the CloudTrail fields
                           each factor can move
``conf/techniques.yaml``   eight techniques plus per-technique exclusions and
                           baseline overrides

Validation is deliberately strict. A typo in an exclusion list would silently
create variants that cannot be executed, which shows up much later as a
"missing" trial rather than as a config error. So every exclusion is checked
against the factor definitions at load time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from identity_shield import config

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class CatalogueError(ValueError):
    """The factor or technique definitions are internally inconsistent."""


@dataclass(frozen=True)
class Factor:
    name: str
    description: str
    levels: tuple[str, ...]
    baseline: str
    surface: tuple[str, ...]

    def index(self, level: str) -> int:
        return self.levels.index(level)

    def surface_for(self, level: str, baseline: str | None = None) -> tuple[str, ...]:
        """Fields this level can move, relative to the given baseline level.

        The baseline is a parameter because a technique may override the
        factor's default: T1552.005 runs as ``instance_profile``, so for that
        technique ``iam_user`` *is* a change even though it is the global
        default.
        """
        if level == (baseline or self.baseline):
            return ()
        return self.surface


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    executor: str
    event_names: tuple[str, ...]
    required_actions: tuple[str, ...]
    requires_data_events: bool
    excluded_levels: Mapping[str, tuple[str, ...]]
    baseline_levels: Mapping[str, str]
    notes: str = ""

    def is_allowed(self, factor: str, level: str) -> bool:
        return level not in self.excluded_levels.get(factor, ())


@dataclass(frozen=True)
class Catalogue:
    version: int
    factors: Mapping[str, Factor]
    techniques: tuple[Technique, ...]

    @property
    def factor_names(self) -> tuple[str, ...]:
        return tuple(self.factors)

    def technique(self, technique_id: str) -> Technique:
        for entry in self.techniques:
            if entry.technique_id == technique_id:
                return entry
        raise KeyError(f"unknown technique {technique_id!r}")

    def baseline_for(self, technique: Technique) -> dict[str, str]:
        """The canonical level of every factor for this technique."""
        baseline: dict[str, str] = {}
        for name, factor in self.factors.items():
            level = technique.baseline_levels.get(name, factor.baseline)
            baseline[name] = level
        return baseline

    def allowed_levels(self, technique: Technique, factor: Factor) -> tuple[str, ...]:
        return tuple(level for level in factor.levels if technique.is_allowed(factor.name, level))

    def expected_surface(self, technique: Technique, levels: Mapping[str, str]) -> tuple[str, ...]:
        """CloudTrail fields this combination should move, relative to baseline.

        This is the offline half of the validity gate. The live half, in M5,
        compares actual captured events. A variant with an empty expected
        surface cannot prove anything: it is the same log record under a new
        name.
        """
        baseline = self.baseline_for(technique)
        fields: list[str] = []
        for name, level in levels.items():
            factor = self.factors[name]
            if level == baseline[name]:
                continue
            for field_name in factor.surface_for(level, baseline[name]):
                if field_name not in fields:
                    fields.append(field_name)
        return tuple(fields)


def _read_yaml(path: Path) -> Mapping[str, Any]:
    if not path.exists():
        raise CatalogueError(f"missing catalogue file: {path}")
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(document, Mapping):
        raise CatalogueError(f"{path}: expected a mapping at the top level")
    return document


def load_factors(path: str | Path | None = None) -> dict[str, Factor]:
    document = _read_yaml(Path(path) if path else config.FACTORS_YAML)
    raw = document.get("factors")
    if not isinstance(raw, Mapping) or not raw:
        raise CatalogueError("factors.yaml: 'factors' must be a non-empty mapping")

    factors: dict[str, Factor] = {}
    for name, entry in raw.items():
        if not isinstance(entry, Mapping):
            raise CatalogueError(f"factor {name!r} must be a mapping")
        levels_raw = entry.get("levels")
        if not isinstance(levels_raw, Mapping) or len(levels_raw) < 2:
            raise CatalogueError(f"factor {name!r} needs at least two levels")
        levels = tuple(str(level) for level in levels_raw)
        baseline = entry.get("baseline")
        if baseline is None:
            raise CatalogueError(f"factor {name!r} has no baseline level")
        baseline = str(baseline)
        if baseline not in levels:
            raise CatalogueError(
                f"factor {name!r}: baseline {baseline!r} is not one of {levels}"
            )
        surface = tuple(str(field) for field in entry.get("cloudtrail_surface") or ())
        if not surface:
            raise CatalogueError(
                f"factor {name!r} declares no cloudtrail_surface; variants of it "
                "could not be distinguished from baseline"
            )
        factors[str(name)] = Factor(
            name=str(name),
            description=str(entry.get("description") or ""),
            levels=levels,
            baseline=baseline,
            surface=surface,
        )
    return factors


def load_techniques(path: str | Path | None = None) -> tuple[Technique, ...]:
    document = _read_yaml(Path(path) if path else config.TECHNIQUES_YAML)
    raw = document.get("techniques")
    if not isinstance(raw, list) or not raw:
        raise CatalogueError("techniques.yaml: 'techniques' must be a non-empty list")

    techniques: list[Technique] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise CatalogueError("each technique must be a mapping")
        technique_id = str(entry.get("technique_id") or "")
        if not _TECHNIQUE_RE.match(technique_id):
            raise CatalogueError(f"bad technique_id {technique_id!r}")

        excluded: dict[str, tuple[str, ...]] = {}
        for factor_name, levels in (entry.get("excluded_levels") or {}).items():
            excluded[str(factor_name)] = tuple(str(level) for level in levels or ())

        baseline_levels = {
            str(name): str(level)
            for name, level in (entry.get("baseline_levels") or {}).items()
        }

        techniques.append(
            Technique(
                technique_id=technique_id,
                name=str(entry.get("name") or technique_id),
                tactic=str(entry.get("tactic") or ""),
                executor=str(entry.get("executor") or ""),
                event_names=tuple(str(name) for name in entry.get("event_names") or ()),
                required_actions=tuple(
                    str(action) for action in entry.get("required_actions") or ()
                ),
                requires_data_events=bool(entry.get("requires_data_events")),
                excluded_levels=excluded,
                baseline_levels=baseline_levels,
                notes=str(entry.get("notes") or "").strip(),
            )
        )
    return tuple(techniques)


def validate(catalogue: Catalogue) -> None:
    """Raise :class:`CatalogueError` if the catalogue cannot produce valid variants."""
    problems: list[str] = []
    seen: set[str] = set()

    for technique in catalogue.techniques:
        if technique.technique_id in seen:
            problems.append(f"duplicate technique {technique.technique_id}")
        seen.add(technique.technique_id)

        if not technique.event_names:
            problems.append(f"{technique.technique_id}: no event_names")

        for factor_name, levels in technique.excluded_levels.items():
            factor = catalogue.factors.get(factor_name)
            if factor is None:
                problems.append(
                    f"{technique.technique_id}: excluded_levels references unknown factor "
                    f"{factor_name!r}"
                )
                continue
            for level in levels:
                if level not in factor.levels:
                    problems.append(
                        f"{technique.technique_id}: excluded level {level!r} is not a level "
                        f"of {factor_name!r}"
                    )
            remaining = [level for level in factor.levels if level not in levels]
            if not remaining:
                problems.append(
                    f"{technique.technique_id}: excludes every level of {factor_name!r}"
                )

        for factor_name, level in technique.baseline_levels.items():
            factor = catalogue.factors.get(factor_name)
            if factor is None:
                problems.append(
                    f"{technique.technique_id}: baseline_levels references unknown factor "
                    f"{factor_name!r}"
                )
                continue
            if level not in factor.levels:
                problems.append(
                    f"{technique.technique_id}: baseline level {level!r} is not a level of "
                    f"{factor_name!r}"
                )

        baseline = catalogue.baseline_for(technique)
        for factor_name, level in baseline.items():
            if not technique.is_allowed(factor_name, level):
                problems.append(
                    f"{technique.technique_id}: baseline level {level!r} of {factor_name!r} "
                    "is excluded for this technique; add baseline_levels"
                )

    if problems:
        raise CatalogueError("catalogue is inconsistent:\n  - " + "\n  - ".join(problems))


def load_catalogue(
    factors_path: str | Path | None = None,
    techniques_path: str | Path | None = None,
) -> Catalogue:
    factors = load_factors(factors_path)
    techniques = load_techniques(techniques_path)
    document = _read_yaml(Path(techniques_path) if techniques_path else config.TECHNIQUES_YAML)
    catalogue = Catalogue(
        version=int(document.get("version") or 1),
        factors=factors,
        techniques=techniques,
    )
    validate(catalogue)
    return catalogue
