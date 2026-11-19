"""Project paths and environment overrides.

Everything resolves relative to the repository root so that commands work from
any working directory, including from inside the Streamlit app.
"""

from __future__ import annotations

import os
from pathlib import Path

_ENV_ROOT = "IDENTITY_SHIELD_ROOT"
_ENV_DB = "IDENTITY_SHIELD_DB"


def _find_root() -> Path:
    override = os.environ.get(_ENV_ROOT)
    if override:
        return Path(override).resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return here.parents[3]


ROOT: Path = _find_root()
CONF: Path = ROOT / "conf"
FIXTURES: Path = ROOT / "fixtures"
DATA: Path = ROOT / "data"
DOCS: Path = ROOT / "docs"
VENDOR: Path = ROOT / "vendor"
INFRA: Path = ROOT / "infra"

#: Module 4 output: variants.jsonl + coverage.json live here.
VARIANTS_DIR: Path = DATA / "variants"

#: Lab module output: census snapshots and teardown reports.
LAB_DIR: Path = DATA / "lab"

#: Terraform root for the lab environment.
TERRAFORM_LAB: Path = INFRA / "terraform" / "envs" / "lab"

DEFAULT_DB: Path = Path(os.environ.get(_ENV_DB, DATA / "identity_shield.db"))

TECHNIQUES_YAML = CONF / "techniques.yaml"
FACTORS_YAML = CONF / "factors.yaml"
RULESETS_YAML = CONF / "rulesets.yaml"
SCHEMA_SQL = Path(__file__).resolve().parent / "db" / "schema.sql"

FIXTURE_ROOT = FIXTURES / "cloudtrail"
FIXTURE_MANIFEST = FIXTURES / "manifest.yaml"


def resolve_db(path: str | Path | None = None) -> Path:
    return Path(path).expanduser().resolve() if path else DEFAULT_DB
