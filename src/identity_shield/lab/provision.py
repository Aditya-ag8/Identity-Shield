"""Terraform invocations for the lab environment.

Every call is a subprocess with an explicit working directory, a timeout and
captured output. Nothing here mutates anything by itself; ``apply`` and
``destroy`` are the two functions that do, and both are only reachable through
CLI verbs that require ``--yes``.

The milestone this module exists for is teardown, so ``destroy`` is a first-class
operation rather than an afterthought.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping

from identity_shield import config
from identity_shield.lab.models import TerraformRun


class TerraformUnavailable(RuntimeError):
    """The terraform binary is not on PATH."""


def binary() -> str:
    found = shutil.which("terraform")
    if not found:
        raise TerraformUnavailable(
            "terraform is not installed or not on PATH; install it with "
            "`winget install Hashicorp.Terraform` and open a new shell"
        )
    return found


def available() -> bool:
    return shutil.which("terraform") is not None


def version() -> str | None:
    if not available():
        return None
    try:
        result = subprocess.run(
            [binary(), "version", "-json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    try:
        return str(json.loads(result.stdout).get("terraform_version") or "") or None
    except json.JSONDecodeError:
        return None


def workdir(path: str | Path | None = None) -> Path:
    return Path(path) if path else config.TERRAFORM_LAB


def _var_args(variables: Mapping[str, Any] | None) -> list[str]:
    arguments: list[str] = []
    for key, value in (variables or {}).items():
        arguments.extend(["-var", f"{key}={value}"])
    return arguments


def run(
    directory: str | Path,
    arguments: list[str],
    *,
    timeout: int = 1800,
) -> TerraformRun:
    directory = Path(directory)
    command = (binary(), *arguments)
    try:
        result = subprocess.run(
            list(command),
            cwd=str(directory),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:  # pragma: no cover - guarded by binary()
        raise TerraformUnavailable(str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        return TerraformRun(
            command=command,
            returncode=-1,
            stdout=exc.stdout or "",
            stderr=f"terraform timed out after {timeout}s: {' '.join(arguments)}",
        )
    return TerraformRun(
        command=command,
        returncode=result.returncode,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
    )


def init(directory: str | Path | None = None, *, upgrade: bool = False) -> TerraformRun:
    arguments = ["init", "-input=false", "-no-color"]
    if upgrade:
        arguments.append("-upgrade")
    return run(workdir(directory), arguments)


def plan(directory: str | Path | None = None, variables: Mapping[str, Any] | None = None) -> TerraformRun:
    return run(
        workdir(directory),
        ["plan", "-input=false", "-no-color", *_var_args(variables)],
    )


def apply(
    directory: str | Path | None = None,
    variables: Mapping[str, Any] | None = None,
    *,
    auto_approve: bool = True,
    timeout: int = 1800,
) -> TerraformRun:
    arguments = ["apply", "-input=false", "-no-color", *_var_args(variables)]
    if auto_approve:
        arguments.append("-auto-approve")
    return run(workdir(directory), arguments, timeout=timeout)


def destroy(
    directory: str | Path | None = None,
    variables: Mapping[str, Any] | None = None,
    *,
    auto_approve: bool = True,
    timeout: int = 1800,
) -> TerraformRun:
    arguments = ["destroy", "-input=false", "-no-color", *_var_args(variables)]
    if auto_approve:
        arguments.append("-auto-approve")
    return run(workdir(directory), arguments, timeout=timeout)


def outputs(directory: str | Path | None = None) -> dict[str, Any]:
    result = run(workdir(directory), ["output", "-json", "-no-color"], timeout=120)
    if not result.ok or not result.stdout.strip():
        return {}
    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}
    return {
        key: value.get("value") if isinstance(value, Mapping) else value
        for key, value in raw.items()
    }
