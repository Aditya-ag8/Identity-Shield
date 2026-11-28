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
import os
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
    import re

    arguments: list[str] = []
    for key, value in (variables or {}).items():
        clean_key = str(key).strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", clean_key):
            raise ValueError(f"Invalid Terraform variable name {key!r}")
        text_val = str(value)
        if "\x00" in text_val or "\n" in text_val or "\r" in text_val:
            raise ValueError(f"Invalid control character in Terraform variable {clean_key!r}")
        arguments.extend(["-var", f"{clean_key}={text_val}"])
    return arguments


def aws_env(
    *,
    session: Any = None,
    profile: str | None = None,
    region: str | None = None,
) -> dict[str, str]:
    """Build subprocess environment variables carrying the active AWS session.

    Ensures Terraform uses the exact same credentials, temporary STS tokens,
    or AWS profile that the operator connected via CLI or GUI.
    """
    env = dict(os.environ)
    if region:
        env["AWS_REGION"] = str(region)
        env["AWS_DEFAULT_REGION"] = str(region)

    raw_session = getattr(session, "_session", session)
    extracted = False
    if raw_session is not None and hasattr(raw_session, "get_credentials"):
        try:
            creds = raw_session.get_credentials()
            if creds is not None:
                frozen = creds.get_frozen_credentials()
                if frozen.access_key and frozen.secret_key:
                    env["AWS_ACCESS_KEY_ID"] = frozen.access_key
                    env["AWS_SECRET_ACCESS_KEY"] = frozen.secret_key
                    if frozen.token:
                        env["AWS_SESSION_TOKEN"] = frozen.token
                    else:
                        env.pop("AWS_SESSION_TOKEN", None)
                    env.pop("AWS_PROFILE", None)
                    extracted = True
        except Exception:
            extracted = False

    if not extracted and profile:
        env["AWS_PROFILE"] = str(profile)
    return env


def run(
    directory: str | Path,
    arguments: list[str],
    *,
    timeout: int = 1800,
    env: Mapping[str, str] | None = None,
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
            env=dict(env) if env is not None else None,
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


def init(
    directory: str | Path | None = None,
    *,
    upgrade: bool = False,
    env: Mapping[str, str] | None = None,
) -> TerraformRun:
    arguments = ["init", "-input=false", "-no-color"]
    if upgrade:
        arguments.append("-upgrade")
    return run(workdir(directory), arguments, env=env)


def plan(
    directory: str | Path | None = None,
    variables: Mapping[str, Any] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> TerraformRun:
    return run(
        workdir(directory),
        ["plan", "-input=false", "-no-color", *_var_args(variables)],
        env=env,
    )


def apply(
    directory: str | Path | None = None,
    variables: Mapping[str, Any] | None = None,
    *,
    auto_approve: bool = True,
    timeout: int = 1800,
    env: Mapping[str, str] | None = None,
) -> TerraformRun:
    arguments = ["apply", "-input=false", "-no-color", *_var_args(variables)]
    if auto_approve:
        arguments.append("-auto-approve")
    return run(workdir(directory), arguments, timeout=timeout, env=env)


def destroy(
    directory: str | Path | None = None,
    variables: Mapping[str, Any] | None = None,
    *,
    auto_approve: bool = True,
    timeout: int = 1800,
    env: Mapping[str, str] | None = None,
) -> TerraformRun:
    arguments = ["destroy", "-input=false", "-no-color", *_var_args(variables)]
    if auto_approve:
        arguments.append("-auto-approve")
    return run(workdir(directory), arguments, timeout=timeout, env=env)


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
