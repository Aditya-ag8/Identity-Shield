"""Technique deployment capabilities and live lab feasibility gating.

Evaluates whether each of the eight ATT&CK techniques can be executed live
under the active AWS lab configuration. Prevents running attacks when required
telemetry or target resources are disabled, ensuring disabled services are
marked as unavailable rather than mistakenly recorded as evasions or detections.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class TechniqueCapability:
    technique_id: str
    available: bool
    reason: str
    required_services: tuple[str, ...]
    telemetry_dependency: str
    limitations: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "available": self.available,
            "reason": self.reason,
            "required_services": list(self.required_services),
            "telemetry_dependency": self.telemetry_dependency,
            "limitations": self.limitations,
        }


def check_technique_capability(
    technique_id: str,
    lab_config: Mapping[str, Any],
    *,
    synthetic: bool = False,
) -> TechniqueCapability:
    """Return whether a technique can be executed under the given lab configuration."""
    if synthetic:
        return TechniqueCapability(
            technique_id=technique_id,
            available=True,
            reason="Synthetic rehearsal: offline fixture replay is always available",
            required_services=(),
            telemetry_dependency="fixture_event",
            limitations="Simulated fixture events, no live AWS execution",
        )

    enable_data_events = bool(lab_config.get("enable_data_events", False))
    enable_instance = bool(lab_config.get("enable_instance", False))
    instance_id = str(lab_config.get("instance_id") or "").strip()
    data_bucket = str(lab_config.get("data_bucket") or "").strip()
    test_user = str(lab_config.get("test_user_name") or "is-test-user").strip()
    admin_role = str(lab_config.get("admin_role_name") or "is-admin-role").strip()

    if technique_id in ("T1087.004", "T1526", "T1580"):
        return TechniqueCapability(
            technique_id=technique_id,
            available=True,
            reason="Active CloudTrail management events trail configured",
            required_services=("cloudtrail", "iam", "sts", "ec2", "s3"),
            telemetry_dependency="management_events",
            limitations="Read-only discovery APIs. Probed services without resources return empty or access denied.",
        )

    if technique_id == "T1078.004":
        return TechniqueCapability(
            technique_id=technique_id,
            available=True,
            reason="Authenticated AWS session available for caller identity verification",
            required_services=("sts", "iam"),
            telemetry_dependency="management_events",
            limitations=(
                "Valid cloud account verification uses sts:GetCallerIdentity and iam:ListUsers. "
                "Interactive web console login (ConsoleLogin event) is not performed programmatically."
            ),
        )

    if technique_id == "T1098.001":
        return TechniqueCapability(
            technique_id=technique_id,
            available=True,
            reason=f"Target IAM user {test_user!r} available for credential creation/cleanup",
            required_services=("iam",),
            telemetry_dependency="management_events",
            limitations="Modifications are strictly confined to the test user and immediately cleaned up.",
        )

    if technique_id == "T1098.003":
        return TechniqueCapability(
            technique_id=technique_id,
            available=True,
            reason=f"Target IAM role {admin_role!r} available for role attachment/trust policy modification",
            required_services=("iam",),
            telemetry_dependency="management_events",
            limitations="Modifications are strictly confined to the test admin role and immediately cleaned up.",
        )

    if technique_id == "T1552.005":
        if not enable_instance or not instance_id:
            return TechniqueCapability(
                technique_id=technique_id,
                available=False,
                reason=(
                    "T1552.005 requires an active EC2 target and SSM Run Command (enable_instance=true). "
                    "Instance provisioning is disabled under lab cost controls."
                ),
                required_services=("ec2", "ssm"),
                telemetry_dependency="instance_metadata_and_credentials",
                limitations="Requires live EC2 instance profile and SSM agent.",
            )
        return TechniqueCapability(
            technique_id=technique_id,
            available=True,
            reason=f"EC2 IMDS target {instance_id} enabled and available via SSM",
            required_services=("ec2", "ssm"),
            telemetry_dependency="instance_metadata_and_credentials",
            limitations="IMDS queries execute on-instance; secret material is redacted before database write.",
        )

    if technique_id == "T1530":
        if not enable_data_events:
            return TechniqueCapability(
                technique_id=technique_id,
                available=False,
                reason=(
                    "T1530 requires CloudTrail S3 object-level data events (enable_data_events=true). "
                    "S3 data events are disabled under lab cost controls."
                ),
                required_services=("s3", "cloudtrail"),
                telemetry_dependency="s3_data_events",
                limitations="Without S3 data events enabled in CloudTrail, s3:GetObject is not recorded.",
            )
        return TechniqueCapability(
            technique_id=technique_id,
            available=True,
            reason=f"S3 object-level data events enabled on target bucket {data_bucket!r}",
            required_services=("s3", "cloudtrail"),
            telemetry_dependency="s3_data_events",
            limitations="Requires S3 data event logging enabled for the designated crown jewels bucket.",
        )

    return TechniqueCapability(
        technique_id=technique_id,
        available=False,
        reason=f"Unknown or unsupported technique: {technique_id}",
        required_services=(),
        telemetry_dependency="unknown",
        limitations="Not in the fixed eight-technique scope.",
    )


def capability_matrix(lab_config: Mapping[str, Any], *, synthetic: bool = False) -> dict[str, dict[str, Any]]:
    """Return capability status for all eight in-scope techniques."""
    techniques = [
        "T1087.004",
        "T1526",
        "T1580",
        "T1078.004",
        "T1098.001",
        "T1098.003",
        "T1552.005",
        "T1530",
    ]
    return {
        tech: check_technique_capability(tech, lab_config, synthetic=synthetic).to_dict()
        for tech in techniques
    }
