"""Trial cleanup and residue check.

Cleanup is explicit first (delete the key we created, detach the policy we
attached) and tag-based second (find anything still carrying the run tag). A
trial that fails cleanup is a failed trial even if the attack succeeded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

import json


@dataclass
class SweepReport:
    cleaned: list[str] = field(default_factory=list)
    failed: list[dict[str, str]] = field(default_factory=list)
    residue: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed and not self.residue

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "cleaned": list(self.cleaned),
            "failed": list(self.failed),
            "residue": list(self.residue),
        }


def cleanup_actions(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    actions = evidence.get("cleanup") or []
    return [dict(action) for action in actions if isinstance(action, Mapping)]


def _client(session, service: str, region: str):
    return session.client(service, region_name=region)


def sweep(session, actions: list[Mapping[str, Any]], *, region: str) -> SweepReport:
    report = SweepReport()
    if session is None:
        return report
    for action in actions:
        kind = str(action.get("kind") or "")
        try:
            if kind == "iam_access_key":
                _client(session, "iam", region).delete_access_key(
                    UserName=str(action.get("user")), AccessKeyId=str(action.get("key_id"))
                )
            elif kind == "iam_login_profile":
                _client(session, "iam", region).delete_login_profile(
                    UserName=str(action.get("user"))
                )
            elif kind == "iam_role_policy":
                _client(session, "iam", region).detach_role_policy(
                    RoleName=str(action.get("role")), PolicyArn=str(action.get("policy_arn"))
                )
            elif kind == "iam_trust_policy":
                original = action.get("original_document")
                if original:
                    _client(session, "iam", region).update_assume_role_policy(
                        RoleName=str(action.get("role")),
                        PolicyDocument=json.dumps(original),
                    )
            else:
                # Unknown action types are reported, not silently skipped.
                report.failed.append({"kind": kind, "detail": "no cleanup handler"})
                continue
            report.cleaned.append(kind)
        except Exception as exc:  # noqa: BLE001
            report.failed.append({"kind": kind, "detail": f"{type(exc).__name__}: {exc}"})
    return report


def find_residue(session, *, run_id: str, region: str) -> list[str]:
    if session is None:
        return []
    try:
        response = _client(session, "resourcegroupstaggingapi", region).get_resources(
            TagFilters=[{"Key": "identity-shield:run_id", "Values": [run_id]}]
        )
    except Exception:  # noqa: BLE001 - absence of the API is not proof of residue
        return []
    return [
        str(row.get("ResourceARN"))
        for row in response.get("ResourceTagMappingList", [])
        if row.get("ResourceARN")
    ]
