"""Decoupled Detection Scoring, Policy Evaluation, and Enforcement Gate (Phase Five)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

# Newly onboarded clouds default to observe-only until enforcement is explicitly enabled.
DEFAULT_PROVIDER_POLICIES: dict[str, str] = {
    "aws": "inherit",      # Inherits proxy_config.mode (observe | block)
    "gcp": "observe",      # Observe-only default until explicitly enabled
    "azure": "observe",    # Observe-only default until explicitly enabled
    "unknown": "inherit",  # Generic http_app / unknown inherits proxy_config.mode
}

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 85.0,
    "high": 70.0,
    "medium": 45.0,
    "low": 25.0,
    "info": 10.0,
}


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    cloud_provider: str
    traffic_type: str
    requested_mode: str
    effective_mode: str
    inspection_capable: bool
    risk_score: float
    action_taken: str      # allowed | alerted | blocked
    policy_decision: str   # allowed | observed | alerted | blocked
    policy_reason: str
    matched_rule_count: int
    evidence_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud_provider": self.cloud_provider,
            "traffic_type": self.traffic_type,
            "requested_mode": self.requested_mode,
            "effective_mode": self.effective_mode,
            "inspection_capable": self.inspection_capable,
            "risk_score": self.risk_score,
            "action_taken": self.action_taken,
            "policy_decision": self.policy_decision,
            "policy_reason": self.policy_reason,
            "matched_rule_count": self.matched_rule_count,
            "evidence_summary": self.evidence_summary,
        }


def compute_risk_score(
    *,
    matched_static: Sequence[Mapping[str, Any]],
    matched_dynamic: Sequence[Mapping[str, Any]],
) -> float:
    """Aggregate static + behavioral detector findings into a bounded [0, 100] score."""
    scores: list[float] = []
    for item in matched_static:
        sev = str(item.get("level") or "medium").lower()
        scores.append(_SEVERITY_WEIGHTS.get(sev, 40.0))

    for item in matched_dynamic:
        sev = str(item.get("severity") or "medium").lower()
        base = _SEVERITY_WEIGHTS.get(sev, 40.0)
        evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
        if evidence.get("cold_start"):
            base *= 0.4
        scores.append(base)

    if not scores:
        return 0.0
    base_max = max(scores)
    extra_bonus = min(30.0, 12.0 * (len(scores) - 1))
    return round(min(100.0, base_max + extra_bonus), 1)


def resolve_effective_mode(
    *,
    cloud_provider: str,
    proxy_mode: str,
    provider_policies: Mapping[str, str] | None = None,
) -> str:
    """Resolve enforcement posture for a given cloud provider."""
    policies = dict(DEFAULT_PROVIDER_POLICIES)
    if provider_policies:
        for k, v in provider_policies.items():
            val = str(v or "").strip().lower()
            if val in {"inherit", "observe", "block"}:
                policies[str(k).lower()] = val

    base_mode = "block" if str(proxy_mode or "").lower() == "block" else "observe"
    override = policies.get(str(cloud_provider or "unknown").lower(), "inherit")
    if override in {"observe", "block"}:
        return override
    return base_mode


def evaluate_policy(
    *,
    cloud_provider: str,
    traffic_type: str,
    proxy_mode: str,
    block_threshold: float,
    matched_static: Sequence[Mapping[str, Any]],
    matched_dynamic: Sequence[Mapping[str, Any]],
    provider_policies: Mapping[str, str] | None = None,
    inspection_capable: bool = True,
    explicit_tunnel_block: bool = False,
) -> PolicyDecision:
    """Evaluate enforcement decision independently of detection rule matching.

    Invariants:
    - A single alert never forces blocking unless risk_score >= block_threshold AND effective_mode == 'block'.
    - Newly added cloud providers ('gcp', 'azure') default to observe-only unless explicitly overridden.
    - Uninspected CONNECT tunnels record 'observed' and cannot be HTTP-403 payload-blocked unless
      explicit tunnel/SSRF deny policy triggers.
    """
    risk_score = compute_risk_score(
        matched_static=matched_static,
        matched_dynamic=matched_dynamic,
    )
    effective_mode = resolve_effective_mode(
        cloud_provider=cloud_provider,
        proxy_mode=proxy_mode,
        provider_policies=provider_policies,
    )
    matched_count = len(matched_static) + len(matched_dynamic)
    threshold = float(block_threshold)

    if not inspection_capable:
        if explicit_tunnel_block:
            return PolicyDecision(
                cloud_provider=cloud_provider,
                traffic_type=traffic_type,
                requested_mode=proxy_mode,
                effective_mode=effective_mode,
                inspection_capable=False,
                risk_score=max(risk_score, 85.0),
                action_taken="blocked",
                policy_decision="blocked",
                policy_reason="Tunnel blocked at CONNECT handshake by SSRF/destination policy.",
                matched_rule_count=matched_count,
                evidence_summary={"tunnel_only": True, "payload_inspected": False},
            )
        if matched_count > 0:
            return PolicyDecision(
                cloud_provider=cloud_provider,
                traffic_type=traffic_type,
                requested_mode=proxy_mode,
                effective_mode=effective_mode,
                inspection_capable=False,
                risk_score=risk_score,
                action_taken="alerted",
                policy_decision="alerted",
                policy_reason="CONNECT metadata matched alert (payload uninspected without TLS interception).",
                matched_rule_count=matched_count,
                evidence_summary={"tunnel_only": True, "payload_inspected": False},
            )
        return PolicyDecision(
            cloud_provider=cloud_provider,
            traffic_type=traffic_type,
            requested_mode=proxy_mode,
            effective_mode=effective_mode,
            inspection_capable=False,
            risk_score=0.0,
            action_taken="allowed",
            policy_decision="observed",
            policy_reason="CONNECT tunnel observed at metadata level (L7 payload uninspected).",
            matched_rule_count=0,
            evidence_summary={"tunnel_only": True, "payload_inspected": False},
        )

    if effective_mode == "block" and risk_score >= threshold and matched_count > 0:
        return PolicyDecision(
            cloud_provider=cloud_provider,
            traffic_type=traffic_type,
            requested_mode=proxy_mode,
            effective_mode=effective_mode,
            inspection_capable=True,
            risk_score=risk_score,
            action_taken="blocked",
            policy_decision="blocked",
            policy_reason=(
                f"Blocked HTTP 403 ({cloud_provider}): risk {risk_score} >= threshold {threshold} "
                f"across {matched_count} finding(s)."
            ),
            matched_rule_count=matched_count,
            evidence_summary={
                "static_ids": [m.get("rule_id") for m in matched_static],
                "dynamic_ids": [m.get("rule_id") for m in matched_dynamic],
            },
        )

    if matched_count > 0:
        if effective_mode != "block" and risk_score >= threshold:
            reason = (
                f"Alerted only ({cloud_provider} policy='{effective_mode}'): "
                f"risk {risk_score} met threshold {threshold}, enforcement held."
            )
        elif proxy_mode == "block" and risk_score < threshold:
            reason = (
                f"Alerted only ({cloud_provider}): {matched_count} rule(s) matched with risk {risk_score} "
                f"below block threshold {threshold}."
            )
        else:
            reason = f"Observed alert ({cloud_provider}): {matched_count} finding(s), risk {risk_score}."
        return PolicyDecision(
            cloud_provider=cloud_provider,
            traffic_type=traffic_type,
            requested_mode=proxy_mode,
            effective_mode=effective_mode,
            inspection_capable=True,
            risk_score=risk_score,
            action_taken="alerted",
            policy_decision="alerted",
            policy_reason=reason,
            matched_rule_count=matched_count,
            evidence_summary={
                "static_ids": [m.get("rule_id") for m in matched_static],
                "dynamic_ids": [m.get("rule_id") for m in matched_dynamic],
            },
        )

    return PolicyDecision(
        cloud_provider=cloud_provider,
        traffic_type=traffic_type,
        requested_mode=proxy_mode,
        effective_mode=effective_mode,
        inspection_capable=True,
        risk_score=risk_score,
        action_taken="allowed",
        policy_decision="allowed",
        policy_reason="Clean request passed static and behavioral checks.",
        matched_rule_count=0,
        evidence_summary={"static_ids": [], "dynamic_ids": []},
    )
