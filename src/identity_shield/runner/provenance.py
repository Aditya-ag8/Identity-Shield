"""Live factor provenance tracking and classification.

Every attack variation in Identity Shield is systematically audited to record:
1. Requested factor level
2. Actual applied factor level
3. Actual observed factor evidence
4. Mutation classification: 'genuine', 'partial', or 'synthetic-only'

Strictly enforces:
- Regional endpoint modifications are marked as 'partial' (regional endpoint change),
  NOT as network-origin egress changes.
- Setting a User-Agent header via boto3 Config is marked as 'partial'
  (user-agent header mutation), NOT as genuine AWS CLI or Terraform binary execution.
- Missing live infrastructure (NAT gateways, Lambda service mediation) is explicitly
  reported as 'synthetic-only'.
- Timing variations executed synchronously are reported as 'synthetic-only'.
- Principal identity is verified via CloudTrail evidence.
"""

from __future__ import annotations

from typing import Any, Mapping

from identity_shield.runner.models import ExecutionResult, TrialContext


def record_factor_provenance(
    ctx: TrialContext,
    result: ExecutionResult,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Audit and classify the factor mutations for a trial."""
    levels = ctx.variant.factor_levels
    factors: dict[str, dict[str, Any]] = {}
    events = events or result.events

    # 1. client_tool
    req_tool = levels.get("client_tool", "boto3_default")
    if ctx.synthetic:
        factors["client_tool"] = {
            "requested": req_tool,
            "applied": req_tool,
            "observed": (events[0].get("userAgent") if events else None) or req_tool,
            "mutation_type": "synthetic-only",
            "detail": "Synthetic fixture event contains simulated User-Agent string",
        }
    elif req_tool == "boto3_default":
        factors["client_tool"] = {
            "requested": req_tool,
            "applied": "boto3_default",
            "observed": (events[0].get("userAgent") if events else None) or "Boto3/botocore",
            "mutation_type": "genuine",
            "detail": "Standard stock boto3/botocore SDK execution",
        }
    else:
        factors["client_tool"] = {
            "requested": req_tool,
            "applied": f"boto3_with_{req_tool}_user_agent",
            "observed": (events[0].get("userAgent") if events else None) or f"Custom-User-Agent ({req_tool})",
            "mutation_type": "partial",
            "detail": (
                f"User-Agent HTTP header modified via botocore.config.Config(user_agent=...); "
                f"underlying client is Python boto3, NOT a genuine {req_tool} binary process"
            ),
        }

    # 2. network_origin
    req_net = levels.get("network_origin", "nat_a")
    if ctx.synthetic:
        factors["network_origin"] = {
            "requested": req_net,
            "applied": req_net,
            "observed": (events[0].get("sourceIPAddress") if events else None) or req_net,
            "mutation_type": "synthetic-only",
            "detail": "Synthetic fixture event contains simulated source IP/endpoint",
        }
    elif req_net == "alternate_endpoint":
        factors["network_origin"] = {
            "requested": req_net,
            "applied": "regional_endpoint_us_east_1",
            "observed": (events[0].get("awsRegion") if events else None) or "us-east-1",
            "mutation_type": "partial",
            "detail": (
                "Regional endpoint mutated from eu-west-1 to us-east-1 (awsRegion in CloudTrail changed). "
                "Client source IP is NOT modified (origin network path unchanged)"
            ),
        }
    elif req_net in ("nat_a", "nat_b"):
        factors["network_origin"] = {
            "requested": req_net,
            "applied": "runner_host_direct_ip",
            "observed": (events[0].get("sourceIPAddress") if events else None) or "runner_ip",
            "mutation_type": "synthetic-only",
            "detail": "VPC NAT gateways with dedicated Elastic IPs are excluded under lab cost controls",
        }
    else:  # service_mediated
        factors["network_origin"] = {
            "requested": req_net,
            "applied": "runner_host_direct_ip",
            "observed": (events[0].get("sourceIPAddress") if events else None) or "runner_ip",
            "mutation_type": "synthetic-only",
            "detail": "Lambda/ECS service-mediated execution is excluded from current lab scope",
        }

    # 3. identity_context
    req_ident = levels.get("identity_context", "iam_user")
    observed_arn = (
        (events[0].get("userIdentity") or {}).get("arn")
        if events
        else str(result.evidence.get("arn") or "")
    )
    if ctx.synthetic:
        factors["identity_context"] = {
            "requested": req_ident,
            "applied": req_ident,
            "observed": observed_arn or req_ident,
            "mutation_type": "synthetic-only",
            "detail": "Simulated identity in synthetic CloudTrail fixture",
        }
    elif req_ident == "iam_user":
        factors["identity_context"] = {
            "requested": req_ident,
            "applied": "iam_user",
            "observed": observed_arn or f"arn:aws:iam::{ctx.account_id}:user/operator",
            "mutation_type": "genuine",
            "detail": "Long-term IAM user credentials",
        }
    elif req_ident == "assumed_role":
        factors["identity_context"] = {
            "requested": req_ident,
            "applied": "assumed_role",
            "observed": observed_arn or f"arn:aws:sts::{ctx.account_id}:assumed-role/...",
            "mutation_type": "genuine" if "assumed-role" in str(observed_arn) else "partial",
            "detail": "STS AssumeRole session",
        }
    elif req_ident == "instance_profile":
        is_imds = ctx.technique.technique_id == "T1552.005"
        factors["identity_context"] = {
            "requested": req_ident,
            "applied": "instance_profile" if is_imds else "synthetic_instance_profile",
            "observed": observed_arn or "EC2InstanceProfileRole",
            "mutation_type": "genuine" if is_imds else "synthetic-only",
            "detail": "Credentials obtained from EC2 IMDS" if is_imds else "Simulated instance profile",
        }
    else:  # federated_session
        factors["identity_context"] = {
            "requested": req_ident,
            "applied": "synthetic_federated",
            "observed": observed_arn or "FederatedUser",
            "mutation_type": "synthetic-only",
            "detail": "OIDC/SAML live federation identity provider is excluded from current lab scope",
        }

    # 4. timing
    req_timing = levels.get("timing", "business_hours")
    if ctx.synthetic:
        factors["timing"] = {
            "requested": req_timing,
            "applied": req_timing,
            "observed": (events[0].get("eventTime") if events else None) or "synthetic_timestamp",
            "mutation_type": "synthetic-only",
            "detail": "Event timestamp adjusted deterministically in synthetic fixture",
        }
    elif req_timing == "business_hours":
        factors["timing"] = {
            "requested": req_timing,
            "applied": "business_hours",
            "observed": ctx.window_start,
            "mutation_type": "genuine",
            "detail": "Live execution scheduled inside operational window",
        }
    else:
        factors["timing"] = {
            "requested": req_timing,
            "applied": "synchronous_execution",
            "observed": ctx.window_start,
            "mutation_type": "synthetic-only",
            "detail": (
                f"Live trial executed synchronously. Off-hours timing ({req_timing}) "
                "is measured deterministically via synthetic timestamp replay"
            ),
        }

    # 5. api_form
    req_api = levels.get("api_form", "canonical")
    if ctx.synthetic:
        factors["api_form"] = {
            "requested": req_api,
            "applied": req_api,
            "observed": (events[0].get("eventName") if events else None) or req_api,
            "mutation_type": "synthetic-only",
            "detail": "Synthetic event reflects requested API form",
        }
    else:
        factors["api_form"] = {
            "requested": req_api,
            "applied": req_api,
            "observed": result.evidence.get("api_form") or req_api,
            "mutation_type": "genuine",
            "detail": f"Genuinely executed API form mutation ({req_api}) via boto3 executor",
        }

    # Provenance summary counts
    summary = {
        "genuine": sum(1 for f in factors.values() if f["mutation_type"] == "genuine"),
        "partial": sum(1 for f in factors.values() if f["mutation_type"] == "partial"),
        "synthetic_only": sum(1 for f in factors.values() if f["mutation_type"] == "synthetic-only"),
    }

    return {
        "factors": factors,
        "provenance_summary": summary,
        "is_fully_genuine": summary["genuine"] == 5,
        "is_partially_genuine": summary["genuine"] > 0 or summary["partial"] > 0,
    }
