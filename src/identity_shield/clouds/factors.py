"""Provider-aware 5-factor compatibility and semantics matrix across AWS, GCP, and Azure."""

from __future__ import annotations

from typing import Any

# Maps each universal 5-factor axis + level to provider-specific feasibility and log surfaces.
PROVIDER_FACTOR_SUPPORT: dict[str, dict[str, dict[str, dict[str, Any]]]] = {
    "aws": {
        "identity_context": {
            "iam_user": {"supported": True, "surface": "userIdentity.type=IAMUser"},
            "assumed_role": {"supported": True, "surface": "userIdentity.type=AssumedRole"},
            "instance_profile": {"supported": True, "surface": "EC2 instance role credentials"},
            "federated_session": {"supported": True, "surface": "sessionContext.sourceIdentity"},
        },
        "network_origin": {
            "nat_a": {"supported": True, "surface": "sourceIPAddress"},
            "nat_b": {"supported": True, "surface": "sourceIPAddress"},
            "service_mediated": {"supported": True, "surface": "userIdentity.invokedBy=lambda.amazonaws.com"},
            "alternate_endpoint": {"supported": True, "surface": "awsRegion/tlsDetails"},
        },
        "client_tool": {
            "boto3_default": {"supported": True, "ua": "Boto3/1.34.49"},
            "aws_cli": {"supported": True, "ua": "aws-cli/2.15.30"},
            "terraform": {"supported": True, "ua": "Terraform/1.8.0"},
            "non_sdk_http": {"supported": True, "ua": "python-requests/2.31.0"},
        },
        "timing": {
            "business_hours": {"supported": True},
            "off_hours": {"supported": True},
            "burst": {"supported": True},
            "spread": {"supported": True},
        },
        "api_form": {
            "canonical": {"supported": True},
            "alternative_api": {"supported": True},
            "extra_parameters": {"supported": True},
            "batched": {"supported": True},
            "hostile_identifier": {"supported": True},
        },
    },
    "gcp": {
        "identity_context": {
            "iam_user": {"supported": True, "alias": "service_account_key", "surface": "protoPayload.authenticationInfo.serviceAccountKeyName"},
            "assumed_role": {"supported": True, "alias": "sa_impersonation", "surface": "protoPayload.authenticationInfo.serviceAccountDelegationInfo"},
            "instance_profile": {"supported": True, "alias": "gce_metadata_sa", "surface": "GCE metadata attached service account"},
            "federated_session": {"supported": True, "alias": "workload_identity_federation", "surface": "principalSubject (WIF)"},
        },
        "network_origin": {
            "nat_a": {"supported": True, "surface": "requestMetadata.callerIp"},
            "nat_b": {"supported": True, "surface": "requestMetadata.callerIp"},
            "service_mediated": {"supported": True, "alias": "cloud_function_run", "surface": "Cloud Run / Cloud Functions SA"},
            "alternate_endpoint": {"supported": False, "reason": "Most IAM/Cloud Audit APIs in GCP use global googleapis.com endpoints rather than regional CloudTrail hops."},
        },
        "client_tool": {
            "boto3_default": {"supported": True, "alias": "google_cloud_sdk", "ua": "google-api-python-client/2.140.0"},
            "aws_cli": {"supported": True, "alias": "gcloud_cli", "ua": "google-cloud-sdk gcloud/490.0.0"},
            "terraform": {"supported": True, "ua": "Terraform/1.8.0 google/5.40.0"},
            "non_sdk_http": {"supported": True, "ua": "curl/8.4.0"},
        },
        "timing": {
            "business_hours": {"supported": True},
            "off_hours": {"supported": True},
            "burst": {"supported": True},
            "spread": {"supported": True},
        },
        "api_form": {
            "canonical": {"supported": True},
            "alternative_api": {"supported": True},
            "extra_parameters": {"supported": True},
            "batched": {"supported": True},
            "hostile_identifier": {"supported": True},
        },
    },
    "azure": {
        "identity_context": {
            "iam_user": {"supported": True, "alias": "spn_client_secret", "surface": "claims.appid / appDisplayName"},
            "assumed_role": {"supported": True, "alias": "delegated_admin_role", "surface": "Entra privileged role session"},
            "instance_profile": {"supported": True, "alias": "managed_identity", "surface": "Azure VM / App Managed Identity"},
            "federated_session": {"supported": True, "alias": "entra_federated_oidc", "surface": "Entra federated credential / SSO"},
        },
        "network_origin": {
            "nat_a": {"supported": True, "surface": "callerIpAddress / ipAddress"},
            "nat_b": {"supported": True, "surface": "callerIpAddress / ipAddress"},
            "service_mediated": {"supported": True, "alias": "azure_automation_func", "surface": "Azure Functions / Automation Runbook"},
            "alternate_endpoint": {"supported": False, "reason": "ARM management.azure.com and Entra graph.microsoft.com route globally rather than per-region API hostnames."},
        },
        "client_tool": {
            "boto3_default": {"supported": True, "alias": "azure_sdk_python", "ua": "azsdk-python-mgmt-authorization/4.0.0"},
            "aws_cli": {"supported": True, "alias": "az_cli", "ua": "AZURECLI/2.64.0"},
            "terraform": {"supported": True, "ua": "Terraform/1.8.0 azurerm/3.116.0"},
            "non_sdk_http": {"supported": True, "ua": "python-requests/2.31.0"},
        },
        "timing": {
            "business_hours": {"supported": True},
            "off_hours": {"supported": True},
            "burst": {"supported": True},
            "spread": {"supported": True},
        },
        "api_form": {
            "canonical": {"supported": True},
            "alternative_api": {"supported": True},
            "extra_parameters": {"supported": True},
            "batched": {"supported": True},
            "hostile_identifier": {"supported": True},
        },
    },
}


def check_factor_support(cloud_provider: str, factor_levels: dict[str, str]) -> tuple[bool, list[str]]:
    """Return `(all_supported, unsupported_reasons)` for a `(cloud_provider, factor_levels)` combination."""
    cid = str(cloud_provider or "aws").lower()
    matrix = PROVIDER_FACTOR_SUPPORT.get(cid, PROVIDER_FACTOR_SUPPORT["aws"])
    reasons: list[str] = []
    for axis, level in factor_levels.items():
        info = (matrix.get(axis) or {}).get(level)
        if info and not info.get("supported", True):
            reasons.append(f"{cid}:{axis}={level}: {info.get('reason') or 'unsupported on provider'}")
    return (len(reasons) == 0), reasons


def user_agent_for_provider(cloud_provider: str, client_tool_level: str) -> str:
    cid = str(cloud_provider or "aws").lower()
    matrix = PROVIDER_FACTOR_SUPPORT.get(cid, PROVIDER_FACTOR_SUPPORT["aws"]).get("client_tool", {})
    entry = matrix.get(client_tool_level) or matrix.get("boto3_default") or {}
    return str(entry.get("ua") or "python-requests/2.31.0")
