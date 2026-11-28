"""Live Proxy Traffic Simulator (`proxy/simulator.py`).

Sends real HTTP requests through the live proxy socket (`127.0.0.1:<port>`)
to demonstrate baseline learning, AWS API evasion bursts, kill-chain sequences,
and Cloud Web App attack blocking cleanly in seconds.
"""

from __future__ import annotations

import http.client
from typing import Any


def send_sample_traffic(
    *,
    host: str = "127.0.0.1",
    port: int,
    scenario: str = "mixed",
) -> list[dict[str, Any]]:
    """Fire real HTTP requests through the running LiveSecurityProxy socket."""
    results: list[dict[str, Any]] = []

    def _send(
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> dict[str, Any]:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        conn.request(method, path, body=body or None, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        action = resp.getheader("X-Identity-Shield-Action") or ""
        risk = resp.getheader("X-Identity-Shield-Risk") or ""
        status = resp.status
        conn.close()
        item = {
            "method": method,
            "path": path,
            "status": status,
            "action": action,
            "risk": risk,
            "body_preview": raw[:180],
        }
        results.append(item)
        return item

    if scenario in {"baseline", "mixed"}:
        # 1. Clean baseline traffic from developer tool so Drift detector learns normal profile
        normal_headers = {
            "Authorization": "AWS4-HMAC-SHA256 Credential=AKIADEVOPERATOR1/20261126/eu-west-1/s3/aws4_request",
            "User-Agent": "Boto3/1.34.49 Python/3.11.9",
        }
        for _ in range(3):
            _send("HEAD", "/app-assets-bucket", headers=normal_headers)
        _send("GET", "/api/health", headers={"User-Agent": "Mozilla/5.0", "X-Identity-User": "alice"})

    if scenario in {"aws_attack", "mixed"}:
        # 2. Same developer key suddenly swaps tool -> curl, runs discovery burst -> persistence chain
        aws_attacker = {
            "Authorization": "AWS4-HMAC-SHA256 Credential=AKIADEVOPERATOR1/20261126/us-east-1/iam/aws4_request",
            "User-Agent": "curl/8.4.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        for action_name in (
            "ListUsers",
            "ListRoles",
            "ListAccessKeys",
            "GetAccountAuthorizationDetails",
            "CreateAccessKey",
        ):
            _send(
                "POST",
                "/",
                headers=aws_attacker,
                body=f"Action={action_name}&Version=2010-05-08".encode("utf-8"),
            )

        # S3 data exfiltration attempt via proxy
        _send(
            "GET",
            "/is-lab-crown-jewels/finance/q4.csv",
            headers={
                "Authorization": "AWS4-HMAC-SHA256 Credential=AKIADEVOPERATOR1/20261126/eu-west-1/s3/aws4_request",
                "User-Agent": "curl/8.4.0",
            },
        )

    if scenario in {"webapp_attack", "mixed"}:
        # 3. Cloud Web App auth failure burst (triggers 401 threshold >= 4), sensitive probe & traversal
        for _ in range(5):
            _send(
                "GET",
                "/api/login",
                headers={"User-Agent": "python-requests/2.31", "X-Identity-User": "scanner", "X-Mock-Status": "401"},
            )
        _send(
            "GET",
            "/.env",
            headers={"User-Agent": "python-requests/2.31", "X-Identity-User": "scanner"},
        )
        _send(
            "GET",
            "/api/files?name=../../etc/passwd",
            headers={"User-Agent": "curl/8.4.0", "X-Identity-User": "scanner"},
        )

    if scenario in {"gcp_attack", "multicloud_mixed"}:
        # 4. GCP API discovery -> service account key creation via googleapis headers
        _send(
            "GET",
            "/storage/v1/b/prod-finance-gcs/o",
            headers={
                "Host": "storage.googleapis.com",
                "X-Goog-User-Project": "prod-gcp-101",
                "X-Identity-User": "ci-deployer@prod-gcp-101.iam.gserviceaccount.com",
                "User-Agent": "google-cloud-sdk gcloud/490.0.0",
            },
        )
        _send(
            "POST",
            "/v1/projects/prod-gcp-101/serviceAccounts/admin@prod-gcp-101.iam.gserviceaccount.com/keys",
            headers={
                "Host": "iam.googleapis.com",
                "X-Goog-User-Project": "prod-gcp-101",
                "X-Identity-User": "ci-deployer@prod-gcp-101.iam.gserviceaccount.com",
                "User-Agent": "curl/8.4.0",
                "Content-Type": "application/json",
            },
            body=b'{"keyAlgorithm":"KEY_ALG_RSA_2048"}',
        )

    if scenario in {"azure_attack", "multicloud_mixed"}:
        # 5. Azure ARM role assignment escalation + KeyVault secret read
        _send(
            "PUT",
            "/subscriptions/sub-9999/resourceGroups/rg-prod/providers/Microsoft.Authorization/roleAssignments/backdoor-ra?api-version=2022-04-01",
            headers={
                "Host": "management.azure.com",
                "X-Ms-Client-Request-Id": "req-az-001",
                "X-Identity-User": "devops-spn@contoso.onmicrosoft.com",
                "User-Agent": "AZURECLI/2.64.0",
                "Content-Type": "application/json",
            },
            body=b'{"properties":{"roleDefinitionId":"Owner"}}',
        )
        _send(
            "GET",
            "/secrets/db-master-password?api-version=7.4",
            headers={
                "Host": "corp-prod-kv.vault.azure.net",
                "X-Ms-Client-Request-Id": "req-az-002",
                "X-Identity-User": "devops-spn@contoso.onmicrosoft.com",
                "User-Agent": "python-requests/2.31.0",
            },
        )

    return results
