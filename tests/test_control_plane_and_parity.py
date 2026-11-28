"""End-to-end tests for Control Plane API, CLI parity, custom attacks, variance, and resource binding."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from aws_fakes import FakeClient, FakeSession
from identity_shield import config, ops_cli, settings
from identity_shield.contracts import Variant, spec_hash
from identity_shield.db.connection import connect
from identity_shield.db.init import init_db
from identity_shield.lab import census as census_module
from identity_shield.lab import provision
from identity_shield.runner import orchestrator
from identity_shield.runner.executors import Boto3Executor
from identity_shield.runner.models import TrialContext
from identity_shield.runner.verifiers import verify
from identity_shield.variants.loader import load_catalogue
from identity_shield.web.app import app


class _AsgiHarness:
    """Minimal zero-dependency ASGI caller for testing Starlette routes directly."""

    def __init__(self, asgi_app) -> None:
        self._app = asgi_app

    def _call(self, method: str, url: str, payload: dict | None = None) -> SimpleNamespace:
        split = urlsplit(url)
        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else b""
        headers = [(b"host", b"testserver")]
        if payload is not None:
            headers.append((b"content-type", b"application/json"))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": split.path,
            "raw_path": split.path.encode("ascii"),
            "query_string": split.query.encode("ascii"),
            "headers": headers,
            "client": ("127.0.0.1", 0),
            "server": ("testserver", 80),
        }

        sent = False
        status = 500
        resp_body: list[bytes] = []

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body":
                resp_body.append(message.get("body", b""))

        asyncio.run(self._app(scope, receive, send))
        text = b"".join(resp_body).decode("utf-8", errors="replace")
        return SimpleNamespace(
            status_code=status,
            text=text,
            json=lambda: json.loads(text) if text else {},
        )

    def get(self, url: str) -> SimpleNamespace:
        return self._call("GET", url)

    def post(self, url: str, json: dict | None = None) -> SimpleNamespace:
        return self._call("POST", url, json)

    def put(self, url: str, json: dict | None = None) -> SimpleNamespace:
        return self._call("PUT", url, json)

    def patch(self, url: str, json: dict | None = None) -> SimpleNamespace:
        return self._call("PATCH", url, json)

    def delete(self, url: str) -> SimpleNamespace:
        return self._call("DELETE", url)


client_factory = _AsgiHarness


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    db_path = tmp_path / "control_plane.db"
    cfg_path = tmp_path / "workspace_config.json"
    overrides_path = tmp_path / "attack_overrides.json"
    variants_dir = tmp_path / "variants"
    variants_dir.mkdir(parents=True, exist_ok=True)
    custom_rules_root = tmp_path / "rules" / "custom"

    init_db(db_path, drop=True)
    monkeypatch.setenv("IDENTITY_SHIELD_DB", str(db_path))
    monkeypatch.setenv("IDENTITY_SHIELD_CONFIG", str(cfg_path))
    monkeypatch.setenv("IDENTITY_SHIELD_ATTACK_OVERRIDES", str(overrides_path))
    monkeypatch.setattr(config, "DEFAULT_DB", db_path)
    monkeypatch.setattr(config, "VARIANTS_DIR", variants_dir)
    monkeypatch.setattr(config, "DATA", tmp_path)
    settings.RUNTIME_SESSION.clear()
    return {
        "db": db_path,
        "cfg": cfg_path,
        "overrides": overrides_path,
        "variants_dir": variants_dir,
        "custom_rules_root": custom_rules_root,
    }


def test_web_shell_and_state_bootstrap(isolated_env):
    client = client_factory(app)
    res_html = client.get("/")
    assert res_html.status_code == 200
    assert "Identity Shield" in res_html.text

    res_state = client.get("/api/state")
    assert res_state.status_code == 200
    data = res_state.json()
    assert data["db"]["runs"] == 0
    assert data["db"]["events"] == 0
    assert data["connection"]["connected"] is False

    res_tpl = client.get("/api/connect/templates")
    assert res_tpl.status_code == 200
    assert "single-account" in res_tpl.json()["templates"]
    assert "organization" in res_tpl.json()["templates"]


def test_custom_attack_variance_execution_and_custom_rule_end_to_end(isolated_env):
    client = client_factory(app)

    # 1. Bind target client resource & adjust thresholds
    r_bind = client.post(
        "/api/lab/resources",
        json={"data_bucket": "client-prod-audit-bucket", "region": "us-east-1"},
    )
    assert r_bind.status_code == 200
    assert r_bind.json()["resources"]["data_bucket"] == "client-prod-audit-bucket"

    r_th = client.put(
        "/api/thresholds",
        json={"budget_usd": 25, "min_detection_rate": 0.9, "allowed_regions": ["eu-west-1", "us-east-1"]},
    )
    assert r_th.status_code == 200
    assert r_th.json()["thresholds"]["budget_usd"] == 25.0

    # 2. Add a brand-new custom attack (must also generate its 5-factor variants automatically)
    r_add = client.post(
        "/api/attacks",
        json={
            "technique_id": "T9001.custom",
            "name": "Custom VPC Enumeration",
            "tactic": "discovery",
            "event_names": "DescribeVpcs",
            "service": "ec2",
            "operation": "describe_vpcs",
            "sync_variants": True,
        },
    )
    assert r_add.status_code == 200, r_add.text
    sync = r_add.json()["variant_sync"]
    assert sync["variants_total"] > 0

    # 3. Verify custom attack appears in Attack Studio & Variants Explorer
    attacks = client.get("/api/attacks").json()["attacks"]
    custom = next(a for a in attacks if a["technique_id"] == "T9001.custom")
    assert custom["custom"] is True
    assert custom["enabled"] is True
    assert custom["variant_count"] > 0

    variants = client.get("/api/variants?technique_id=T9001.custom").json()["variants"]
    assert len(variants) > 0
    assert any(v["variant_set"] == "ofat" for v in variants)

    # 4. Author a custom Sigma rule targeting DescribeVpcs under custom-v1
    sigma_yaml = """
title: Detect Custom DescribeVpcs
id: custom-rule-t9001
status: test
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: DescribeVpcs
  condition: selection
level: medium
"""
    r_rule = client.post(
        "/api/rules/custom",
        json={"filename": "custom-t9001", "yaml": sigma_yaml},
    )
    assert r_rule.status_code == 200, r_rule.text

    # 5. Execute the generated custom attack variants through the Campaign Runner + Sigma Replay
    catalogue = load_catalogue()
    custom_tech = catalogue.technique("T9001.custom")
    custom_variants = [
        v for v in (variants[:4])
    ]
    from identity_shield.contracts import Variant as VContract

    v_objs = [
        VContract(
            variant_id=row["variant_id"],
            technique_id=row["technique_id"],
            variant_set=row["variant_set"],
            factor_levels=row["factor_levels"],
            seed=row["seed"],
            spec_sha256=row["spec_sha256"],
        )
        for row in custom_variants
    ]

    conn = connect(isolated_env["db"])
    try:
        camp = orchestrator.run_campaign(
            conn,
            run_id="e2e-custom-1",
            variants=v_objs,
            catalogue=catalogue,
            account_id="123456789012",
            region="us-east-1",
            synthetic=True,
        )
        assert camp.succeeded == len(v_objs)
    finally:
        conn.close()

    r_replay = client.post("/api/rules/replay", json={"ruleset_version": "custom-v1"})
    assert r_replay.status_code == 200
    assert r_replay.json()["replay"]["custom-v1"]["alerts"] >= len(v_objs)

    # 6. Verify Analytics & Logs see the custom execution and alert match
    analytics = client.get("/api/analytics?ruleset=custom-v1&run_id=e2e-custom-1").json()
    assert analytics["summary"]["overall"]["detection_rate"] == 1.0

    logs = client.get("/api/logs?search=DescribeVpcs&alerts_only=true").json()
    assert len(logs["events"]) >= 1
    assert "custom-v1" in logs["events"][0]["matched_rules"]

    # 7. Toggle disable & remove custom attack cleanly
    r_dis = client.patch("/api/attacks/T9001.custom", json={"enabled": False})
    assert r_dis.status_code == 200
    assert "T9001.custom" in r_dis.json()["disabled_techniques"]

    r_del = client.delete("/api/attacks/T9001.custom")
    assert r_del.status_code == 200
    assert r_del.json()["deleted_custom"] is True


def test_custom_boto3_executor_mutates_factors_on_client_resources(isolated_env):
    settings.add_or_update_custom_attack(
        {
            "technique_id": "T9002.bucket",
            "name": "Custom Target Bucket Check",
            "tactic": "collection",
            "event_names": ["HeadBucket"],
            "service": "s3",
            "operation": "head_bucket",
            "kwargs": {"Bucket": "{bucket}"},
        }
    )
    catalogue = load_catalogue()
    tech = catalogue.technique("T9002.bucket")
    variant = Variant(
        variant_id="T9002.bucket-ofat-001",
        technique_id="T9002.bucket",
        variant_set="ofat",
        factor_levels={"client_tool": "aws_cli", "network_origin": "alternate_endpoint"},
        seed=1,
        spec_sha256=spec_hash("T9002.bucket", {"client_tool": "aws_cli", "network_origin": "alternate_endpoint"}),
    )

    s3_fake = FakeClient({"head_bucket": {"ResponseMetadata": {"HTTPStatusCode": 200}}})
    session = FakeSession({"s3": s3_fake}, region="eu-west-1")
    ctx = TrialContext(
        run_id="live-custom",
        variant=variant,
        technique=tech,
        repetition=1,
        account_id="123456789012",
        region="eu-west-1",
        lab={"data_bucket": "client-crown-bucket"},
        synthetic=False,
        session=session,
    )
    res = Boto3Executor().execute(ctx)
    assert res.ok is True
    assert s3_fake.calls == [("head_bucket", {"Bucket": "client-crown-bucket"})]

    ver = verify(ctx, res)
    assert ver.passed is True


def test_provision_aws_env_propagates_sts_credentials_and_profile():
    class FakeCreds:
        def get_frozen_credentials(self):
            class Frozen:
                access_key = "ASIA_TEST_KEY"
                secret_key = "TEST_SECRET"
                token = "TEST_SESSION_TOKEN"

            return Frozen()

    class RawSess:
        def get_credentials(self):
            return FakeCreds()

    env_sts = provision.aws_env(session=RawSess(), region="us-west-2")
    assert env_sts["AWS_ACCESS_KEY_ID"] == "ASIA_TEST_KEY"
    assert env_sts["AWS_SECRET_ACCESS_KEY"] == "TEST_SECRET"
    assert env_sts["AWS_SESSION_TOKEN"] == "TEST_SESSION_TOKEN"
    assert env_sts["AWS_REGION"] == "us-west-2"

    env_prof = provision.aws_env(profile="lab", region="eu-west-1")
    assert env_prof["AWS_PROFILE"] == "lab"
    assert env_prof["AWS_REGION"] == "eu-west-1"


def test_census_live_inventory_probes_ec2_and_ssm():
    session = FakeSession(
        {
            "ssm": FakeClient(
                {
                    "describe_instance_information": [
                        {
                            "InstanceInformationList": [
                                {"InstanceId": "i-111", "PingStatus": "Online", "PlatformName": "Amazon Linux"}
                            ]
                        }
                    ]
                }
            ),
            "ec2": FakeClient(
                {
                    "describe_instances": [
                        {
                            "Reservations": [
                                {
                                    "Instances": [
                                        {
                                            "InstanceId": "i-111",
                                            "State": {"Name": "running"},
                                            "InstanceType": "t3.micro",
                                            "Tags": [{"Key": "Name", "Value": "is-imds-target"}],
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ),
            "cloudtrail": FakeClient(
                {
                    "describe_trails": {"trailList": [{"Name": "client-trail", "S3BucketName": "ct-logs"}]},
                    "get_trail_status": {"IsLogging": True},
                    "get_event_selectors": {"EventSelectors": []},
                }
            ),
            "sqs": FakeClient({"list_queues": [{"QueueUrls": []}], "get_queue_attributes": {}}),
            "s3": FakeClient(
                {
                    "list_buckets": {"Buckets": [{"Name": "client-data"}]},
                    "get_bucket_tagging": {},
                    "head_object": {},
                }
            ),
            "iam": FakeClient({"list_users": [{"Users": []}], "list_roles": [{"Roles": []}]}),
        }
    )
    inv = census_module.collect_live_inventory(
        session, region="eu-west-1", data_bucket="client-data", data_key="finance/q4.csv"
    )
    assert len(inv["ec2_instances"]) == 1
    assert inv["ec2_instances"][0]["state"] == "running"
    assert inv["ec2_instances"][0]["ssm_status"] == "Online"
    assert inv["trails"][0]["is_logging"] is True
    assert inv["buckets"][0]["target_key_present"] is True


def test_cli_parity_attacks_and_config_commands(isolated_env, capsys):
    assert ops_cli.config_main(["thresholds", "--budget-usd", "15", "--allowed-regions", "eu-west-1,ap-south-1"]) == 0
    assert ops_cli.config_main(["bind", "--bucket", "cli-bucket", "--region", "ap-south-1"]) == 0
    _ = capsys.readouterr()
    assert ops_cli.attacks_main(["list", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["attacks"]) >= 8
    assert settings.get_thresholds().budget_usd == 15.0
    assert settings.get_resources().data_bucket == "cli-bucket"
