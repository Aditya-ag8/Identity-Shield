from __future__ import annotations

import json

import pytest

from identity_shield.contracts import Census, ResourceRef
from identity_shield.lab import census as census_module
from identity_shield.lab import destroy as destroy_module
from identity_shield.lab import doctor as doctor_module
from identity_shield.lab import cli as lab_cli
from identity_shield.lab.aws import GuardedClient, GuardedSession, ReadOnlyViolation
from identity_shield.lab.models import DoctorReport, TerraformRun
from aws_fakes import FakeClient, FakeSession

ACCOUNT = "123456789012"


def _error(code: str) -> Exception:
    exc = RuntimeError(code)
    exc.response = {"Error": {"Code": code}}
    return exc


def _session(**overrides) -> FakeSession:
    buckets = {
        "is-lab-crown-jewels": [],
        "identity-shield-cloudtrail-123456789012": [],
        "someone-elses-bucket": [],
    }

    def bucket_tags(kwargs):
        if kwargs["Bucket"] == "someone-elses-bucket":
            raise _error("NoSuchTagSet")
        return {"TagSet": [{"Key": "Purpose", "Value": "lab"}]}

    clients = {
        "resourcegroupstaggingapi": FakeClient(
            {
                "get_resources": [
                    {
                        "ResourceTagMappingList": [
                            {
                                "ResourceARN": "arn:aws:iam::123456789012:role/identity-shield/extra-role",
                                "Tags": [{"Key": "identity-shield:lab", "Value": "identity-shield"}],
                            }
                        ]
                    }
                ]
            }
        ),
        "s3": FakeClient(
            {
                "list_buckets": {"Buckets": [{"Name": name} for name in buckets]},
                "get_bucket_tagging": bucket_tags,
            }
        ),
        "iam": FakeClient(
            {
                "list_roles": [
                    {
                        "Roles": [
                            {
                                "RoleName": "is-app-role",
                                "Arn": "arn:aws:iam::123456789012:role/identity-shield/is-app-role",
                            }
                        ]
                    }
                ],
                "list_users": [{"Users": [{"UserName": "is-test-user", "Arn": "arn:aws:iam::123456789012:user/identity-shield/is-test-user"}]}],
                "list_policies": [{"Policies": []}],
                "list_instance_profiles": [{"InstanceProfiles": []}],
            }
        ),
        "cloudtrail": FakeClient(
            {
                "describe_trails": {
                    "trailList": [
                        {
                            "Name": "identity-shield-trail",
                            "TrailARN": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/identity-shield-trail",
                            "HomeRegion": "eu-west-1",
                        }
                    ]
                },
                "list_tags": {
                    "TagsList": [{"Key": "identity-shield:lab", "Value": "identity-shield"}]
                },
            }
        ),
        "sqs": FakeClient(
            {
                "list_queues": [
                    {
                        "QueueUrls": [
                            "https://sqs.eu-west-1.amazonaws.com/123456789012/identity-shield-cloudtrail-events"
                        ]
                    }
                ],
                "list_queue_tags": {"Tags": {"identity-shield:lab": "identity-shield"}},
            }
        ),
        "budgets": FakeClient(
            {
                "describe_budgets": [
                    {"Budgets": [{"BudgetName": "identity-shield-monthly"}]}
                ]
            }
        ),
    }
    clients.update(overrides.pop("clients", {}))
    return FakeSession(clients, **overrides)


def _identifiers(census) -> set[str]:
    return {resource.identifier for resource in census.resources}


def test_guarded_client_blocks_mutating_calls():
    client = FakeClient({"list_buckets": {"Buckets": []}})
    guarded = GuardedClient(client, "s3")

    assert guarded.list_buckets() == {"Buckets": []}
    with pytest.raises(ReadOnlyViolation, match="delete_bucket"):
        guarded.delete_bucket(Bucket="x")
    assert client.calls == [("list_buckets", {})]


def test_guarded_session_passes_region_to_clients():
    seen = {}

    class Session:
        region_name = None

        def client(self, service, **kwargs):
            seen[service] = kwargs
            return FakeClient({})

    GuardedSession(Session(), region_name="eu-west-1").client("s3")
    assert seen["s3"]["region_name"] == "eu-west-1"


def test_census_finds_only_lab_owned_resources():
    census = census_module.collect(_session())
    identifiers = _identifiers(census)

    assert census.account_id == ACCOUNT
    assert census.errors == ()
    assert "is-lab-crown-jewels" in identifiers
    assert "identity-shield-cloudtrail-123456789012" in identifiers
    assert "identity-shield-cloudtrail-events" in identifiers
    assert "identity-shield-trail" in identifiers
    assert "is-app-role" in identifiers
    assert "identity-shield-monthly" in identifiers
    assert "identity-shield/extra-role" in identifiers
    assert "someone-elses-bucket" not in identifiers


def test_census_is_sorted_and_summarisable():
    census = census_module.collect(_session())
    keys = [(resource.service, resource.kind, resource.identifier) for resource in census.resources]
    assert keys == sorted(keys)
    summary = census_module.summarise(census)
    assert summary["s3/bucket"] == 2
    assert summary["sqs/queue"] == 1


def test_census_survives_a_failing_service_and_reports_it():
    def raising(_kwargs):
        raise _error("AccessDenied")

    session = _session(clients={"s3": FakeClient({"list_buckets": raising})})
    census = census_module.collect(session)
    assert any(error["service"] == "s3" and error["code"] == "AccessDenied" for error in census.errors)
    # The rest of the census still ran.
    assert "identity-shield-trail" in _identifiers(census)


def test_census_marks_unknown_account_when_sts_fails():
    session = _session(credentials=False)
    census = census_module.collect(session)
    assert census.account_id == "unknown"
    assert any(error["service"] == "sts" for error in census.errors)


def test_compare_separates_survivors_from_disappeared():
    kept = ResourceRef(service="s3", kind="bucket", identifier="is-kept", source="s3")
    gone = ResourceRef(service="iam", kind="role", identifier="is-gone", source="iam")
    new = ResourceRef(service="sqs", kind="queue", identifier="is-new", source="sqs")
    before = Census(generated_at="t0", account_id=ACCOUNT, region="eu-west-1", resources=(kept, gone))
    after = Census(generated_at="t1", account_id=ACCOUNT, region="eu-west-1", resources=(kept, new))

    residue = census_module.compare(before, after)
    # Everything present after teardown is residue: a resource that appeared
    # during the run is just as much a failure as one that survived it.
    assert [r.identifier for r in residue.still_present] == ["is-kept", "is-new"]
    assert [r.identifier for r in residue.disappeared] == ["is-gone"]
    assert [r.identifier for r in residue.appeared] == ["is-new"]
    assert residue.passed is False


def _census(*identifiers: str) -> Census:
    return Census(
        generated_at="t",
        account_id=ACCOUNT,
        region="eu-west-1",
        resources=tuple(
            ResourceRef(service="s3", kind="bucket", identifier=name, source="s3")
            for name in identifiers
        ),
    )


def test_teardown_passes_only_after_a_clean_destroy(monkeypatch, tmp_path):
    before = _census("is-a", "is-b")
    after = _census()
    snapshots = iter([before, after])

    monkeypatch.setattr(
        destroy_module.census_module, "collect", lambda *a, **k: next(snapshots)
    )
    monkeypatch.setattr(
        destroy_module.provision,
        "destroy",
        lambda *a, **k: TerraformRun(command=("terraform", "destroy"), returncode=0),
    )

    report = destroy_module.teardown(
        object(), report_path=tmp_path / "report.json", attempts=1, run_id="lab-1"
    )
    assert report.passed is True
    assert report.terraform_exit_code == 0
    assert report.residue == ()
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["passed"] is True


def test_teardown_fails_when_a_resource_survives(monkeypatch):
    monkeypatch.setattr(
        destroy_module.census_module, "collect", lambda *a, **k: _census("is-a")
    )
    monkeypatch.setattr(
        destroy_module.provision,
        "destroy",
        lambda *a, **k: TerraformRun(command=("terraform", "destroy"), returncode=0),
    )

    report = destroy_module.teardown(object(), attempts=1, run_id="lab-2")
    assert report.passed is False
    assert [resource.identifier for resource in report.residue] == ["is-a"]
    assert any("survived" in note for note in report.notes)


def test_teardown_fails_when_terraform_fails(monkeypatch):
    snapshots = iter([_census("is-a"), _census()])
    monkeypatch.setattr(
        destroy_module.census_module, "collect", lambda *a, **k: next(snapshots)
    )
    monkeypatch.setattr(
        destroy_module.provision,
        "destroy",
        lambda *a, **k: TerraformRun(
            command=("terraform", "destroy"), returncode=1, stderr="bucket not empty"
        ),
    )

    report = destroy_module.teardown(object(), attempts=1, run_id="lab-3")
    assert report.passed is False
    assert report.terraform_exit_code == 1
    assert any("bucket not empty" in note for note in report.notes)


def test_teardown_refuses_to_claim_success_when_the_census_failed(monkeypatch):
    broken = Census(
        generated_at="t",
        account_id=ACCOUNT,
        region="eu-west-1",
        errors=({"service": "s3", "operation": "list_buckets", "code": "AccessDenied"},),
    )
    snapshots = iter([broken, broken])
    monkeypatch.setattr(
        destroy_module.census_module, "collect", lambda *a, **k: next(snapshots)
    )
    monkeypatch.setattr(
        destroy_module.provision,
        "destroy",
        lambda *a, **k: TerraformRun(command=("terraform", "destroy"), returncode=0),
    )

    report = destroy_module.teardown(object(), attempts=1, run_id="lab-4")
    assert report.passed is False
    assert report.census_errors
    assert any("cannot be proven" in note for note in report.notes)


def test_check_only_does_not_destroy_and_cannot_pass(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("terraform destroy must not run during --check-only")

    monkeypatch.setattr(destroy_module.provision, "destroy", forbidden)
    monkeypatch.setattr(
        destroy_module.census_module, "collect", lambda *a, **k: _census("is-a")
    )

    report = destroy_module.teardown(object(), check_only=True, run_id="lab-5")
    assert report.terraform_exit_code is None
    assert report.passed is False


def test_doctor_degrades_without_terraform(tmp_path, monkeypatch):
    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    monkeypatch.setattr(doctor_module.provision, "available", lambda: False)

    report = doctor_module.run_doctor(directory=tmp_path, session=_session())
    checks = {check.name: check for check in report.checks}
    assert checks["terraform"].status == "fail"
    assert checks["terraform"].remedy
    assert checks["credentials"].status == "ok"
    assert report.ok is False


def test_doctor_reports_scp_availability(tmp_path, monkeypatch):
    (tmp_path / "main.tf").write_text("", encoding="utf-8")
    monkeypatch.setattr(doctor_module.provision, "available", lambda: True)
    monkeypatch.setattr(doctor_module.provision, "version", lambda: "1.9.0")

    organizations = FakeClient(
        {
            "describe_organization": {
                "Organization": {"Id": "o-abc123", "FeatureSet": "ALL"}
            }
        }
    )
    session = _session(clients={"organizations": organizations})
    report = doctor_module.run_doctor(directory=tmp_path, session=session)
    checks = {check.name: check for check in report.checks}

    assert report.ok is True
    assert checks["organization"].status == "ok"
    assert "SCPs available" in checks["organization"].detail


def test_lab_cli_runs_doctor_without_nesting_the_command(monkeypatch):
    report = DoctorReport(
        generated_at="2026-01-01T00:00:00Z",
        region="eu-west-1",
        checks=(),
    )
    monkeypatch.setattr(lab_cli.doctor_module, "run_doctor", lambda **_kwargs: report)
    assert lab_cli.main(["doctor", "--json"]) == 0


def test_lab_cli_down_reports_residue_and_exits_nonzero(monkeypatch):
    class Report:
        run_id = "lab-test"
        before = ()
        after = ()
        terraform_exit_code = 0
        residue = ()
        notes = ()
        passed = False

        def to_dict(self):
            return {"passed": False}

    monkeypatch.setattr(lab_cli, "teardown", lambda *_args, **_kwargs: Report())
    monkeypatch.setattr(lab_cli, "_session", lambda _region: _session())

    assert lab_cli.main(["down", "--check-only", "--json"]) == 1
