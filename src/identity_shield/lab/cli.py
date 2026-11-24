"""Lab command line.

    identity-shield lab doctor
    identity-shield lab status
    identity-shield lab census --out data/lab/census-before.json
    identity-shield lab up --yes
    identity-shield lab up --plan
    identity-shield lab down --yes

``up`` and ``down`` change AWS state and therefore require ``--yes``.
``down --check-only`` performs the census half of teardown without destroying
anything, which is what you run before the account exists.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from identity_shield import config
from identity_shield.contracts import ContractError, utc_now, write_json
from identity_shield.lab import census as census_module
from identity_shield.lab import doctor as doctor_module
from identity_shield.lab import provision
from identity_shield.lab.aws import GuardedSession
from identity_shield.lab.destroy import default_report_path, teardown


def _session(region: str | None, profile: str | None = None) -> GuardedSession:
    return GuardedSession(region_name=region, profile_name=profile)


def _session_from_args(args) -> GuardedSession:
    # Handle customer cross-account STS AssumeRole if provided
    role_arn = getattr(args, "role_arn", None)
    external_id = getattr(args, "external_id", None)
    if role_arn:
        import boto3
        from identity_shield.lab import integration

        base = boto3.Session(region_name=getattr(args, "region", None), profile_name=getattr(args, "profile", None))
        assumed = integration.assume_role(base, role_arn, external_id)
        return GuardedSession(session=assumed, region_name=getattr(args, "region", None))
    # Keep the one-argument call compatible with existing integrations/tests;
    # pass a profile only when the operator explicitly selected one.
    return _session(args.region, args.profile) if getattr(args, "profile", None) else _session(args.region)


def _require_credentials(session: GuardedSession) -> bool:
    if session.has_credentials():
        return True
    print(
        "no AWS credentials found. Configure the lab account with AWS_PROFILE or "
        "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, then retry.",
        file=sys.stderr,
    )
    return False


def _parse_vars(pairs: list[str] | None) -> dict[str, str]:
    variables: dict[str, str] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise SystemExit(f"--var expects key=value, got {pair!r}")
        key, value = pair.split("=", 1)
        variables[key.strip()] = value.strip()
    return variables


def _print_census(census, *, title: str) -> None:
    print(title)
    print(f"  account:   {census.account_id}")
    print(f"  region:    {census.region}")
    print(f"  resources: {len(census.resources)}")
    for key, count in census_module.summarise(census).items():
        print(f"    {key:<28} {count}")
    if census.errors:
        print(f"  census errors: {len(census.errors)}")
        for error in census.errors[:10]:
            print(f"    {error['service']}.{error['operation']}: {error['code']}")


def _classify(args) -> int:
    session = _session_from_args(args)
    if not _require_credentials(session):
        return 2
    from identity_shield.lab import integration

    scope = integration.DeploymentScope(args.scope)
    classification = integration.classify_account(session, scope=scope)
    if args.json:
        print(json.dumps(classification.to_dict(), indent=2))
    else:
        print("account classification")
        print(f"  account:        {classification.account_id}")
        print(f"  scope:          {classification.deployment_scope.value}")
        print(f"  org status:     {classification.organization_status.value}")
        if classification.organization_id:
            print(f"  org id:         {classification.organization_id}")
        if classification.management_account_id:
            print(f"  management id:  {classification.management_account_id}")
        print(f"  inspectable:    {'yes' if classification.inspectable else 'no'}")
        if classification.detail:
            print(f"  detail:         {classification.detail}")
    return 0


def _doctor(args) -> int:
    report = doctor_module.run_doctor(
        directory=args.workdir,
        region=args.region,
        session=_session_from_args(args),
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(doctor_module.summarise(report))
    if args.strict and not report.ok:
        return 1
    return 0


def _census(args) -> int:
    session = _session_from_args(args)
    if not _require_credentials(session):
        return 2
    snapshot = census_module.collect(
        session, region=args.region, lab_name=args.lab_name
    )
    if args.out:
        write_json(args.out, snapshot.to_dict())
    if args.json:
        print(json.dumps(snapshot.to_dict(), indent=2))
    else:
        _print_census(snapshot, title="lab census")
        if args.out:
            print(f"\nwritten: {args.out}")
    return 0


def _up(args) -> int:
    if not provision.available():
        print("terraform is not installed or not on PATH", file=sys.stderr)
        print("install it with: winget install Hashicorp.Terraform", file=sys.stderr)
        return 2

    if not args.plan and not args.yes:
        print("refusing to apply without --yes (use --plan to preview)", file=sys.stderr)
        return 2

    variables = _parse_vars(args.var)
    init = provision.init(args.workdir)
    if not init.ok:
        print("terraform init failed:", file=sys.stderr)
        print(init.tail(), file=sys.stderr)
        return 1

    if args.plan:
        result = provision.plan(args.workdir, variables)
        print(result.stdout or result.stderr)
        return 0 if result.ok else 1

    result = provision.apply(args.workdir, variables, timeout=args.timeout)
    if not result.ok:
        print("terraform apply failed:", file=sys.stderr)
        print(result.tail(), file=sys.stderr)
        return 1

    outputs = provision.outputs(args.workdir)
    if args.json:
        print(json.dumps({"terraform": "applied", "outputs": outputs}, indent=2))
    else:
        print("lab applied")
        for key, value in outputs.items():
            print(f"  {key}: {value}")

    session = _session_from_args(args)
    if session.has_credentials():
        snapshot = census_module.collect(session, region=args.region)
        if not args.json:
            print()
            _print_census(snapshot, title="post-apply census")
    return 0


def _down(args) -> int:
    if not provision.available() and not args.check_only:
        print("terraform is not installed", file=sys.stderr)
        print("install it with: winget install Hashicorp.Terraform", file=sys.stderr)
        return 2
    if not args.check_only and not args.yes:
        print("refusing to destroy without --yes (use --check-only to inspect)", file=sys.stderr)
        return 2

    session = _session_from_args(args)
    if not _require_credentials(session):
        return 2

    report_path = Path(args.report) if args.report else default_report_path(
        f"manual-{utc_now().replace('-', '').replace(':', '')[:15]}"
    )
    report = teardown(
        session,
        directory=args.workdir,
        region=args.region,
        lab_name=args.lab_name,
        report_path=report_path,
        check_only=args.check_only,
        attempts=args.attempts,
        timeout=args.timeout,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"run:            {report.run_id}")
        print(f"resources before: {len(report.before)}")
        print(f"resources after:  {len(report.after)}")
        print(f"terraform exit:   {report.terraform_exit_code}")
        print(f"residue:          {len(report.residue)}")
        for resource in report.residue:
            print(f"  SURVIVED {resource.service}/{resource.kind}: {resource.identifier}")
        for note in report.notes:
            print(f"note: {note}")
        print(f"verdict:          {'PASS - zero residue' if report.passed else 'FAIL'}")
        print(f"report:           {report_path}")
    return 0 if report.passed else 1


def _add_classify(commands) -> None:
    classify_parser = commands.add_parser("classify", help="classify account deployment scope and Organizations status")
    classify_parser.add_argument("--region", default=None)
    classify_parser.add_argument("--profile", default=None)
    classify_parser.add_argument("--role-arn", default=None, help="STS AssumeRole ARN")
    classify_parser.add_argument("--external-id", default=None, help="STS AssumeRole External ID")
    classify_parser.add_argument("--scope", default="single_account", choices=["single_account", "organization"])
    classify_parser.add_argument("--json", action="store_true")
    classify_parser.set_defaults(handler=_classify)


def _add_doctor(commands) -> None:
    doctor_parser = commands.add_parser("doctor", help="check Terraform, credentials and organization")
    doctor_parser.add_argument("--workdir", default=None)
    doctor_parser.add_argument("--region", default=None)
    doctor_parser.add_argument("--profile", default=None)
    doctor_parser.add_argument("--json", action="store_true")
    doctor_parser.add_argument("--strict", action="store_true", help="exit non-zero if not ready")
    doctor_parser.set_defaults(handler=_doctor)


def _add_status(commands) -> None:
    status_parser = commands.add_parser("status", help="what exists in the lab right now")
    status_parser.add_argument("--region", default=None)
    status_parser.add_argument("--lab-name", default=None)
    status_parser.add_argument("--profile", default=None)
    status_parser.add_argument("--json", action="store_true")
    status_parser.set_defaults(handler=_census, out=None)


def _add_census(commands) -> None:
    census_parser = commands.add_parser("census", help="write a census snapshot")
    census_parser.add_argument("--region", default=None)
    census_parser.add_argument("--lab-name", default=None)
    census_parser.add_argument("--profile", default=None)
    census_parser.add_argument("--out", default=None)
    census_parser.add_argument("--json", action="store_true")
    census_parser.set_defaults(handler=_census)


def _add_up(commands) -> None:
    up_parser = commands.add_parser("up", help="terraform init + apply")
    up_parser.add_argument("--workdir", default=None)
    up_parser.add_argument("--region", default=None)
    up_parser.add_argument("--profile", default=None)
    up_parser.add_argument("--var", action="append", help="terraform variable as key=value")
    up_parser.add_argument("--plan", action="store_true", help="plan only")
    up_parser.add_argument("--yes", action="store_true", help="confirm apply")
    up_parser.add_argument("--json", action="store_true")
    up_parser.add_argument("--timeout", type=int, default=1800)
    up_parser.set_defaults(handler=_up)


def _add_down(commands) -> None:
    down_parser = commands.add_parser("down", help="terraform destroy + residue check")
    down_parser.add_argument("--workdir", default=None)
    down_parser.add_argument("--region", default=None)
    down_parser.add_argument("--profile", default=None)
    down_parser.add_argument("--lab-name", default=None)
    down_parser.add_argument("--report", default=None)
    down_parser.add_argument("--check-only", action="store_true", help="census only, no destroy")
    down_parser.add_argument("--attempts", type=int, default=3, help="census attempts after destroy")
    down_parser.add_argument("--yes", action="store_true", help="confirm destroy")
    down_parser.add_argument("--json", action="store_true")
    down_parser.add_argument("--timeout", type=int, default=1800)
    down_parser.set_defaults(handler=_down)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="identity-shield lab")
    commands = parser.add_subparsers(dest="command", required=True)
    _add_classify(commands)
    _add_doctor(commands)
    _add_status(commands)
    _add_census(commands)
    _add_up(commands)
    _add_down(commands)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (ContractError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
