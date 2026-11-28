"""State-independent census of the lab account.

Terraform's own state is not evidence. This module enumerates what actually
exists in the account, using APIs only, so that "destroy complete" can be
checked rather than believed. It is the core of the lab deliverable.

Scope
-----
Only resources the lab owns are counted. Ownership is decided by, in order:

* the tag ``identity-shield:lab`` (via the resource tagging API),
* an ``is-`` name prefix, or
* the IAM path prefix ``/identity-shield/``.

That keeps a shared account usable: unrelated buckets and roles in the same
account are ignored, so a residue report says "nothing of ours survived" rather
than "the account is not empty".

Deliberate omissions
--------------------
KMS keys are not enumerated. No lab resource creates one, none of the eight
techniques does either, and scheduled key deletion has a seven-day floor that
would make every teardown report fail for a reason that is not a bug. If a later
technique needs KMS, add it here *and* teach the residue report about the
deletion window.
"""

from __future__ import annotations

from typing import Any, Iterator, Mapping

from identity_shield.contracts import Census, ResourceRef, utc_now
from identity_shield.lab.models import Residue

LAB_TAG_KEY = "identity-shield:lab"
LAB_NAME = "identity-shield"
NAME_PREFIX = "is-"
IAM_PATH_PREFIX = "/identity-shield/"
BUDGET_PREFIX = "identity-shield"


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        return str((response.get("Error") or {}).get("Code") or type(exc).__name__)
    return type(exc).__name__


def _note(errors: list[dict[str, Any]], service: str, operation: str, exc: Exception) -> None:
    errors.append(
        {
            "service": service,
            "operation": operation,
            "code": _error_code(exc),
            "message": str(exc)[:300],
        }
    )


def _paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> list[Any]:
    """Collect every page of a boto3 paginator, or a single page if unsupported."""
    try:
        paginator = client.get_paginator(operation)
    except Exception:
        response = getattr(client, operation)(**kwargs)
        return list(response.get(result_key) or [])

    items: list[Any] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key) or [])
    return items


def _tags(entries: Any) -> dict[str, str]:
    tags: dict[str, str] = {}
    for entry in entries or ():
        if isinstance(entry, Mapping) and entry.get("Key"):
            tags[str(entry["Key"])] = str(entry.get("Value") or "")
    return tags


def parse_arn(arn: str) -> tuple[str, str, str, str | None]:
    """Return ``(service, kind, identifier, region)`` for a resource ARN."""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return ("unknown", "resource", arn, None)
    service, region, resource = parts[2], parts[3] or None, parts[5]
    if service == "s3":
        return ("s3", "bucket", resource, None)
    if "/" in resource:
        kind, _, identifier = resource.partition("/")
    else:
        kind, _, identifier = resource.partition(":")
    return (service, kind or "resource", identifier or resource, region)


def _add(
    bucket: dict[tuple[str, str], ResourceRef],
    resource: ResourceRef,
) -> None:
    bucket.setdefault(resource.key, resource)


def _collect_tagging(
    session: Any, resources: dict[tuple[str, str], ResourceRef], errors: list[dict[str, Any]]
) -> None:
    service = "resourcegroupstaggingapi"
    try:
        client = session.client(service)
        mappings = _paginate(
            client,
            "get_resources",
            "ResourceTagMappingList",
            TagFilters=[{"Key": LAB_TAG_KEY}],
        )
    except Exception as exc:
        _note(errors, service, "get_resources", exc)
        return

    for mapping in mappings:
        arn = str(mapping.get("ResourceARN") or "")
        if not arn:
            continue
        service_name, kind, identifier, region = parse_arn(arn)
        _add(
            resources,
            ResourceRef(
                service=service_name,
                kind=kind,
                identifier=identifier,
                arn=arn,
                region=region,
                tags=_tags(mapping.get("Tags")),
                source="tagging",
            ),
        )


def _collect_s3(
    session: Any,
    resources: dict[tuple[str, str], ResourceRef],
    errors: list[dict[str, Any]],
    prefix: str,
    lab_name: str | None,
) -> None:
    try:
        client = session.client("s3")
        buckets = client.list_buckets().get("Buckets") or []
    except Exception as exc:
        _note(errors, "s3", "list_buckets", exc)
        return

    for bucket in buckets:
        name = str(bucket.get("Name") or "")
        if not name:
            continue
        tags: dict[str, str] = {}
        try:
            tags = _tags(client.get_bucket_tagging(Bucket=name).get("TagSet"))
        except Exception as exc:
            if _error_code(exc) not in ("NoSuchTagSet", "NoSuchBucket"):
                _note(errors, "s3", f"get_bucket_tagging/{name}", exc)
        if (
            name.startswith(prefix)
            or (lab_name and name.startswith(lab_name))
            or LAB_TAG_KEY in tags
        ):
            _add(
                resources,
                ResourceRef(
                    service="s3",
                    kind="bucket",
                    identifier=name,
                    arn=f"arn:aws:s3:::{name}",
                    tags=tags,
                    source="s3",
                ),
            )


def _collect_iam(
    session: Any, resources: dict[tuple[str, str], ResourceRef], errors: list[dict[str, Any]]
) -> None:
    try:
        client = session.client("iam")
    except Exception as exc:  # pragma: no cover - client construction failure
        _note(errors, "iam", "client", exc)
        return

    for operation, key, kind in (
        ("list_roles", "Roles", "role"),
        ("list_users", "Users", "user"),
        ("list_policies", "Policies", "policy"),
        ("list_instance_profiles", "InstanceProfiles", "instance-profile"),
    ):
        try:
            items = _paginate(client, operation, key, PathPrefix=IAM_PATH_PREFIX)
        except Exception as exc:
            _note(errors, "iam", operation, exc)
            continue
        for item in items:
            identifier = str(item.get("RoleName") or item.get("UserName") or item.get("PolicyName") or item.get("InstanceProfileName") or "")
            if not identifier:
                continue
            _add(
                resources,
                ResourceRef(
                    service="iam",
                    kind=kind,
                    identifier=identifier,
                    arn=item.get("Arn") or item.get("InstanceProfileArn"),
                    tags={},
                    source="iam",
                ),
            )


def _collect_cloudtrail(
    session: Any,
    resources: dict[tuple[str, str], ResourceRef],
    errors: list[dict[str, Any]],
    prefix: str,
    lab_name: str | None,
) -> None:
    try:
        client = session.client("cloudtrail")
        trails = client.describe_trails(includeShadowTrails=False).get("trailList") or []
    except Exception as exc:
        _note(errors, "cloudtrail", "describe_trails", exc)
        return

    for trail in trails:
        name = str(trail.get("Name") or "")
        arn = str(trail.get("TrailARN") or "")
        if not name:
            continue
        tags: dict[str, str] = {}
        try:
            tags = _tags(client.list_tags(ResourceId=arn).get("TagsList"))
        except Exception as exc:
            _note(errors, "cloudtrail", f"list_tags/{name}", exc)
        if name.startswith(prefix) or (lab_name and lab_name in name) or LAB_TAG_KEY in tags:
            _add(
                resources,
                ResourceRef(
                    service="cloudtrail",
                    kind="trail",
                    identifier=name,
                    arn=arn,
                    region=trail.get("HomeRegion"),
                    tags=tags,
                    source="cloudtrail",
                ),
            )


def _collect_sqs(
    session: Any,
    resources: dict[tuple[str, str], ResourceRef],
    errors: list[dict[str, Any]],
    prefix: str,
    lab_name: str | None,
    account_id: str,
) -> None:
    try:
        client = session.client("sqs")
        urls = _paginate(
            client, "list_queues", "QueueUrls", QueueNamePrefix=lab_name or prefix
        )
    except Exception as exc:
        _note(errors, "sqs", "list_queues", exc)
        return

    for url in urls:
        name = str(url).rsplit("/", 1)[-1]
        tags: dict[str, str] = {}
        try:
            tags = dict(client.list_queue_tags(QueueUrl=url).get("Tags") or {})
        except Exception as exc:
            _note(errors, "sqs", f"list_queue_tags/{name}", exc)
        _add(
            resources,
            ResourceRef(
                service="sqs",
                kind="queue",
                identifier=name,
                arn=f"arn:aws:sqs:{getattr(session, 'region', '')}:{account_id}:{name}",
                tags=tags,
                source="sqs",
            ),
        )


def _collect_budgets(
    session: Any,
    resources: dict[tuple[str, str], ResourceRef],
    errors: list[dict[str, Any]],
    account_id: str,
    lab_name: str | None,
) -> None:
    if not account_id or account_id == "unknown":
        return
    try:
        # Budgets is a global service whose API endpoint lives in us-east-1.
        client = session.client("budgets", region_name="us-east-1")
        budgets = _paginate(client, "describe_budgets", "Budgets", AccountId=account_id)
    except Exception as exc:
        _note(errors, "budgets", "describe_budgets", exc)
        return

    for budget in budgets:
        name = str(budget.get("BudgetName") or "")
        if not name.startswith(BUDGET_PREFIX) and not (lab_name and lab_name in name):
            continue
        _add(
            resources,
            ResourceRef(
                service="budgets",
                kind="budget",
                identifier=name,
                arn=f"arn:aws:budgets::{account_id}:budget/{name}",
                tags={},
                source="budgets",
            ),
        )


def collect(
    session: Any,
    *,
    region: str | None = None,
    account_id: str | None = None,
    lab_name: str | None = None,
    prefix: str = NAME_PREFIX,
) -> Census:
    """Enumerate lab-owned resources. Never raises for a permission gap."""
    errors: list[dict[str, Any]] = []
    resolved_region = region or getattr(session, "region", None) or ""
    if not resolved_region:
        raise ValueError(
            "no AWS region resolved; pass --region or set AWS_REGION before running the census"
        )
    lab_name = lab_name or LAB_NAME

    if account_id is None:
        try:
            account_id = session.account_id()
        except Exception as exc:
            _note(errors, "sts", "get_caller_identity", exc)
            account_id = "unknown"

    resources: dict[tuple[str, str], ResourceRef] = {}
    _collect_tagging(session, resources, errors)
    _collect_s3(session, resources, errors, prefix, lab_name)
    _collect_iam(session, resources, errors)
    _collect_cloudtrail(session, resources, errors, prefix, lab_name)
    _collect_sqs(session, resources, errors, prefix, lab_name, str(account_id))
    _collect_budgets(session, resources, errors, str(account_id), lab_name)

    census = Census(
        generated_at=utc_now(),
        account_id=str(account_id),
        region=str(resolved_region),
        resources=tuple(
            sorted(resources.values(), key=lambda resource: (resource.service, resource.kind, resource.identifier))
        ),
        errors=tuple(errors),
    )
    census.validate()
    return census


def compare(before: Census, after: Census) -> Residue:
    """What survived, what disappeared, and what appeared during the run."""
    before_keys = {resource.key for resource in before.resources}
    after_keys = {resource.key for resource in after.resources}
    return Residue(
        before=before.resources,
        after=after.resources,
        disappeared=tuple(
            resource for resource in before.resources if resource.key not in after_keys
        ),
        appeared=tuple(
            resource for resource in after.resources if resource.key not in before_keys
        ),
    )


def summarise(census: Census) -> dict[str, int]:
    counts: dict[str, int] = {}
    for resource in census.resources:
        key = f"{resource.service}/{resource.kind}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def iter_services(census: Census) -> Iterator[str]:
    for service in sorted({resource.service for resource in census.resources}):
        yield service


def collect_live_inventory(
    session: Any,
    *,
    region: str | None = None,
    data_bucket: str | None = None,
    data_key: str | None = None,
) -> dict[str, Any]:
    """Read-only deep probe for the Control Plane GUI & CLI live inspector.

    Collects EC2 instance states, SSM online status, CloudTrail trail logging status,
    SQS queue message counts, S3 buckets (and optional target object check), and IAM test principals.
    Never mutates AWS state and gracefully records any permission gaps per service.
    """
    resolved_region = region or getattr(session, "region", None) or "eu-west-1"
    inventory: dict[str, Any] = {
        "region": resolved_region,
        "ec2_instances": [],
        "trails": [],
        "queues": [],
        "buckets": [],
        "iam_roles": [],
        "iam_users": [],
        "errors": [],
    }

    # SSM status map (instance_id -> PingStatus)
    ssm_status: dict[str, dict[str, str]] = {}
    try:
        ssm = session.client("ssm", region_name=resolved_region)
        for info in _paginate(ssm, "describe_instance_information", "InstanceInformationList"):
            iid = info.get("InstanceId")
            if iid:
                ssm_status[str(iid)] = {
                    "ping_status": str(info.get("PingStatus") or "Unknown"),
                    "platform": str(info.get("PlatformName") or ""),
                    "agent_version": str(info.get("AgentVersion") or ""),
                }
    except Exception as exc:  # noqa: BLE001
        _note(inventory["errors"], "ssm", "describe_instance_information", exc)

    # EC2 instances
    try:
        ec2 = session.client("ec2", region_name=resolved_region)
        for res in _paginate(ec2, "describe_instances", "Reservations"):
            for inst in res.get("Instances") or ():
                iid = str(inst.get("InstanceId") or "")
                tags = _tags(inst.get("Tags"))
                profile = inst.get("IamInstanceProfile") or {}
                ssm_info = ssm_status.get(iid, {})
                inventory["ec2_instances"].append(
                    {
                        "instance_id": iid,
                        "name": tags.get("Name") or iid,
                        "state": str((inst.get("State") or {}).get("Name") or "unknown"),
                        "instance_type": str(inst.get("InstanceType") or ""),
                        "private_ip": inst.get("PrivateIpAddress"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "iam_profile": profile.get("Arn"),
                        "ssm_status": ssm_info.get("ping_status", "Not Registered"),
                        "lab_owned": LAB_TAG_KEY in tags or str(tags.get("Name", "")).startswith(NAME_PREFIX),
                    }
                )
    except Exception as exc:  # noqa: BLE001
        _note(inventory["errors"], "ec2", "describe_instances", exc)

    # CloudTrail trails + live logging status
    try:
        ct = session.client("cloudtrail", region_name=resolved_region)
        for trail in ct.describe_trails(includeShadowTrails=False).get("trailList") or ():
            name = str(trail.get("Name") or "")
            is_logging = False
            latest_delivery = None
            has_data_events = False
            try:
                status = ct.get_trail_status(Name=name)
                is_logging = bool(status.get("IsLogging"))
                dt = status.get("LatestDeliveryTime")
                latest_delivery = dt.isoformat() if hasattr(dt, "isoformat") else (str(dt) if dt else None)
            except Exception as exc:  # noqa: BLE001
                _note(inventory["errors"], "cloudtrail", "get_trail_status", exc)
            try:
                selectors = ct.get_event_selectors(TrailName=name)
                for es in selectors.get("EventSelectors") or ():
                    for dr in es.get("DataResources") or ():
                        if dr.get("Type") == "AWS::S3::Object":
                            has_data_events = True
                for aes in selectors.get("AdvancedEventSelectors") or ():
                    for fs in aes.get("FieldSelectors") or ():
                        if "S3" in str(fs.get("Equals") or ""):
                            has_data_events = True
            except Exception:
                pass
            inventory["trails"].append(
                {
                    "name": name,
                    "arn": trail.get("TrailARN"),
                    "s3_bucket": trail.get("S3BucketName"),
                    "home_region": trail.get("HomeRegion"),
                    "multi_region": bool(trail.get("IsMultiRegionTrail")),
                    "is_logging": is_logging,
                    "latest_delivery": latest_delivery,
                    "s3_data_events": has_data_events,
                }
            )
    except Exception as exc:  # noqa: BLE001
        _note(inventory["errors"], "cloudtrail", "describe_trails", exc)

    # SQS queues
    try:
        sqs = session.client("sqs", region_name=resolved_region)
        for url in _paginate(sqs, "list_queues", "QueueUrls"):
            name = str(url).rstrip("/").rsplit("/", 1)[-1]
            msgs = None
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
                ).get("Attributes") or {}
                msgs = int(attrs.get("ApproximateNumberOfMessages", 0))
            except Exception:
                pass
            inventory["queues"].append(
                {
                    "name": name,
                    "url": str(url),
                    "messages_available": msgs,
                    "lab_owned": name.startswith((LAB_NAME, NAME_PREFIX)),
                }
            )
    except Exception as exc:  # noqa: BLE001
        _note(inventory["errors"], "sqs", "list_queues", exc)

    # S3 buckets
    try:
        s3 = session.client("s3", region_name=resolved_region)
        for bucket in s3.list_buckets().get("Buckets") or ():
            name = str(bucket.get("Name") or "")
            target_present = None
            if data_bucket and name == data_bucket and data_key:
                try:
                    s3.head_object(Bucket=name, Key=data_key)
                    target_present = True
                except Exception:
                    target_present = False
            inventory["buckets"].append(
                {
                    "name": name,
                    "lab_owned": name.startswith((NAME_PREFIX, LAB_NAME)) or name == data_bucket,
                    "target_key_present": target_present,
                }
            )
    except Exception as exc:  # noqa: BLE001
        _note(inventory["errors"], "s3", "list_buckets", exc)

    # IAM users & roles (filtered to lab-relevant or capped preview)
    try:
        iam = session.client("iam", region_name=resolved_region)
        for u in _paginate(iam, "list_users", "Users"):
            uname = str(u.get("UserName") or "")
            arn = str(u.get("Arn") or "")
            inventory["iam_users"].append(
                {
                    "name": uname,
                    "arn": arn,
                    "lab_owned": uname.startswith((NAME_PREFIX, LAB_NAME)) or IAM_PATH_PREFIX in arn,
                }
            )
        for r in _paginate(iam, "list_roles", "Roles"):
            rname = str(r.get("RoleName") or "")
            arn = str(r.get("Arn") or "")
            if rname.startswith((NAME_PREFIX, LAB_NAME, "IdentityShield")) or IAM_PATH_PREFIX in arn:
                inventory["iam_roles"].append(
                    {
                        "name": rname,
                        "arn": arn,
                        "lab_owned": True,
                    }
                )
    except Exception as exc:  # noqa: BLE001
        _note(inventory["errors"], "iam", "list_roles", exc)

    return inventory
