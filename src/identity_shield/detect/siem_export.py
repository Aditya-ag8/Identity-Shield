"""Modular Multi-Cloud SIEM Query Exporter (`detect/siem_export.py`).

Compiles Identity Shield Sigma AST rules into native SIEM query formats:
- `aws_cloudwatch`: AWS CloudWatch Logs Insights query
- `gcp_logging`: Google Cloud Logging (LQL) filter
- `gcp_secops`: Google SecOps / Chronicle YARA-L 2.0 rule
- `azure_sentinel`: Microsoft Sentinel KQL (`AzureActivity`, `SigninLogs`, `AuditLogs`)

Never claims lossless conversion: any unsupported AST modifier or condition
is reported explicitly in `unsupported_conditions` and `warnings`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from identity_shield.detect.rules import BoolNode, FieldMatch, Node, Rule, UnsupportedRule, load_sigma_text

SIEM_TARGETS = ("aws_cloudwatch", "gcp_logging", "gcp_secops", "azure_sentinel")

_DEFAULT_FIELD_MAPS: dict[str, dict[str, str]] = {
    "aws_cloudwatch": {
        "eventsource": "eventSource",
        "eventname": "eventName",
        "awsregion": "awsRegion",
        "sourceipaddress": "sourceIPAddress",
        "useragent": "userAgent",
        "errorcode": "errorCode",
        "useridentity.arn": "userIdentity.arn",
        "useridentity.type": "userIdentity.type",
        "requestparameters.username": "requestParameters.userName",
        "requestparameters.rolename": "requestParameters.roleName",
        "requestparameters.bucketname": "requestParameters.bucketName",
    },
    "gcp_logging": {
        "eventsource": "protoPayload.serviceName",
        "eventname": "protoPayload.methodName",
        "sourceipaddress": "protoPayload.requestMetadata.callerIp",
        "useragent": "protoPayload.requestMetadata.callerSuppliedUserAgent",
        "useridentity.arn": "protoPayload.authenticationInfo.principalEmail",
        "protopayload.servicename": "protoPayload.serviceName",
        "protopayload.methodname": "protoPayload.methodName",
        "protopayload.status.code": "protoPayload.status.code",
    },
    "gcp_secops": {
        "eventsource": "target.application",
        "eventname": "metadata.product_event_type",
        "sourceipaddress": "principal.ip",
        "useragent": "network.http.user_agent",
        "useridentity.arn": "principal.user.email_addresses",
        "protopayload.servicename": "target.application",
        "protopayload.methodname": "metadata.product_event_type",
        "protopayload.status.code": "security_result.action_details",
        "errorcode": "security_result.action_details",
    },
}

_SENTINEL_TABLE_FIELD_MAPS: dict[str, dict[str, str]] = {
    "AWSCloudTrail": {
        "eventsource": "EventSource",
        "eventname": "EventName",
        "awsregion": "AWSRegion",
        "sourceipaddress": "SourceIpAddress",
        "useragent": "UserAgent",
        "errorcode": "ErrorCode",
        "useridentity.arn": "UserIdentityArn",
        "useridentity.type": "UserIdentityType",
    },
    "SigninLogs": {
        "userprincipalname": "UserPrincipalName",
        "ipaddress": "IPAddress",
        "sourceipaddress": "IPAddress",
        "useridentity.arn": "UserPrincipalName",
        "eventname": "OperationName",
        "conditionalaccessstatus": "ConditionalAccessStatus",
        "status.errorcode": "ResultType",
        "errorcode": "ResultType",
        "authenticationrequirement": "AuthenticationRequirement",
    },
    "AuditLogs": {
        "activitydisplayname": "OperationName",
        "eventname": "OperationName",
        "eventsource": "LoggedByService",
        "result": "Result",
        "useridentity.arn": "InitiatedBy",
        "sourceipaddress": "AdditionalDetails",
    },
    "AzureActivity": {
        "eventsource": "ResourceProviderValue",
        "resourceprovidername.value": "ResourceProviderValue",
        "eventname": "OperationNameValue",
        "operationname.value": "OperationNameValue",
        "sourceipaddress": "CallerIpAddress",
        "useridentity.arn": "Caller",
        "errorcode": "ActivityStatusValue",
        "resulttype": "ActivityStatusValue",
    },
}


@dataclass
class ExportContext:
    target: str
    warnings: list[str]
    unsupported: list[str]
    table: str = ""


def _map_field(path: str, ctx: ExportContext) -> str:
    lower = path.strip().lower()
    if ctx.target == "azure_sentinel":
        tmap = _SENTINEL_TABLE_FIELD_MAPS.get(ctx.table or "AzureActivity", {})
        if lower in tmap:
            return tmap[lower]
        if ctx.table == "AWSCloudTrail" and lower.startswith("requestparameters."):
            return "RequestParameters"
        return path.strip()
    mapping = _DEFAULT_FIELD_MAPS.get(ctx.target, {})
    mapped = mapping.get(lower, path.strip())
    if ctx.target == "gcp_secops" and lower == "protopayload.status.code":
        msg = "GCP integer 'protoPayload.status.code' mapped to string UDM 'security_result.action_details'; verify gRPC status filter against your SecOps parser."
        if msg not in ctx.warnings:
            ctx.warnings.append(msg)
    return mapped


def _escape_double_quoted(val: str) -> str:
    return str(val).replace("\\", "\\\\").replace('"', '\\"')


def _escape_single_quoted(val: str) -> str:
    return str(val).replace("\\", "\\\\").replace("'", "\\'")


def _escape_slash_regex(pattern: str) -> str:
    # Escape unescaped forward slashes so /pattern/ delimiter stays valid in CloudWatch & SecOps YARA-L
    return re.sub(r"(?<!\\)/", r"\/", str(pattern))


def _wildcard_to_regex(pattern: str) -> str:
    parts: list[str] = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return f"^{''.join(parts)}$"


def _emit_field_value(field: str, op: str, val: str, ctx: ExportContext) -> str | None:
    has_wildcards = ("*" in val or "?" in val) and op != "re"
    if ctx.target == "aws_cloudwatch":
        if op == "re":
            return f'{field} =~ /{_escape_slash_regex(val)}/i'
        if op == "regex" or has_wildcards:
            rx = val if op == "regex" else _wildcard_to_regex(val)
            return f'{field} =~ /{_escape_slash_regex(rx)}/i'
        if op == "contains":
            return f'{field} like "{_escape_double_quoted(val)}"'
        if op == "startswith":
            return f'{field} =~ /^{_escape_slash_regex(re.escape(val))}/i'
        if op == "endswith":
            return f'{field} =~ /{_escape_slash_regex(re.escape(val))}$/i'
        return f'{field} = "{_escape_double_quoted(val)}"'

    if ctx.target == "gcp_logging":
        if op in {"re", "regex"}:
            rx = val.strip("^$")
            return f'{field} =~ "{_escape_double_quoted(rx)}"'
        if has_wildcards:
            return f'{field} =~ "{_escape_double_quoted(_wildcard_to_regex(val))}"'
        if op in {"contains", "startswith", "endswith"}:
            escaped = _escape_double_quoted(re.escape(val))
            anchor = f"^{escaped}" if op == "startswith" else (f"{escaped}$" if op == "endswith" else escaped)
            return f'{field} =~ "{anchor}"'
        return f'{field} = "{_escape_double_quoted(val)}"'

    if ctx.target == "gcp_secops":
        udm_field = field if field.startswith("$e.") else f"$e.{field}"
        if op in {"re", "regex"} or has_wildcards:
            rx = val if op in {"re", "regex"} else _wildcard_to_regex(val)
            return f'{udm_field} = /{_escape_slash_regex(rx)}/ nocase'
        if op == "contains":
            return f'strings.contains(strings.to_lower({udm_field}), "{_escape_double_quoted(val.lower())}")'
        if op == "startswith":
            return f'{udm_field} = /^{_escape_slash_regex(re.escape(val))}/ nocase'
        if op == "endswith":
            return f'{udm_field} = /{_escape_slash_regex(re.escape(val))}$/ nocase'
        return f'{udm_field} = "{_escape_double_quoted(val)}" nocase'

    # azure_sentinel (KQL)
    if op in {"re", "regex"}:
        return f'{field} matches regex "{_escape_double_quoted(val)}"'
    if has_wildcards:
        return f'{field} matches regex "{_escape_double_quoted(_wildcard_to_regex(val))}"'
    if op == "contains":
        return f'{field} contains "{_escape_double_quoted(val)}"'
    if op == "startswith":
        return f'{field} startswith "{_escape_double_quoted(val)}"'
    if op == "endswith":
        return f'{field} endswith "{_escape_double_quoted(val)}"'
    return f'{field} =~ "{_escape_double_quoted(val)}"'


def _emit_node(node: Node, ctx: ExportContext) -> str | None:
    and_kw = {"aws_cloudwatch": " and ", "gcp_logging": " AND ", "gcp_secops": " and ", "azure_sentinel": " and "}[ctx.target]
    or_kw = {"aws_cloudwatch": " or ", "gcp_logging": " OR ", "gcp_secops": " or ", "azure_sentinel": " or "}[ctx.target]
    not_kw = {"aws_cloudwatch": "not ", "gcp_logging": "NOT ", "gcp_secops": "not ", "azure_sentinel": "not "}[ctx.target]

    if isinstance(node, FieldMatch):
        mapped = _map_field(node.path, ctx)
        parts: list[str] = []
        for v in node.values:
            expr = _emit_field_value(mapped, node.op, v, ctx)
            if expr is None:
                ctx.unsupported.append(f"{node.path}|{node.op}={v!r}")
                return None
            parts.append(expr)
        if not parts:
            ctx.unsupported.append(f"empty values for {node.path}")
            return None
        if len(parts) == 1:
            return parts[0]
        joiner = and_kw if node.match_all else or_kw
        return f"({joiner.join(parts)})"

    if node.op in {"and", "or"}:
        rendered: list[str] = []
        for child in node.children:
            sub = _emit_node(child, ctx)
            if sub is None:
                return None
            rendered.append(sub)
        if len(rendered) == 1:
            return rendered[0]
        joiner = and_kw if node.op == "and" else or_kw
        return f"({joiner.join(rendered)})"

    if node.op == "not":
        inner = _emit_node(node.children[0], ctx)
        if inner is None:
            return None
        return f"{not_kw}({inner})" if not inner.startswith("(") else f"{not_kw}{inner}"

    if node.op == "at_least":
        if node.count == 1:
            rendered = []
            for child in node.children:
                sub = _emit_node(child, ctx)
                if sub is None:
                    return None
                rendered.append(sub)
            return f"({or_kw.join(rendered)})"
        if node.count == len(node.children):
            rendered = []
            for child in node.children:
                sub = _emit_node(child, ctx)
                if sub is None:
                    return None
                rendered.append(sub)
            return f"({and_kw.join(rendered)})"
        ctx.unsupported.append(f"at_least(count={node.count} of {len(node.children)})")
        return None

    ctx.unsupported.append(f"unsupported boolean node op {node.op!r}")
    return None


def _sentinel_table(rule: Rule) -> str:
    svc = (rule.logsource_service or "").lower()
    if svc == "signinlogs":
        return "SigninLogs"
    if svc == "auditlogs":
        return "AuditLogs"
    if (rule.cloud_provider or "").lower() == "aws":
        return "AWSCloudTrail"
    return "AzureActivity"


def _yara_slug(title: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_")
    return cleaned[:48] or "identity_shield_rule"


def _validate_query(target: str, query: str) -> tuple[bool, list[str]]:
    errs: list[str] = []
    if not query.strip():
        errs.append("empty generated query")
        return False, errs
    if query.count("(") != query.count(")"):
        errs.append("unbalanced parentheses in generated query")
    if target == "gcp_secops" and "rule " not in query:
        errs.append("missing YARA-L rule header")
    if target == "azure_sentinel" and "| where " not in query:
        errs.append("missing KQL '| where' clause")
    if target == "aws_cloudwatch" and "| filter " not in query:
        errs.append("missing CloudWatch Logs Insights '| filter' clause")
    return len(errs) == 0, errs


def export_rule_to_siem(rule: Rule, target: str) -> dict[str, Any]:
    """Translate a compiled Sigma Rule into a target SIEM query with explicit warnings."""
    norm_target = str(target or "").strip().lower()
    if norm_target not in SIEM_TARGETS:
        raise ValueError(f"Unsupported SIEM target {target!r}; expected one of {SIEM_TARGETS}")

    warnings: list[str] = []
    unsupported: list[str] = []

    if rule.loader == "python" or rule.node is None:
        unsupported.append("python_rule_callable_without_sigma_ast")
        return {
            "target": norm_target,
            "rule_id": rule.native_id,
            "title": rule.title,
            "cloud_provider": rule.cloud_provider or "aws",
            "table_or_logsource": "custom_python_rule",
            "query": "",
            "supported": False,
            "valid": False,
            "warnings": ["Python function rules have no Sigma AST and cannot be auto-translated to SIEM syntax."],
            "unsupported_conditions": unsupported,
            "metadata": {"level": rule.level, "technique_id": rule.technique_id},
        }

    expected_cloud = {"aws_cloudwatch": "aws", "gcp_logging": "gcp", "gcp_secops": "gcp", "azure_sentinel": "azure"}[norm_target]
    if rule.cloud_provider and rule.cloud_provider not in {expected_cloud, "generic"}:
        warnings.append(
            f"Cross-cloud schema mismatch: rule targets '{rule.cloud_provider}' while SIEM target expects '{expected_cloud}'. Review field mappings before deploying."
        )

    sentinel_tbl = _sentinel_table(rule) if norm_target == "azure_sentinel" else ""
    ctx = ExportContext(target=norm_target, warnings=warnings, unsupported=unsupported, table=sentinel_tbl)
    expr = _emit_node(rule.node, ctx)
    if expr is None or ctx.unsupported:
        return {
            "target": norm_target,
            "rule_id": rule.native_id,
            "title": rule.title,
            "cloud_provider": rule.cloud_provider or "aws",
            "table_or_logsource": sentinel_tbl if norm_target == "azure_sentinel" else norm_target,
            "query": "",
            "supported": False,
            "valid": False,
            "warnings": warnings + ["Rule uses conditions that cannot be safely translated to this SIEM backend without manual authoring."],
            "unsupported_conditions": list(dict.fromkeys(ctx.unsupported)),
            "metadata": {"level": rule.level, "technique_id": rule.technique_id},
        }

    if norm_target == "aws_cloudwatch":
        table = "AWSCloudTrail"
        query = (
            f"# Identity Shield Export: {rule.title} ({rule.native_id})\n"
            "fields @timestamp, eventSource, eventName, userIdentity.arn, sourceIPAddress, userAgent\n"
            f"| filter {expr}\n"
            "| sort @timestamp desc\n"
            "| limit 200"
        )
    elif norm_target == "gcp_logging":
        table = "cloudaudit.googleapis.com"
        query = (
            f"-- Identity Shield Export: {rule.title} ({rule.native_id})\n"
            f'logName:"cloudaudit.googleapis.com" AND {expr}'
        )
    elif norm_target == "gcp_secops":
        table = "UDM (Google SecOps)"
        query = (
            f"rule {_yara_slug(rule.title)} {{\n"
            "  meta:\n"
            f'    author = "Identity Shield"\n'
            f'    rule_id = "{_escape_double_quoted(rule.native_id)}"\n'
            f'    severity = "{_escape_double_quoted(rule.level)}"\n'
            "  events:\n"
            f"    {expr}\n"
            "  condition:\n"
            "    $e\n"
            "}"
        )
    else:
        table = sentinel_tbl or _sentinel_table(rule)
        proj = {
            "AWSCloudTrail": "TimeGenerated, EventSource, EventName, UserIdentityArn, SourceIpAddress, ErrorCode",
            "AzureActivity": "TimeGenerated, OperationNameValue, Caller, CallerIpAddress, _ResourceId",
            "SigninLogs": "TimeGenerated, UserPrincipalName, IPAddress, ConditionalAccessStatus, ResultType",
            "AuditLogs": "TimeGenerated, OperationName, InitiatedBy, Result",
        }.get(table, "TimeGenerated, OperationName, InitiatedBy, Result")
        query = (
            f"// Identity Shield Export: {rule.title} ({rule.native_id})\n"
            f"{table}\n"
            f"| where {expr}\n"
            f"| project {proj}\n"
            "| sort by TimeGenerated desc"
        )

    valid, val_errors = _validate_query(norm_target, query)
    warnings.extend(val_errors)
    return {
        "target": norm_target,
        "rule_id": rule.native_id,
        "title": rule.title,
        "cloud_provider": rule.cloud_provider or "aws",
        "table_or_logsource": table,
        "query": query,
        "supported": True,
        "valid": valid,
        "warnings": warnings,
        "unsupported_conditions": [],
        "metadata": {"level": rule.level, "technique_id": rule.technique_id},
    }


def export_sigma_yaml_to_siem(yaml_text: str, target: str) -> dict[str, Any]:
    try:
        rule = load_sigma_text(yaml_text)
    except UnsupportedRule as exc:
        return {
            "target": str(target),
            "rule_id": "unparsed",
            "title": "Unsupported Rule",
            "supported": False,
            "valid": False,
            "query": "",
            "warnings": [str(exc)],
            "unsupported_conditions": [str(exc)],
        }
    return export_rule_to_siem(rule, target)
