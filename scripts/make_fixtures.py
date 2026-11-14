"""Generate the M0 CloudTrail fixtures.

Run with::

    .\\.venv\\Scripts\\python.exe scripts\\make_fixtures.py

The JSON files under ``fixtures/cloudtrail/`` are the source of truth; this
script exists so that new fixtures are added with identical CloudTrail
scaffolding rather than drifting in shape. It overwrites files.

IMPORTANT: these fixtures are written from AWS documentation, not captured from
a live account. They are provisional until replaced by real captures at M5.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "fixtures" / "cloudtrail"

ACCOUNT = "123456789012"
REGION = "eu-west-1"

CLI_UA = "aws-cli/2.15.30 Python/3.11.9 Windows/10 exe/AMD64 prompt/off"
BOTO_UA = "Boto3/1.34.49 md/Botocore#1.34.49 ua/2.0 os/windows#10 md/arch#amd64 lang/python#3.11.9"
TF_UA = "APN/1.0 HashiCorp/1.0 Terraform/1.7.5 (+https://www.terraform.io) terraform-provider-aws/5.40.0"
STRATUS_UA = "stratus-red-team/2.11.0"
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


def event_id(technique: str, flavour: str) -> str:
    return hashlib.sha256(f"{technique}/{flavour}".encode()).hexdigest()[:32]


def request_id(seed: str) -> str:
    return hashlib.sha256(f"req/{seed}".encode()).hexdigest()[:32].upper()


def user_identity(kind: str, *, user: str = "is-operator", role: str = "is-operator-role") -> dict:
    if kind == "iam_user":
        return {
            "type": "IAMUser",
            "principalId": "AIDAISLABUSER0001",
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
            "accountId": ACCOUNT,
            "accessKeyId": "AKIAISLABUSER0001",
            "userName": user,
        }
    if kind == "assumed_role":
        return {
            "type": "AssumedRole",
            "principalId": f"AROAISLABROLE0001:{user}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{user}",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAISLABSESSION01",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAISLABROLE0001",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
                    "accountId": ACCOUNT,
                    "userName": role,
                },
                "attributes": {"mfaAuthenticated": "false", "creationDate": "2026-11-03T08:58:11Z"},
            },
        }
    if kind == "instance_profile":
        return {
            "type": "AssumedRole",
            "principalId": "AROAISEC2ROLE0001:i-0abc123def456",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-ec2-role/i-0abc123def456",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAISEC2SESSION01",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAISEC2ROLE0001",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/is-ec2-role",
                    "accountId": ACCOUNT,
                    "userName": "is-ec2-role",
                },
                "attributes": {"mfaAuthenticated": "false", "creationDate": "2026-11-03T09:02:44Z"},
            },
        }
    if kind == "federated":
        return {
            "type": "AssumedRole",
            "principalId": "AROAISFEDROLE0001:aditya@example.edu",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-sso-role/aditya@example.edu",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAISFEDSESSION01",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAISFEDROLE0001",
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/is-sso-role",
                    "accountId": ACCOUNT,
                    "userName": "is-sso-role",
                },
                "attributes": {"mfaAuthenticated": "true", "creationDate": "2026-11-03T09:05:02Z"},
            },
        }
    raise ValueError(kind)


def base(
    technique: str,
    flavour: str,
    *,
    event_source: str,
    event_name: str,
    event_time: str,
    identity: dict,
    source_ip: str,
    user_agent: str,
    request_parameters: dict | None = None,
    response_elements: dict | None = None,
    error_code: str | None = None,
    event_type: str = "AwsApiCall",
    read_only: bool = True,
    category: str = "Management",
    additional: dict | None = None,
    resources: list | None = None,
    region: str = REGION,
) -> dict:
    seed = f"{technique}/{flavour}"
    event: dict = {
        "eventVersion": "1.09",
        "userIdentity": identity,
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "requestParameters": request_parameters,
        "responseElements": response_elements,
        "requestID": request_id(seed),
        "eventID": event_id(technique, flavour),
        "readOnly": read_only,
        "eventType": event_type,
        "managementEvent": category == "Management",
        "recipientAccountId": ACCOUNT,
        "eventCategory": category,
    }
    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = f"{event_name} is not authorized"
    if additional:
        event["additionalEventData"] = additional
    if resources:
        event["resources"] = resources
    event["tlsDetails"] = {
        "tlsVersion": "TLSv1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "clientProvidedHostHeader": f"{event_source.replace('.amazonaws.com', '')}.eu-west-1.amazonaws.com",
    }
    return event


FIXTURES: dict[str, dict[str, dict]] = {}

# --- T1087.004 Cloud Account Discovery -------------------------------------

FIXTURES["T1087.004"] = {
    "catch": base(
        "T1087.004", "catch",
        event_source="iam.amazonaws.com",
        event_name="ListUsers",
        event_time="2026-11-03T09:14:22Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=CLI_UA + " command/iam.list-users",
        request_parameters={"maxItems": 100},
    ),
    "obvious": base(
        "T1087.004", "obvious",
        event_source="iam.amazonaws.com",
        event_name="ListRoles",
        event_time="2026-11-03T09:15:04Z",
        identity=user_identity("assumed_role", user="enum-session"),
        source_ip="81.2.69.142",
        user_agent=BOTO_UA,
        request_parameters={"maxItems": 1000},
    ),
    "hard": base(
        "T1087.004", "hard",
        event_source="iam.amazonaws.com",
        event_name="GetAccountAuthorizationDetails",
        event_time="2026-11-03T03:41:57Z",
        identity=user_identity("federated"),
        source_ip="81.2.69.142",
        user_agent=BOTO_UA,
        request_parameters={"filter": ["User", "Role", "Group", "LocalManagedPolicy"]},
    ),
}

# --- T1526 Cloud Service Discovery -----------------------------------------

FIXTURES["T1526"] = {
    "catch": base(
        "T1526", "catch",
        event_source="ec2.amazonaws.com",
        event_name="DescribeInstances",
        event_time="2026-11-03T10:02:11Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters={"instancesSet": {}, "filterSet": {}},
    ),
    "obvious": base(
        "T1526", "obvious",
        event_source="ec2.amazonaws.com",
        event_name="DescribeInstances",
        event_time="2026-11-03T22:47:35Z",
        identity=user_identity("assumed_role", user="sweep-session"),
        source_ip="81.2.69.142",
        user_agent=CLI_UA + " command/ec2.describe-instances",
        request_parameters={"instancesSet": {}, "filterSet": {}},
    ),
    "hard": base(
        "T1526", "hard",
        event_source="s3.amazonaws.com",
        event_name="ListBuckets",
        event_time="2026-11-03T10:03:48Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters=None,
    ),
}

# --- T1580 Cloud Infrastructure Discovery ----------------------------------

FIXTURES["T1580"] = {
    "catch": base(
        "T1580", "catch",
        event_source="ec2.amazonaws.com",
        event_name="DescribeSecurityGroups",
        event_time="2026-11-03T10:11:09Z",
        identity=user_identity("assumed_role", user="stratus-session"),
        source_ip="52.94.13.7",
        user_agent=STRATUS_UA,
        request_parameters={"securityGroupSet": {}, "filterSet": {}},
    ),
    "obvious": base(
        "T1580", "obvious",
        event_source="ec2.amazonaws.com",
        event_name="DescribeSubnets",
        event_time="2026-11-03T10:11:41Z",
        identity=user_identity("assumed_role", user="stratus-session-2"),
        source_ip="81.2.69.142",
        user_agent=STRATUS_UA,
        request_parameters={"subnetSet": {}, "filterSet": {}},
    ),
    "hard": base(
        "T1580", "hard",
        event_source="s3.amazonaws.com",
        event_name="ListBuckets",
        event_time="2026-11-03T10:12:03Z",
        identity=user_identity("assumed_role", user="stratus-session"),
        source_ip="52.94.13.7",
        user_agent=STRATUS_UA,
        request_parameters=None,
    ),
}

# --- T1078.004 Valid Accounts - Cloud Accounts -----------------------------

FIXTURES["T1078.004"] = {
    "catch": base(
        "T1078.004", "catch",
        event_source="signin.amazonaws.com",
        event_name="ConsoleLogin",
        event_time="2026-11-03T09:31:12Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=CHROME_UA,
        request_parameters=None,
        response_elements={"ConsoleLogin": "Success"},
        event_type="AwsConsoleSignIn",
        read_only=False,
        additional={
            "MobileVersion": "No",
            "MFAUsed": "No",
            "LoginTo": "https://console.aws.amazon.com/console/home",
        },
        region="us-east-1",
    ),
    "obvious": base(
        "T1078.004", "obvious",
        event_source="signin.amazonaws.com",
        event_name="ConsoleLogin",
        event_time="2026-11-03T23:58:40Z",
        identity=user_identity("iam_user", user="is-backup-ops"),
        source_ip="81.2.69.142",
        user_agent=CHROME_UA,
        request_parameters=None,
        response_elements={"ConsoleLogin": "Success"},
        event_type="AwsConsoleSignIn",
        read_only=False,
        additional={
            "MobileVersion": "No",
            "MFAUsed": "No",
            "LoginTo": "https://console.aws.amazon.com/console/home",
        },
        region="us-east-1",
    ),
    "hard": base(
        "T1078.004", "hard",
        event_source="signin.amazonaws.com",
        event_name="ConsoleLogin",
        event_time="2026-11-03T11:04:55Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=CHROME_UA,
        request_parameters=None,
        response_elements={"ConsoleLogin": "Success"},
        event_type="AwsConsoleSignIn",
        read_only=False,
        additional={
            "MobileVersion": "No",
            "MFAUsed": "Yes",
            "LoginTo": "https://console.aws.amazon.com/console/home",
        },
        region="us-east-1",
    ),
}

# --- T1098.001 Additional Cloud Credentials --------------------------------

FIXTURES["T1098.001"] = {
    "catch": base(
        "T1098.001", "catch",
        event_source="iam.amazonaws.com",
        event_name="CreateAccessKey",
        event_time="2026-11-03T10:22:37Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters={"userName": "is-operator"},
        response_elements={
            "accessKey": {
                "userName": "is-operator",
                "accessKeyId": "AKIAISNEWKEY00001",
                "status": "Active",
                "createDate": "Nov 3, 2026 10:22:37 AM",
            }
        },
        read_only=False,
    ),
    "obvious": base(
        "T1098.001", "obvious",
        event_source="iam.amazonaws.com",
        event_name="CreateAccessKey",
        event_time="2026-11-03T02:15:03Z",
        identity=user_identity("assumed_role", user="persist-session"),
        source_ip="81.2.69.142",
        user_agent=BOTO_UA,
        request_parameters={"userName": "TempAdmin"},
        response_elements={
            "accessKey": {
                "userName": "TempAdmin",
                "accessKeyId": "AKIAISNEWKEY00002",
                "status": "Active",
                "createDate": "Nov 3, 2026 2:15:03 AM",
            }
        },
        read_only=False,
    ),
    "hard": base(
        "T1098.001", "hard",
        event_source="iam.amazonaws.com",
        event_name="CreateLoginProfile",
        event_time="2026-11-03T10:24:59Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters={"userName": "is-operator", "password": "****", "passwordResetRequired": "true"},
        response_elements={
            "loginProfile": {
                "userName": "is-operator",
                "createDate": "Nov 3, 2026 10:24:59 AM",
                "passwordResetRequired": "true",
            }
        },
        read_only=False,
    ),
}

# --- T1098.003 Additional Cloud Roles --------------------------------------

FIXTURES["T1098.003"] = {
    "catch": base(
        "T1098.003", "catch",
        event_source="iam.amazonaws.com",
        event_name="AttachRolePolicy",
        event_time="2026-11-03T10:31:18Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters={
            "roleName": "is-app-role",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        read_only=False,
    ),
    "obvious": base(
        "T1098.003", "obvious",
        event_source="iam.amazonaws.com",
        event_name="PutRolePolicy",
        event_time="2026-11-03T04:07:44Z",
        identity=user_identity("assumed_role", user="backdoor-session"),
        source_ip="81.2.69.142",
        user_agent=TF_UA,
        request_parameters={
            "roleName": "is-app-role",
            "policyName": "is-backdoor",
            "policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
        },
        read_only=False,
    ),
    "hard": base(
        "T1098.003", "hard",
        event_source="sts.amazonaws.com",
        event_name="PassRole",
        event_time="2026-11-03T10:33:02Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters={"roleName": "is-admin-role", "roleSessionName": "escalate"},
        read_only=False,
    ),
}

# --- T1552.005 Cloud Instance Metadata API ---------------------------------

FIXTURES["T1552.005"] = {
    "catch": base(
        "T1552.005", "catch",
        event_source="sts.amazonaws.com",
        event_name="GetCallerIdentity",
        event_time="2026-11-03T11:12:26Z",
        identity=user_identity("instance_profile"),
        source_ip="52.94.13.7",
        user_agent=CLI_UA + " command/sts.get-caller-identity",
        request_parameters=None,
        response_elements={
            "userId": "AROAISEC2ROLE0001:i-0abc123def456",
            "account": ACCOUNT,
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-ec2-role/i-0abc123def456",
        },
    ),
    "obvious": base(
        "T1552.005", "obvious",
        event_source="sts.amazonaws.com",
        event_name="GetCallerIdentity",
        event_time="2026-11-03T11:14:52Z",
        identity={
            "type": "AssumedRole",
            "principalId": "AROAISEC2ROLE0001:i-0def456abc789",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-ec2-role/i-0def456abc789",
            "accountId": ACCOUNT,
            "accessKeyId": "ASIAISEC2SESSION02",
        },
        source_ip="81.2.69.142",
        user_agent=CLI_UA + " command/sts.get-caller-identity",
        request_parameters=None,
        response_elements={
            "userId": "AROAISEC2ROLE0001:i-0def456abc789",
            "account": ACCOUNT,
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-ec2-role/i-0def456abc789",
        },
    ),
    "hard": base(
        "T1552.005", "hard",
        event_source="sts.amazonaws.com",
        event_name="GetCallerIdentity",
        event_time="2026-11-03T11:16:07Z",
        identity=user_identity("instance_profile"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters=None,
        response_elements={
            "userId": "AROAISEC2ROLE0001:i-0abc123def456",
            "account": ACCOUNT,
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/is-ec2-role/i-0abc123def456",
        },
    ),
}

# --- T1530 Data from Cloud Storage -----------------------------------------

FIXTURES["T1530"] = {
    "catch": base(
        "T1530", "catch",
        event_source="s3.amazonaws.com",
        event_name="GetObject",
        event_time="2026-11-03T12:02:14Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=BOTO_UA,
        request_parameters={"bucketName": "is-lab-crown-jewels", "key": "finance/q4.csv", "Host": "is-lab-crown-jewels.s3.eu-west-1.amazonaws.com"},
        category="Data",
        resources=[
            {
                "type": "AWS::S3::Object",
                "ARN": "arn:aws:s3:::is-lab-crown-jewels/finance/q4.csv",
                "accountId": ACCOUNT,
            }
        ],
    ),
    "obvious": base(
        "T1530", "obvious",
        event_source="s3.amazonaws.com",
        event_name="GetObject",
        event_time="2026-11-03T01:23:39Z",
        identity=user_identity("assumed_role", user="collect-session"),
        source_ip="81.2.69.142",
        user_agent=CLI_UA + " command/s3.cp",
        request_parameters={"bucketName": "is-lab-crown-jewels", "key": "hr/payroll-2026.xlsx", "Host": "is-lab-crown-jewels.s3.eu-west-1.amazonaws.com"},
        category="Data",
        resources=[
            {
                "type": "AWS::S3::Object",
                "ARN": "arn:aws:s3:::is-lab-crown-jewels/hr/payroll-2026.xlsx",
                "accountId": ACCOUNT,
            }
        ],
    ),
    "hard": base(
        "T1530", "hard",
        event_source="s3.amazonaws.com",
        event_name="ListBucket",
        event_time="2026-11-03T12:01:52Z",
        identity=user_identity("iam_user"),
        source_ip="52.94.13.7",
        user_agent=CLI_UA + " command/s3.ls",
        request_parameters={"bucketName": "is-lab-crown-jewels", "prefix": "finance/", "Host": "is-lab-crown-jewels.s3.eu-west-1.amazonaws.com"},
        category="Data",
        resources=[
            {
                "type": "AWS::S3::Bucket",
                "ARN": "arn:aws:s3:::is-lab-crown-jewels",
                "accountId": ACCOUNT,
            }
        ],
    ),
}


def main() -> None:
    written = 0
    for technique, flavours in FIXTURES.items():
        directory = OUT / technique
        directory.mkdir(parents=True, exist_ok=True)
        for flavour, event in flavours.items():
            path = directory / f"{flavour}.json"
            path.write_text(json.dumps(event, indent=2) + "\n", encoding="utf-8")
            written += 1
    print(f"wrote {written} fixtures under {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
