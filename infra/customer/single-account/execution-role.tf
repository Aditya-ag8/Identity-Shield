# Least-privilege IAM role for controlled lab attack execution.
# Bounded strictly to the 8 in-scope MITRE ATT&CK techniques on lab resources.

data "aws_iam_policy_document" "execution_trust" {
  statement {
    sid     = "STSAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.trusted_principal_arns
    }

    dynamic "condition" {
      for_each = toset(var.external_id != "" ? [var.external_id] : [])
      content {
        test     = "StringEquals"
        variable = "sts:ExternalId"
        values   = [condition.value]
      }
    }
  }
}

resource "aws_iam_role" "execution" {
  name                 = "${var.role_prefix}-execution-role"
  assume_role_policy   = data.aws_iam_policy_document.execution_trust.json
  max_session_duration = 3600

  tags = {
    Project   = "identity-shield"
    Component = "attack-execution"
    ManagedBy = "customer"
  }
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "execution_permissions" {
  # T1087.004 (Account Discovery: IAM User/Role Enumeration)
  statement {
    sid    = "TechniqueT1087004Discovery"
    effect = "Allow"
    actions = [
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:GetAccountAuthorizationDetails",
    ]
    resources = ["*"]
  }

  # T1526 & T1580 (Cloud Service & Infrastructure Discovery)
  statement {
    sid    = "TechniquesDiscoveryInfrastructure"
    effect = "Allow"
    actions = [
      "sts:GetCallerIdentity",
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
      "s3:ListAllMyBuckets",
      "rds:DescribeDBInstances",
    ]
    resources = ["*"]
  }

  # T1078.004 (Valid Accounts caller validation)
  statement {
    sid    = "TechniqueT1078004Validation"
    effect = "Allow"
    actions = [
      "sts:GetCallerIdentity",
      "iam:ListUsers",
    ]
    resources = ["*"]
  }

  # T1098.001 (Additional Cloud Credentials on test user)
  statement {
    sid    = "TechniqueT1098001TestUserCredentials"
    effect = "Allow"
    actions = [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:CreateLoginProfile",
      "iam:DeleteLoginProfile",
      "iam:UpdateLoginProfile",
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/is-test-user*",
    ]
  }

  # T1098.003 (Additional Cloud Roles on admin test role)
  statement {
    sid    = "TechniqueT1098003AdminRoleModification"
    effect = "Allow"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:UpdateAssumeRolePolicy",
      "iam:GetRole",
    ]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/is-admin-role*",
    ]
  }

  # T1552.005 (Cloud Instance Metadata API via SSM Run Command)
  statement {
    sid    = "TechniqueT1552005SSMExecution"
    effect = "Allow"
    actions = [
      "ssm:SendCommand",
      "ssm:GetCommandInvocation",
    ]
    resources = [
      "arn:aws:ssm:*:*:document/AWS-RunShellScript",
      "arn:aws:ec2:*:*:instance/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/Project"
      values   = ["identity-shield"]
    }
  }

  # T1530 (Data from Cloud Storage Object)
  statement {
    sid    = "TechniqueT1530S3Access"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      var.data_bucket_arn,
      "${var.data_bucket_arn}/*",
    ]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "${var.role_prefix}-execution-policy"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_permissions.json
}
