# Least-privilege IAM role for CloudTrail telemetry collection and Organization classification.
# Grants read-only visibility into Organization structure without any policy modification rights.

data "aws_iam_policy_document" "telemetry_trust" {
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

resource "aws_iam_role" "telemetry" {
  name                 = "${var.role_prefix}-org-telemetry-role"
  assume_role_policy   = data.aws_iam_policy_document.telemetry_trust.json
  max_session_duration = 3600

  tags = {
    Project   = "identity-shield"
    Component = "telemetry-collection"
    Scope     = "organization"
    ManagedBy = "customer"
  }
}

data "aws_iam_policy_document" "telemetry_permissions" {
  statement {
    sid    = "ReadCloudTrailLogsS3"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      var.cloudtrail_bucket_arn,
      "${var.cloudtrail_bucket_arn}/*",
    ]
  }

  dynamic "statement" {
    for_each = var.cloudtrail_sqs_queue_arn != "" ? [1] : []
    content {
      sid    = "ConsumeCloudTrailQueue"
      effect = "Allow"
      actions = [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl",
      ]
      resources = [var.cloudtrail_sqs_queue_arn]
    }
  }

  statement {
    sid    = "ReadOnlyCloudTrailStatus"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }

  # Read-only Organization classification (used by classify_account)
  # Note: organizations:ListAccounts succeeds only in management account or delegated administrator;
  # ordinary member accounts gracefully fall back to single-account classification.
  statement {
    sid    = "ReadOnlyOrganizationClassification"
    effect = "Allow"
    actions = [
      "organizations:DescribeOrganization",
      "organizations:ListAccounts",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "telemetry" {
  name   = "${var.role_prefix}-org-telemetry-policy"
  role   = aws_iam_role.telemetry.id
  policy = data.aws_iam_policy_document.telemetry_permissions.json
}
