# Least-privilege IAM role for CloudTrail telemetry collection.
# This role NEVER performs attack actions or modifies security configurations.

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
  name                 = "${var.role_prefix}-telemetry-role"
  assume_role_policy   = data.aws_iam_policy_document.telemetry_trust.json
  max_session_duration = 3600

  tags = {
    Project   = "identity-shield"
    Component = "telemetry-collection"
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
}

resource "aws_iam_role_policy" "telemetry" {
  name   = "${var.role_prefix}-telemetry-policy"
  role   = aws_iam_role.telemetry.id
  policy = data.aws_iam_policy_document.telemetry_permissions.json
}
