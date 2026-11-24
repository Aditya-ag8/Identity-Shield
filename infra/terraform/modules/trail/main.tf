# CloudTrail -> S3 -> SQS.
#
# The bucket policy uses a constructed trail ARN rather than aws_cloudtrail.this.arn,
# because the trail depends on the policy. Referencing the resource would create
# a cycle. The construction is stable: CloudTrail trail ARNs are deterministic
# from region, account and name.

data "aws_partition" "current" {}

locals {
  bucket_name = "${var.lab_name}-cloudtrail-${var.account_id}"
  trail_name  = "${var.lab_name}-trail"
  bucket_arn  = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}"
  trail_arn   = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${local.trail_name}"
}

resource "aws_s3_bucket" "trail" {
  bucket = local.bucket_name

  # Deliberate. CloudTrail writes into this bucket continuously, so a normal
  # destroy fails on a non-empty bucket. The cost is that logs die with the
  # bucket, which is why the collector must drain to SQLite before `lab down`.
  force_destroy = true

  tags = {
    Name    = local.bucket_name
    Purpose = "cloudtrail"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.log_retention_days
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = local.bucket_arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${local.bucket_arn}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      }
    ]
  })
}

resource "aws_sqs_queue" "trail" {
  name                      = "${var.lab_name}-cloudtrail-events"
  message_retention_seconds = 86400
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue_policy" "trail" {
  queue_url = aws_sqs_queue.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3Notifications"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.trail.arn
        Condition = { ArnEquals = { "aws:SourceArn" = local.bucket_arn } }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "trail" {
  bucket = aws_s3_bucket.trail.id

  queue {
    queue_arn = aws_sqs_queue.trail.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.trail]
}

resource "aws_cloudtrail" "main" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  # Data events are charged and only T1530 needs them, so the selector is scoped
  # to one bucket. Without this, GetObject produces no log line at all.
  dynamic "advanced_event_selector" {
    for_each = var.enable_data_events ? [1] : []

    content {
      name = "s3-object-events-lab-data"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }

      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }

      field_selector {
        field  = "resources.ARN"
        equals = ["${var.data_bucket_arn}/"]
      }
    }
  }

  # The trail references the bucket id, which already makes Terraform destroy the
  # trail before the bucket. The policy dependency is explicit so the bucket
  # policy exists before CloudTrail is created; without it, creation fails.
  depends_on = [
    aws_s3_bucket_policy.trail,
    aws_s3_bucket_notification.trail,
  ]
}
