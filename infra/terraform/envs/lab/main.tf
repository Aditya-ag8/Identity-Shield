locals {
  common_tags = {
    Project               = "identity-shield"
    "identity-shield:lab" = var.lab_name
    ManagedBy             = "terraform"
  }

  scps_enabled = var.enable_scps && length(var.guardrail_target_ids) > 0
}

data "aws_caller_identity" "current" {}

# The target resources come first: the trail needs the data bucket ARN to scope
# its S3 data-event selector.
module "labdata" {
  source = "../../modules/labdata"

  lab_name         = var.lab_name
  region           = var.region
  data_bucket_name = var.data_bucket_name
  instance_type    = var.instance_type
  enable_instance  = var.enable_instance
}

resource "aws_budgets_budget" "lab" {
  count    = var.enable_budget ? 1 : 0
  provider = aws.us_east_1

  name         = "${var.lab_name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = length(var.budget_alert_emails) > 0 ? [1] : []

    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 80
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.budget_alert_emails
    }
  }
}

module "trail" {
  source = "../../modules/trail"

  lab_name           = var.lab_name
  account_id         = data.aws_caller_identity.current.account_id
  region             = var.region
  data_bucket_arn    = module.labdata.data_bucket_arn
  log_retention_days = var.log_retention_days
  enable_data_events = var.enable_data_events
}

module "guardrails" {
  source = "../../modules/guardrails"
  count  = local.scps_enabled ? 1 : 0

  name_prefix     = var.lab_name
  allowed_regions = var.allowed_regions
  target_ids      = var.guardrail_target_ids
}
