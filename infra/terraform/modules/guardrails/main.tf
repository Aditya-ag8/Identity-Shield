# Service control policies. These are blast-radius controls, not a substitute
# for the IAM permission boundary in the labdata module: SCPs stop the account
# from doing things outside the lab's purpose, while the boundary stops test
# principals from touching resources outside the lab account.
#
# Attach only when the account is inside an AWS Organization with all features
# enabled. `identity-shield lab doctor` reports whether that is true.

locals {
  region_lock = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyRegionsOutsideLab"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions } }
      }
    ]
  })

  service_deny = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyHighRiskServices"
        Effect   = "Deny"
        Action   = var.denied_services
        Resource = "*"
      }
    ]
  })

  spend_guard = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyExpensiveInstances"
        Effect    = "Deny"
        Action    = "ec2:RunInstances"
        Resource  = "*"
        Condition = { StringNotLike = { "ec2:InstanceType" = var.allowed_instance_types } }
      }
    ]
  })
}

resource "aws_organizations_policy" "region_lock" {
  name        = "${var.name_prefix}-region-lock"
  description = "Only approved regions may be used."
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.region_lock
}

resource "aws_organizations_policy" "service_deny" {
  name        = "${var.name_prefix}-service-deny"
  description = "Deny services that are outside the lab's scope or carry unbounded cost."
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.service_deny
}

resource "aws_organizations_policy" "spend_guard" {
  name        = "${var.name_prefix}-spend-guard"
  description = "Only small instance types may be launched."
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.spend_guard
}

resource "aws_organizations_policy_attachment" "region_lock" {
  for_each  = toset(var.target_ids)
  policy_id = aws_organizations_policy.region_lock.id
  target_id = each.value
}

resource "aws_organizations_policy_attachment" "service_deny" {
  for_each  = toset(var.target_ids)
  policy_id = aws_organizations_policy.service_deny.id
  target_id = each.value
}

resource "aws_organizations_policy_attachment" "spend_guard" {
  for_each  = toset(var.target_ids)
  policy_id = aws_organizations_policy.spend_guard.id
  target_id = each.value
}
