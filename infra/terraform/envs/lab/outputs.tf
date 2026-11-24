output "account_id" {
  description = "Lab account the census runs against."
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  value = var.region
}

output "guardrails_enabled" {
  description = "False means the account is standalone, or enable_scps was not set."
  value       = local.scps_enabled
}

output "trail_bucket" {
  value = module.trail.bucket_name
}

output "trail_arn" {
  value = module.trail.trail_arn
}

output "queue_url" {
  description = "SQS queue fed by S3 notifications. The collector will consume this."
  value       = module.trail.queue_url
}

output "data_bucket" {
  description = "Attack-target bucket for T1530."
  value       = module.labdata.data_bucket_name
}

output "data_key" {
  description = "Attack-target S3 object key for T1530."
  value       = module.labdata.data_key
}

output "test_user_arn" {
  value = module.labdata.test_user_arn
}

output "test_user_password" {
  description = "Console password for T1078.004. Sensitive; never commit terraform output."
  value       = module.labdata.test_user_password
  sensitive   = true
}

output "app_role_arn" {
  description = "Low-privilege role the techniques start from."
  value       = module.labdata.app_role_arn
}

output "admin_role_arn" {
  description = "Escalation target for T1098.003. Boundary-limited to the lab account."
  value       = module.labdata.admin_role_arn
}

output "ec2_instance_id" {
  description = "Instance whose IMDS is the target for T1552.005."
  value       = module.labdata.instance_id
}
