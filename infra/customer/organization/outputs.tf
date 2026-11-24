output "telemetry_role_arn" {
  description = "ARN of the IAM role used by Identity Shield for CloudTrail telemetry collection."
  value       = aws_iam_role.telemetry.arn
}

output "execution_role_arn" {
  description = "ARN of the IAM role used by Identity Shield for controlled lab attack execution."
  value       = aws_iam_role.execution.arn
}

output "account_id" {
  description = "Target customer account ID."
  value       = data.aws_caller_identity.current.account_id
}
