output "data_bucket_name" {
  value = aws_s3_bucket.data.id
}

output "data_bucket_arn" {
  value = local.bucket_arn
}

output "boundary_arn" {
  value = aws_iam_policy.boundary.arn
}

output "test_user_arn" {
  value = aws_iam_user.test.arn
}

output "test_user_password" {
  description = "Provider-generated console password for T1078.004. Sensitive; read from Terraform state."
  value       = aws_iam_user_login_profile.test.password
  sensitive   = true
}

output "app_role_arn" {
  value = aws_iam_role.app.arn
}

output "admin_role_arn" {
  value = aws_iam_role.admin.arn
}

output "ec2_role_arn" {
  value = var.enable_instance ? aws_iam_role.ec2[0].arn : null
}

output "instance_id" {
  value = var.enable_instance ? aws_instance.lab[0].id : null
}

output "data_key" {
  description = "Target object key for T1530 data collection."
  value       = aws_s3_object.crown_jewels.key
}
