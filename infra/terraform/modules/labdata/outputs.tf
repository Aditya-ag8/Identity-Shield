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
  value = aws_iam_role.ec2.arn
}

output "instance_id" {
  value = aws_instance.lab.id
}
