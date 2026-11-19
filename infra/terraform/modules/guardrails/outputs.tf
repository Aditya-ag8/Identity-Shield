output "policy_ids" {
  description = "SCP IDs, in attach order."
  value = [
    aws_organizations_policy.region_lock.id,
    aws_organizations_policy.service_deny.id,
    aws_organizations_policy.spend_guard.id,
  ]
}
