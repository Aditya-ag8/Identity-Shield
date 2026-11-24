variable "trusted_principal_arns" {
  description = "ARNs of trusted IAM principals authorized to assume these roles. Supports local CLI profiles, customer EC2 instance profile roles, or a third-party vendor runner role."
  type        = list(string)

  validation {
    condition     = length(var.trusted_principal_arns) > 0
    error_message = "At least one trusted principal ARN must be specified."
  }
}

variable "external_id" {
  description = "Optional external ID for confused-deputy protection. Recommended for cross-account access; optional when runner operates in the same account."
  type        = string
  default     = ""
  sensitive   = true
}

variable "cloudtrail_bucket_arn" {
  description = "ARN of the S3 bucket where Organization or account CloudTrail delivers logs."
  type        = string
}

variable "cloudtrail_sqs_queue_arn" {
  description = "ARN of the SQS queue delivering CloudTrail S3 notifications (optional if using direct polling)."
  type        = string
  default     = ""
}

variable "data_bucket_arn" {
  description = "ARN of the S3 crown jewels bucket for T1530 testing."
  type        = string
}

variable "role_prefix" {
  description = "Naming prefix for Identity Shield integration IAM roles."
  type        = string
  default     = "identity-shield"
}
