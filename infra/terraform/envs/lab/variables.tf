variable "region" {
  description = "Primary lab region. The trail is multi-region; this is where resources live."
  type        = string
  default     = "eu-west-1"
}

variable "lab_name" {
  description = "Prefix for every resource this lab creates."
  type        = string
  default     = "identity-shield"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.lab_name))
    error_message = "lab_name must be 3-31 lowercase alphanumeric or hyphen characters, starting with a letter."
  }
}

variable "enable_scps" {
  description = "Attach service control policies. Requires AWS Organizations with all features enabled."
  type        = bool
  default     = false
}

variable "guardrail_target_ids" {
  description = "OU or account IDs to attach SCPs to. Required when enable_scps is true."
  type        = list(string)
  default     = []
}

variable "allowed_regions" {
  description = "Regions permitted by the SCP region lock."
  type        = list(string)
  default     = ["eu-west-1", "us-east-1"]
}

variable "data_bucket_name" {
  description = <<-EOT
    Name of the attack-target bucket. It must be globally unique. The round-1
    T1530 rule hardcodes `is-lab-crown-jewels`, so if that name is taken you must
    change it here AND update conf/rules/baseline/T1530-crown-jewels-read.yml.
  EOT
  type        = string
  default     = "is-lab-crown-jewels"
}

variable "log_retention_days" {
  description = "Days before CloudTrail objects expire. Drag the collector before this."
  type        = number
  default     = 30
}

variable "budget_usd" {
  description = "Monthly budget alarm threshold, in USD."
  type        = number
  default     = 50
}

variable "budget_alert_emails" {
  description = "Addresses that receive the budget alarm. Empty means the budget is recorded but nobody is notified."
  type        = list(string)
  default     = []
}

variable "instance_type" {
  description = "Instance type for the IMDS target. Must be in the SCP allow-list."
  type        = string
  default     = "t3.micro"
}
