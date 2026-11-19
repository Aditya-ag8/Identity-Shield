variable "lab_name" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "data_bucket_arn" {
  description = "Bucket whose object events are captured for T1530."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 30
}
