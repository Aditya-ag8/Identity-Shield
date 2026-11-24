variable "lab_name" {
  type = string
}

variable "region" {
  type = string
}

variable "data_bucket_name" {
  description = "Globally unique bucket name used as the T1530 target."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "enable_instance" {
  type    = bool
  default = false
}
