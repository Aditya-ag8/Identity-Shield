variable "name_prefix" {
  type = string
}

variable "allowed_regions" {
  description = "Regions the lab may use."
  type        = list(string)
}

variable "target_ids" {
  description = "OU or account IDs the policies are attached to."
  type        = list(string)
}

variable "denied_services" {
  description = "Service namespaces denied outright: cost and scope control, not capability restriction."
  type        = list(string)
  default = [
    "organizations:*",
    "account:*",
    "billing:*",
    "support:*",
    "route53domains:*",
  ]
}

variable "allowed_instance_types" {
  description = "Instance types permitted by the spend guard."
  type        = list(string)
  default     = ["t3.micro", "t3.small", "t4g.micro", "t4g.small"]
}
