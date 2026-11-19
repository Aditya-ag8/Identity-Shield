terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }

  # Local state on purpose. The lab is operated by one person at a time and the
  # state holds no long-lived secrets. Never commit it: *.tfstate is gitignored.
  # If the lab ever gains a second operator, move to an S3 backend with locking
  # before that happens.
}
