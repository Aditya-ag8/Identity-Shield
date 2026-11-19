provider "aws" {
  region = var.region

  default_tags {
    tags = local.common_tags
  }
}

# Budgets is a global service whose API endpoint is in us-east-1.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = local.common_tags
  }
}
