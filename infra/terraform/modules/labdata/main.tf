# The attack target: principals, a data bucket, and one instance whose IMDS is
# the target for T1552.005.
#
# Everything here is intentionally reachable by the eight techniques. The IAM
# permission boundary limits *where* a principal can act (this account only), not
# *what* it can do, so privilege escalation is still possible — which is exactly
# what T1098.003 needs to demonstrate. A restrictive boundary would block the
# technique and be misread as detection.

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  bucket_arn = "arn:${data.aws_partition.current.partition}:s3:::${var.data_bucket_name}"
}

# ---------------------------------------------------------------------------
# Data bucket (T1530 target)
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "data" {
  bucket        = var.data_bucket_name
  force_destroy = true

  tags = {
    Name    = var.data_bucket_name
    Purpose = "attack-target"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Object names match the M0 fixtures on purpose: the same keys appear in
# fixtures/cloudtrail/T1530/*.json, so captured logs and fixtures describe the
# same target.
resource "aws_s3_object" "finance" {
  bucket       = aws_s3_bucket.data.id
  key          = "finance/q4.csv"
  content      = "account,revenue\nnorth,120000\nsouth,98000\n"
  content_type = "text/csv"
}

resource "aws_s3_object" "payroll" {
  bucket       = aws_s3_bucket.data.id
  key          = "hr/payroll-2026.xlsx"
  content      = "placeholder workbook"
  content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
}

# ---------------------------------------------------------------------------
# Permission boundary
# ---------------------------------------------------------------------------

resource "aws_iam_policy" "boundary" {
  name        = "${var.lab_name}-boundary"
  path        = "/identity-shield/"
  description = "Deny-list boundary: keeps principals inside the lab account, blocks cost and log tampering."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyOutsideLabAccount"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        # IfExists matters: aws:ResourceAccount is absent for services such as
        # STS. Without it, GetCallerIdentity would be denied and T1078.004 could
        # never succeed.
        Condition = {
          StringNotEqualsIfExists = { "aws:ResourceAccount" = local.account_id }
        }
      },
      {
        Sid      = "DenyHighRiskServices"
        Effect   = "Deny"
        Action   = ["organizations:*", "account:*", "billing:*", "support:*", "route53domains:*"]
        Resource = "*"
      },
      {
        Sid    = "ProtectEvidence"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors",
        ]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------------

resource "aws_iam_account_password_policy" "lab" {
  minimum_password_length        = 16
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
}

resource "aws_iam_user" "test" {
  name                 = "is-test-user"
  path                 = "/identity-shield/"
  permissions_boundary = aws_iam_policy.boundary.arn

  tags = {
    Purpose = "attack-target"
  }
}

resource "aws_iam_user_login_profile" "test" {
  user                    = aws_iam_user.test.name
  password_length         = 20
  password_reset_required = false
}

# Capability parity, not least privilege: every identity level must be able to
# attempt the same primitive, otherwise a denial from this lab would look like
# evasion in the results. The boundary (above) is what limits blast radius.
resource "aws_iam_policy" "technique_permissions" {
  name        = "${var.lab_name}-technique-permissions"
  path        = "/identity-shield/"
  description = "Actions the eight techniques need, identical for every identity level."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AssumeLabRoles"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole",
          "sts:GetFederationToken",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
      {
        Sid      = "CredentialAndRoleTechniques"
        Effect   = "Allow"
        Action   = ["iam:*"]
        Resource = "*"
      },
      {
        Sid    = "Discovery"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "rds:Describe*",
          "ssm:Describe*",
          "cloudtrail:Describe*",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
        ]
        Resource = "*"
      },
      {
        Sid    = "EscalationProof"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
        ]
        Resource = "*"
      },
      {
        Sid      = "LabDataList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = local.bucket_arn
      },
      {
        Sid      = "LabDataRead"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${local.bucket_arn}/*"
      },
    ]
  })
}

resource "aws_iam_user_policy_attachment" "test" {
  user       = aws_iam_user.test.name
  policy_arn = aws_iam_policy.technique_permissions.arn
}

data "aws_iam_policy_document" "assume_by_test_user" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.test.arn]
    }
  }
}

data "aws_iam_policy_document" "assume_by_ec2" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Low-privilege role: enough discovery to run the reconnaissance techniques,
# no path to the data it does not already own.
resource "aws_iam_role" "app" {
  name                 = "is-app-role"
  path                 = "/identity-shield/"
  assume_role_policy   = data.aws_iam_policy_document.assume_by_test_user.json
  permissions_boundary = aws_iam_policy.boundary.arn

  tags = {
    Purpose = "attack-target"
  }
}

resource "aws_iam_role_policy_attachment" "app_techniques" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.technique_permissions.arn
}

# Escalation target for T1098.003. The boundary keeps it inside this account.
resource "aws_iam_role" "admin" {
  name                 = "is-admin-role"
  path                 = "/identity-shield/"
  assume_role_policy   = data.aws_iam_policy_document.assume_by_test_user.json
  permissions_boundary = aws_iam_policy.boundary.arn

  tags = {
    Purpose = "escalation-target"
  }
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

# Instance role for T1552.005.
resource "aws_iam_role" "ec2" {
  name                 = "is-ec2-role"
  path                 = "/identity-shield/"
  assume_role_policy   = data.aws_iam_policy_document.assume_by_ec2.json
  permissions_boundary = aws_iam_policy.boundary.arn

  tags = {
    Purpose = "imds-target"
  }
}

resource "aws_iam_role_policy_attachment" "ec2_readonly" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

# The IMDS target must also be reachable over SSM, since it has no key pair and
# no inbound rules. This is how Module 5 will run a command on the instance.
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Same capability parity as the user and app role: an instance-profile session
# must be able to attempt the IAM-writing techniques, not be denied by the lab.
resource "aws_iam_role_policy_attachment" "ec2_techniques" {
  role       = aws_iam_role.ec2.name
  policy_arn = aws_iam_policy.technique_permissions.arn
}

resource "aws_iam_instance_profile" "ec2" {
  name = "is-ec2-profile"
  path = "/identity-shield/"
  role = aws_iam_role.ec2.name
}

# ---------------------------------------------------------------------------
# Instance (T1552.005 target)
# ---------------------------------------------------------------------------

resource "aws_security_group" "lab" {
  name        = "${var.lab_name}-no-ingress"
  description = "Lab instance. No inbound rules by design; IMDS is reachable from the instance itself."
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name = "${var.lab_name}-no-ingress"
  }
}

resource "aws_instance" "lab" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = sort(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids = [aws_security_group.lab.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = {
    Name = "${var.lab_name}-instance"
    Role = "imds-target"
  }

  depends_on = [aws_iam_role_policy_attachment.ec2_readonly]
}
