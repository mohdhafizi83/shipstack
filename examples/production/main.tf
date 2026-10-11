# ---------------------------------------------------------------------------
# examples/production — wires every module into one deployable stack.
#
# The network + ECS cluster live here (not in a module) on purpose: most teams
# already have a VPC, so the modules *consume* a network rather than own one.
# This file plays the part of "the rest of your platform" so the example plans
# end-to-end.
# ---------------------------------------------------------------------------

# NOTE: the backend block below is commented out on purpose — this repo is a
# public example and CI plans with fake credentials. To use it for real:
#
#   1. Create an S3 bucket + DynamoDB lock table (or use S3 native locking):
#        aws s3api create-bucket --bucket shipstack-tfstate-<acct> \
#          --region us-east-1 --create-bucket-configuration LocationConstraint=us-east-1
#        aws dynamodb create-table --table-name shipstack-tf-locks \
#          --attribute-definitions AttributeName=LockID,AttributeType=S \
#          --key-schema AttributeName=LockID,KeyType=HASH --billing-mode PAY_PER_REQUEST
#   2. Uncomment the block, set the bucket, `terraform init -reconfigure`.
#
# terraform {
#   backend "s3" {
#     bucket       = "shipstack-tfstate-<acct>"
#     key          = "production/terraform.tfstate"
#     region       = "us-east-1"
#     encrypt      = true
#     use_lockfile = true
#   }
# }

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # These flags let `terraform plan` run in CI with fake credentials:
  # no STS validation call, no account-id lookup, no IMDS check. Remove them
  # for real applies or scope them to a CI-only provider alias.
  skip_credentials_validation = var.ci_plan_mode
  skip_requesting_account_id  = var.ci_plan_mode
  skip_metadata_api_check     = var.ci_plan_mode
}

variable "aws_region" {
  description = "AWS region for the stack."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project name prefix."
  type        = string
  default     = "shipstack"
}

variable "environment" {
  description = "Environment name."
  type        = string
  default     = "production"
}

variable "account_id" {
  description = "AWS account id (used in role trust conditions and ARNs). Use a placeholder in CI."
  type        = string
  default     = "123456789012"
}

variable "ci_plan_mode" {
  description = "When true, the provider skips credential validation so CI can plan without an AWS account. Set false for real applies."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Common tags."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Repo      = "mohdhafizi83/shipstack"
  }
}

# --- Cost knobs ---------------------------------------------------------------
# One variable block flips the whole stack between "demo-cheap" and "prod".
# See README "Cost knobs".

variable "size" {
  description = "'dev' = smallest instances, single-AZ, no deletion protection. 'prod' = HA everything."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "prod"], var.size)
    error_message = "size must be 'dev' or 'prod'."
  }
}

locals {
  is_prod = var.size == "prod"

  db_instance_class   = local.is_prod ? "db.r6g.large" : "db.t4g.micro"
  db_multi_az         = local.is_prod
  db_deletion_protect = local.is_prod

  api_cpu    = local.is_prod ? 1024 : 256
  api_memory = local.is_prod ? 2048 : 512
  api_count  = local.is_prod ? 3 : 1

  cf_price_class = local.is_prod ? "PriceClass_100" : "PriceClass_100"
}

# --- Network (stands in for your existing VPC) ---------------------------------

resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}" })
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id            = aws_vpc.this.id
  cidr_block        = "10.42.${count.index}.0/24"
  availability_zone = "${var.aws_region}${count.index == 0 ? "a" : "b"}"

  map_public_ip_on_launch = false

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-public-${count.index}", Tier = "public" })
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.this.id
  cidr_block        = "10.42.${10 + count.index}.0/24"
  availability_zone = "${var.aws_region}${count.index == 0 ? "a" : "b"}"

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-private-${count.index}", Tier = "private" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-public" })
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-private" })
}

resource "aws_route_table_association" "private" {
  count = 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "joiner" {
  name        = "${var.project}-${var.environment}-joiner"
  description = "Joiner SG: the DB allow-list points here; tasks attach this SG. Breaks the module cycle (db -> joiner <- api)."
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-joiner" })
}

# The VPC default SG ships wide-open in some accounts; strip it to deny-all.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-default" })
}

# VPC flow logs -> CloudWatch (traffic forensics without a SIEM).
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/vpc/${var.project}-${var.environment}/flow-logs"
  retention_in_days = 30

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-flow-logs" })
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.project}-${var.environment}-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-flow-logs" })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.project}-${var.environment}-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups"]

      # Scoped to the one flow-log group — not "*".
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  iam_role_arn             = aws_iam_role.flow_logs.arn
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  max_aggregation_interval = 60

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}-flow-log" })
}

resource "aws_ecs_cluster" "this" {
  name = "${var.project}-${var.environment}"

  setting {
    name  = "containerInsights"
    value = local.is_prod ? "enabled" : "disabled"
  }

  tags = merge(var.tags, { Name = "${var.project}-${var.environment}" })
}

# --- Certificates (placeholders: real ARNs from your cert pipeline) -----------

locals {
  acm_api_cert_arn  = "arn:aws:acm:${var.aws_region}:${var.account_id}:certificate/00000000-0000-0000-0000-000000000001"
  acm_site_cert_arn = "arn:aws:acm:us-east-1:${var.account_id}:certificate/00000000-0000-0000-0000-000000000002"
}

# --- IAM roles (least-privilege builders) --------------------------------------

module "iam_api" {
  source = "../../modules/iam-roles"

  project     = var.project
  environment = var.environment
  name        = "api"
  tags        = var.tags

  source_account_id = var.account_id
  log_group_arn     = "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/ecs/${var.project}-${var.environment}-api"

  ecr_repository_arns = ["arn:aws:ecr:${var.aws_region}:${var.account_id}:repository/${var.project}-api"]

  ssm_parameter_arns = [
    "arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/${var.project}/${var.environment}/db-url",
    "arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/${var.project}/${var.environment}/session-secret",
  ]

  # The app itself only needs these two things at runtime — nothing else.
  task_policy_statements = [
    {
      sid       = "ReadOwnParameters"
      effect    = "Allow"
      actions   = ["ssm:GetParameter"]
      resources = ["arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/${var.project}/${var.environment}/session-secret"]
    },
    {
      sid       = "EnqueueJobs"
      effect    = "Allow"
      actions   = ["sqs:SendMessage"]
      resources = ["arn:aws:sqs:${var.aws_region}:${var.account_id}:${var.project}-${var.environment}-jobs"]
    }
  ]
}

# --- Database -------------------------------------------------------------------

module "db" {
  source = "../../modules/rds-postgres"

  project     = var.project
  environment = var.environment
  name        = "app"
  tags        = var.tags

  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.private[0].id, aws_subnet.private[1].id]

  # Only tasks carrying the joiner SG may reach Postgres — no CIDR rules, and
  # no module cycle between the DB and the service.
  ingress_security_group_ids = [aws_security_group.joiner.id]

  instance_class      = local.db_instance_class
  multi_az            = local.db_multi_az
  deletion_protection = local.db_deletion_protect

  # Dev gets a Terraform-managed password in Secrets Manager; prod expects the
  # password to come from your own bootstrap so it never sits in state.
  manage_master_password = !local.is_prod
  skip_final_snapshot    = !local.is_prod
}

# --- API service ------------------------------------------------------------------

module "api" {
  source = "../../modules/ecs-service"

  project     = var.project
  environment = var.environment
  name        = "api"
  tags        = var.tags

  aws_region   = var.aws_region
  cluster_id   = aws_ecs_cluster.this.id
  cluster_name = aws_ecs_cluster.this.name

  vpc_id             = aws_vpc.this.id
  public_subnet_ids  = [aws_subnet.public[0].id, aws_subnet.public[1].id]
  private_subnet_ids = [aws_subnet.private[0].id, aws_subnet.private[1].id]

  image     = "${var.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.project}-api"
  image_tag = "v1.0.0" # CI replaces this with the git SHA of the build

  cpu           = local.api_cpu
  memory        = local.api_memory
  desired_count = local.api_count
  min_capacity  = local.api_count
  max_capacity  = local.is_prod ? 10 : 2

  task_role_arn      = module.iam_api.task_role_arn
  execution_role_arn = module.iam_api.execution_role_arn

  environment_variables = {
    APP_ENV    = var.environment
    LOG_FORMAT = "json"
    DB_HOST    = module.db.address
    DB_NAME    = module.db.db_name
  }

  secrets = [
    {
      name      = "DATABASE_URL"
      valueFrom = "arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/${var.project}/${var.environment}/db-url"
    },
    {
      name      = "SESSION_SECRET"
      valueFrom = "arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/${var.project}/${var.environment}/session-secret"
    }
  ]

  acm_certificate_arn = local.acm_api_cert_arn

  additional_service_security_group_ids = [aws_security_group.joiner.id]
}

# --- Static marketing site ----------------------------------------------------------

module "site" {
  source = "../../modules/s3-static-site"

  project     = var.project
  environment = var.environment
  name        = "site"
  tags        = var.tags

  acm_certificate_arn = local.acm_site_cert_arn
  aliases             = ["shipstack.example.com"]
  price_class         = local.cf_price_class
}

# --- Outputs a human checks after apply ----------------------------------------------

output "api_url" {
  description = "Public URL of the API."
  value       = "https://${module.api.alb_dns_name}"
}

output "site_url" {
  description = "Public URL of the static site."
  value       = "https://${module.site.cloudfront_domain}"
}

output "db_endpoint" {
  description = "Private DB endpoint (reachable only from inside the VPC)."
  value       = module.db.endpoint
}
