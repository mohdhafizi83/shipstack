# ---------------------------------------------------------------------------
# Private PostgreSQL on RDS.
#
# Hardening defaults: storage encrypted, NOT publicly addressable, security
# group that only accepts Postgres from a caller-supplied list of security
# groups (typically the ECS service SG). Deletion protection is a variable so
# dev can be cheap to tear down while prod refuses `terraform destroy`.
# No data sources: everything is plan-time safe without credentials.
# ---------------------------------------------------------------------------

variable "project" {
  description = "Project name used as a prefix for resource names."
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g. 'production')."
  type        = string
}

variable "name" {
  description = "Database identifier (e.g. 'app')."
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "VPC the DB lives in."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs for the DB subnet group (>= 2, different AZs)."
  type        = list(string)
}

variable "ingress_security_group_ids" {
  description = "Security groups allowed to reach Postgres (e.g. the ECS service SG). Never 0.0.0.0/0."
  type        = list(string)
}

variable "engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "16.3"
}

variable "instance_class" {
  description = "Instance class (dev: db.t4g.micro, prod: db.r6g.large etc.)."
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage_gb" {
  description = "Initial storage in GiB (autoscaling below caps at max_allocated_storage)."
  type        = number
  default     = 20
}

variable "max_allocated_storage_gb" {
  description = "Upper bound for storage autoscaling."
  type        = number
  default     = 100
}

variable "multi_az" {
  description = "Multi-AZ standby. True in prod, false in dev to halve cost."
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = "Automated backup retention (0 disables; keep > 0 in prod)."
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Block `terraform destroy` / instance deletion. Set true in prod."
  type        = bool
  default     = true
}

variable "master_username" {
  description = "Master username. The password is NOT managed here — it is created by the AWS console/Secrets Manager bootstrap and rotated out of band."
  type        = string
  default     = "shipstack_admin"
}

variable "manage_master_password" {
  description = "When true, Terraform generates a random master password into Secrets Manager (convenient for dev). Keep false in prod and inject via your own secret pipeline."
  type        = bool
  default     = false
}

variable "skip_final_snapshot" {
  description = "Skip the final snapshot on destroy. Only ever true for throwaway dev databases."
  type        = bool
  default     = false
}

locals {
  identifier = "${var.project}-${var.environment}-${var.name}"
}

resource "aws_db_subnet_group" "this" {
  name       = local.identifier
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, { Name = local.identifier })
}

resource "aws_db_parameter_group" "this" {
  name        = "${local.identifier}-pg16"
  family      = "postgres16"
  description = "Parameters for ${local.identifier}"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = merge(var.tags, { Name = local.identifier })
}

resource "aws_security_group" "db" {
  name        = "${local.identifier}-db"
  description = "Postgres access for ${local.identifier} from named SGs only"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, { Name = local.identifier })
}

# count (not for_each): the SG ids are unknown until apply, but the list
# LENGTH is static, so the plan shows one rule per entry instead of deferring
# the whole expansion to apply time.
resource "aws_vpc_security_group_ingress_rule" "postgres" {
  count = length(var.ingress_security_group_ids)

  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = var.ingress_security_group_ids[count.index]
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Postgres from joiner security group"

  tags = merge(var.tags, { Name = "${local.identifier}-ingress-${count.index}" })
}

resource "random_password" "master" {
  count = var.manage_master_password ? 1 : 0

  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "master" {
  count = var.manage_master_password ? 1 : 0

  name                    = "${local.identifier}/db/master"
  recovery_window_in_days = 0

  tags = merge(var.tags, { Name = local.identifier })
}

resource "aws_secretsmanager_secret_version" "master" {
  count = var.manage_master_password ? 1 : 0

  secret_id = aws_secretsmanager_secret.master[0].id
  secret_string = jsonencode({
    username = var.master_username
    password = random_password.master[0].result
  })
}

resource "aws_db_instance" "this" {
  identifier     = local.identifier
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.max_allocated_storage_gb
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = replace(var.name, "-", "_")
  username = var.master_username
  password = var.manage_master_password ? random_password.master[0].result : null

  port                            = 5432
  multi_az                        = var.multi_az
  publicly_accessible             = false
  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.db.id]
  parameter_group_name            = aws_db_parameter_group.this.name
  backup_retention_period         = var.backup_retention_days
  backup_window                   = "03:00-04:00"
  maintenance_window              = "sun:04:30-sun:05:30"
  auto_minor_version_upgrade      = true
  performance_insights_enabled    = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
  copy_tags_to_snapshot           = true
  monitoring_interval             = 60
  monitoring_role_arn             = aws_iam_role.rds_monitoring.arn
  deletion_protection             = var.deletion_protection
  skip_final_snapshot             = var.skip_final_snapshot
  final_snapshot_identifier       = "${local.identifier}-final"

  tags = merge(var.tags, { Name = local.identifier })
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${local.identifier}-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, { Name = local.identifier })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

output "endpoint" {
  description = "DB endpoint (host:port)."
  value       = aws_db_instance.this.endpoint
}

output "address" {
  description = "DB hostname."
  value       = aws_db_instance.this.address
}

output "port" {
  description = "DB port."
  value       = aws_db_instance.this.port
}

output "db_name" {
  description = "Initial database name."
  value       = aws_db_instance.this.db_name
}

output "master_username" {
  description = "Master username."
  value       = var.master_username
  sensitive   = true
}

output "master_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the master credentials (empty when manage_master_password = false)."
  value       = var.manage_master_password ? aws_secretsmanager_secret.master[0].arn : ""
}

output "security_group_id" {
  description = "DB security group ID (pass to ecs-service as additional consumer if needed)."
  value       = aws_security_group.db.id
}
