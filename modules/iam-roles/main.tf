# ---------------------------------------------------------------------------
# iam-roles: least-privilege role builders for ECS.
#
# - task role: what the *application* may do at runtime. Everything it needs
#   is passed in as explicit resource ARNs; no "*" resources, no "*" actions.
# - execution role: what the *platform agent* may do (pull images, read SSM
#   secrets listed by ARN, write to one log group). Also explicit.
#
# Policy documents are rendered by the sibling `policy-doc` helper module so
# every statement in this repo goes through one audited code path.
# ---------------------------------------------------------------------------

variable "project" {
  description = "Project name used as a prefix for role names."
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g. 'production')."
  type        = string
}

variable "name" {
  description = "Service name (e.g. 'api')."
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "source_account_id" {
  description = "AWS account id allowed to assume the roles (trust-policy SourceAccount condition). Passed in rather than read from STS so `terraform plan` works without credentials."
  type        = string
}

variable "task_policy_statements" {
  description = "Statements for the task role, built with the policy-doc helper (e.g. ssm:GetParameter on one ARN, sqs:SendMessage on one queue)."
  type        = list(any)
  default     = []
}

variable "ssm_parameter_arns" {
  description = "SSM parameter ARNs the task execution role may read (task-definition `secrets`)."
  type        = list(string)
  default     = []
}

variable "log_group_arn" {
  description = "CloudWatch log group ARN the agent may write to."
  type        = string
}

variable "ecr_repository_arns" {
  description = "ECR repository ARNs the agent may pull images from."
  type        = list(string)
  default     = []
}

locals {
  name = "${var.project}-${var.environment}-${var.name}"
}

data "aws_iam_policy_document" "assume_ecs_tasks" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    # Defense in depth: only roles in this account may be assumed by ECS tasks.
    # The account id is passed in as a variable (not data.aws_caller_identity,
    # which would make an STS call at plan time and break credential-less CI).
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"

      values = [var.source_account_id]
    }
  }
}

# --- Task role (application runtime permissions) -----------------------------

module "task_role_policy" {
  source = "../policy-doc"

  statements = concat(
    var.task_policy_statements,
    [
      {
        sid       = "LogsOnlyOwnStream"
        effect    = "Allow"
        actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        resources = ["${var.log_group_arn}:*"]
      }
    ]
  )
}

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_tasks.json

  tags = merge(var.tags, { Name = "${local.name}-task", RoleKind = "ecs-task" })
}

resource "aws_iam_role_policy" "task" {
  name   = "${local.name}-task"
  role   = aws_iam_role.task.id
  policy = module.task_role_policy.policy_json
}

# --- Execution role (platform agent permissions) -------------------------------

module "execution_role_policy" {
  source = "../policy-doc"

  statements = concat(
    length(var.ecr_repository_arns) > 0 ? [
      {
        sid       = "EcrPull"
        effect    = "Allow"
        actions   = ["ecr:GetAuthorizationToken"]
        resources = ["*"] # GetAuthorizationToken is account-scoped and does not support resource-level permissions
      },
      {
        sid     = "EcrPullImages"
        effect  = "Allow"
        actions = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]

        resources = var.ecr_repository_arns
      }
    ] : [],
    length(var.ssm_parameter_arns) > 0 ? [
      {
        sid       = "ReadDeclaredSecrets"
        effect    = "Allow"
        actions   = ["ssm:GetParameters", "ssm:GetParameter"]
        resources = var.ssm_parameter_arns
      }
    ] : [],
    [
      {
        sid       = "LogsOnlyOwnStream"
        effect    = "Allow"
        actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        resources = ["${var.log_group_arn}:*"]
      }
    ]
  )
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume_ecs_tasks.json

  tags = merge(var.tags, { Name = "${local.name}-exec", RoleKind = "ecs-execution" })
}

resource "aws_iam_role_policy" "execution" {
  name   = "${local.name}-exec"
  role   = aws_iam_role.execution.id
  policy = module.execution_role_policy.policy_json
}

output "task_role_arn" {
  description = "ARN of the ECS task role."
  value       = aws_iam_role.task.arn
}

output "task_role_id" {
  description = "Name of the ECS task role."
  value       = aws_iam_role.task.name
}

output "execution_role_arn" {
  description = "ARN of the ECS task execution role."
  value       = aws_iam_role.execution.arn
}
