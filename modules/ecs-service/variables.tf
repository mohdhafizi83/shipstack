variable "project" {
  description = "Project name used as a prefix for all resource names."
  type        = string
}

variable "name" {
  description = "Service name (e.g. 'api')."
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g. 'production')."
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "cluster_id" {
  description = "ID of the existing ECS cluster to run in."
  type        = string
}

variable "cluster_name" {
  description = "Name of the existing ECS cluster (used for the autoscaling resource_id)."
  type        = string
}

variable "aws_region" {
  description = "AWS region, passed through to the awslogs driver (avoids a plan-time data source)."
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC the service lives in."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for the ALB."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnets for the Fargate tasks."
  type        = list(string)
}

variable "image" {
  description = "Container image URI without tag (e.g. '123456789012.dkr.ecr.us-east-1.amazonaws.com/shipstack-api')."
  type        = string
}

variable "image_tag" {
  description = "Immutable image tag (git SHA preferred over 'latest' so new task-def revisions are created per deploy)."
  type        = string
}

variable "container_port" {
  description = "Port the container listens on."
  type        = number
  default     = 8080
}

variable "command" {
  description = "Optional command override for the container (list of strings)."
  type        = list(string)
  default     = null
}

variable "cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Desired number of running tasks."
  type        = number
  default     = 2
}

variable "min_capacity" {
  description = "Minimum tasks for autoscaling."
  type        = number
  default     = 2
}

variable "max_capacity" {
  description = "Maximum tasks for autoscaling."
  type        = number
  default     = 6
}

variable "task_role_arn" {
  description = "ARN of the runtime task role (build it with the iam-roles module)."
  type        = string
}

variable "execution_role_arn" {
  description = "ARN of the task execution role (build it with the iam-roles module)."
  type        = string
}

variable "environment_variables" {
  description = "Plain-text environment variables for the container."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Secrets injected from SSM Parameter Store. valueFrom is the full parameter ARN/qualified name."
  type = list(object({
    name      = string
    valueFrom = string
  }))
  default = []
}

variable "health_check_path" {
  description = "HTTP path used by the ALB target-group health check."
  type        = string
  default     = "/healthz"
}

variable "log_retention_days" {
  description = "CloudWatch log-group retention in days."
  type        = number
  default     = 30
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for the ALB HTTPS listener."
  type        = string
}

variable "additional_service_security_group_ids" {
  description = "Extra security groups attached to the tasks (e.g. a joiner SG referenced by the DB's ingress rule, so the DB module can point at the tasks without a module cycle)."
  type        = list(string)
  default     = []
}

variable "access_logs_bucket" {
  description = "Optional S3 bucket name for ALB access logs (the bucket needs an ELB-delivery bucket policy)."
  type        = string
  default     = null
}

variable "access_logs_prefix" {
  description = "Key prefix for ALB access logs."
  type        = string
  default     = "alb-logs/"
}

variable "additional_ingress_port" {
  description = "Optional extra container port opened on the service security group (e.g. metrics). Set null to disable."
  type        = number
  default     = null
}
