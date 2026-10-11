output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.this.name
}

output "service_arn" {
  description = "ECS service ARN (in AWS provider 5.x the service id is the ARN)."
  value       = aws_ecs_service.this.id
}

output "task_definition_family" {
  description = "Task definition family (deploy pipeline registers new revisions under this family)."
  value       = aws_ecs_task_definition.this.family
}

output "task_definition_arn" {
  description = "ARN of the current task-definition revision Terraform knows about."
  value       = aws_ecs_task_definition.this.arn
}

output "alb_dns_name" {
  description = "ALB DNS name (point DNS / Route 53 alias at this)."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  description = "Route 53 zone ID of the ALB (for alias records)."
  value       = aws_lb.this.zone_id
}

output "target_group_arn" {
  description = "Target group ARN (second group for blue/green experiments)."
  value       = aws_lb_target_group.this.arn
}

output "security_group_id" {
  description = "Service task security group ID (pass to rds-postgres ingress list)."
  value       = aws_security_group.service.id
}

output "log_group_name" {
  description = "CloudWatch log group name."
  value       = aws_cloudwatch_log_group.this.name
}

output "log_group_arn" {
  description = "CloudWatch log group ARN (pass to iam-roles)."
  value       = aws_cloudwatch_log_group.this.arn
}
