# ---------------------------------------------------------------------------
# ECS Fargate service fronted by an ALB.
#
# Blue-green capability: the task definition is referenced by *family* (no
# pinned revision) and the service runs with deployment_maximum_percent=200 /
# minimum_healthy_percent=100, so every deploy brings up the new revision
# alongside the old one and drains it only after health checks pass. The same
# family + two-target-group layout is what a CodeDeploy blue/green cutover
# would build on (see README "Limitations").
# ---------------------------------------------------------------------------

locals {
  name = "${var.project}-${var.environment}-${var.name}"

  container_environment = [
    for k, v in var.environment_variables : {
      name  = k
      value = v
    }
  ]

  # Build the container definition as an object and drop optional keys when
  # unset — jsonencode would otherwise emit explicit nulls the ECS API rejects.
  container_definition = merge(
    {
      name      = var.name
      image     = "${var.image}:${var.image_tag}"
      essential = true

      portMappings = [
        {
          containerPort = var.container_port
          protocol      = "tcp"
        }
      ]

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${var.container_port}${var.health_check_path} || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }

      # NOTE: no readonlyRootFilesystem — Fargate has no tmpfs volumes, so a
      # read-only root would need an EFS mount just for /tmp. Left as an
      # explicit trade-off rather than a silent omission.

      environment = local.container_environment

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.this.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = var.name
        }
      }
    },
    var.command != null ? { command = var.command } : {},
    length(var.secrets) > 0 ? { secrets = var.secrets } : {}
  )
}

# --- Networking / security ---------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Public ALB for ${local.name}"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP (redirects to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound to targets"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${local.name}-alb" })
}

resource "aws_security_group" "service" {
  name        = "${local.name}-service"
  description = "Fargate tasks for ${local.name} (only reachable via ALB)"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Container port from ALB only"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  dynamic "ingress" {
    for_each = var.additional_ingress_port != null ? [1] : []
    content {
      description     = "Extra container port from ALB (e.g. metrics)"
      from_port       = var.additional_ingress_port
      to_port         = var.additional_ingress_port
      protocol        = "tcp"
      security_groups = [aws_security_group.alb.id]
    }
  }

  egress {
    description = "Outbound for image pulls, SSM, logs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${local.name}-service" })
}

# --- Load balancer -----------------------------------------------------------

resource "aws_lb" "this" {
  name               = local.name
  load_balancer_type = "application"
  internal           = false
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true
  enable_deletion_protection = false

  dynamic "access_logs" {
    for_each = var.access_logs_bucket != null ? [1] : []
    content {
      enabled = true
      bucket  = var.access_logs_bucket
      prefix  = var.access_logs_prefix
    }
  }

  tags = merge(var.tags, { Name = local.name })
}

resource "aws_lb_target_group" "this" {
  name        = local.name
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = var.health_check_path
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 5
    matcher             = "200-399"
  }

  tags = merge(var.tags, { Name = local.name })
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = merge(var.tags, { Name = "${local.name}-http" })
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-https" })
}

# --- Logging -----------------------------------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${local.name}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, { Name = local.name })
}

# --- Task definition (family-based, blue-green capable) ----------------------

resource "aws_ecs_task_definition" "this" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  task_role_arn            = var.task_role_arn
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([local.container_definition])

  tags = merge(var.tags, { Name = local.name })
}

# --- Service -----------------------------------------------------------------

resource "aws_ecs_service" "this" {
  name            = local.name
  cluster         = var.cluster_id
  task_definition = aws_ecs_task_definition.this.family # family, not revision: new revisions roll in without editing the service

  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  health_check_grace_period_seconds  = 60
  enable_execute_command             = false

  deployment_controller {
    type = "ECS"
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = concat([aws_security_group.service.id], var.additional_service_security_group_ids)
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = var.name
    container_port   = var.container_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    # The desired count is owned by autoscaling after the first apply.
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener.https]

  tags = merge(var.tags, { Name = local.name })
}

# --- Autoscaling ---------------------------------------------------------------

resource "aws_appautoscaling_target" "this" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${var.cluster_name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  tags = merge(var.tags, { Name = local.name })
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${local.name}-cpu-target"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension
  service_namespace  = aws_appautoscaling_target.this.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
