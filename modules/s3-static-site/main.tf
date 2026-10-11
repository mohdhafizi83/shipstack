# ---------------------------------------------------------------------------
# Static site on S3 served through CloudFront.
#
# The bucket is PRIVATE: CloudFront reaches it through an Origin Access
# Control (OAC) with a bucket policy that only trusts the distribution.
# No public-read ACL, no public bucket policy — the only public surface is
# CloudFront itself.
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
  description = "Site identifier (e.g. 'docs')."
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN (must be in us-east-1 for CloudFront)."
  type        = string
}

variable "aliases" {
  description = "Custom domain aliases for the distribution."
  type        = list(string)
  default     = []
}

variable "price_class" {
  description = "CloudFront price class (PriceClass_100 = cheapest, North America + Europe only)."
  type        = string
  default     = "PriceClass_100"
}

variable "index_document" {
  description = "Root document name."
  type        = string
  default     = "index.html"
}

variable "error_document" {
  description = "SPA-friendly error document (404 -> index.html)."
  type        = string
  default     = "index.html"
}

variable "web_acl_id" {
  description = "Optional WAFv2 Web ACL ARN to associate with the distribution (must be a CLOUDFRONT-scope ACL in us-east-1)."
  type        = string
  default     = null
}

variable "log_retention_days" {
  description = "Retention for the access-log bucket objects (lifecycle rule)."
  type        = number
  default     = 90
}

locals {
  name = "${var.project}-${var.environment}-${var.name}"
}

resource "random_id" "bucket_suffix" {
  byte_length = 4

  keepers = {
    name = local.name
  }
}

resource "aws_s3_bucket" "site" {
  bucket        = "${local.name}-${random_id.bucket_suffix.hex}"
  force_destroy = false

  tags = merge(var.tags, { Name = local.name, Purpose = "static-site" })
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket = aws_s3_bucket.site.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "site" {
  bucket = aws_s3_bucket.site.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "site" {
  bucket = aws_s3_bucket.site.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Non-current versions expire so versioning does not silently grow the bill.
resource "aws_s3_bucket_lifecycle_configuration" "site" {
  bucket = aws_s3_bucket.site.id

  # Top-level in provider 5.x (not inside rule).
  rule {
    id     = "expire-noncurrent"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_cloudfront_origin_access_control" "this" {
  name                              = "${local.name}-oac"
  description                       = "OAC for ${local.name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Baseline security headers for the static site (HSTS, no-sniff, DENY framing).
resource "aws_cloudfront_response_headers_policy" "this" {
  name = "${local.name}-security"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

resource "aws_cloudfront_distribution" "this" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = local.name
  aliases             = var.aliases
  price_class         = var.price_class
  default_root_object = var.index_document
  web_acl_id          = var.web_acl_id

  # Access logs go to the companion logs bucket (its bucket policy trusts
  # exactly this distribution).
  logging_config {
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = "cloudfront/"
    include_cookies = false
  }

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = local.name
    origin_access_control_id = aws_cloudfront_origin_access_control.this.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = local.name
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 60
    max_ttl     = 31536000

    response_headers_policy_id = aws_cloudfront_response_headers_policy.this.id
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/${var.error_document}"
  }

  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/${var.error_document}"
  }

  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = merge(var.tags, { Name = local.name })
}

data "aws_iam_policy_document" "oac_read" {
  statement {
    sid     = "CloudFrontReadViaOAC"
    effect  = "Allow"
    actions = ["s3:GetObject"]

    resources = ["${aws_s3_bucket.site.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"

      values = [aws_cloudfront_distribution.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = data.aws_iam_policy_document.oac_read.json
}

# --- Access logging bucket -----------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket        = "${local.name}-cflogs-${random_id.bucket_suffix.hex}"
  force_destroy = false

  tags = merge(var.tags, { Name = "${local.name}-cflogs", Purpose = "cloudfront-logs" })
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = var.log_retention_days
    }
  }
}

# CloudFront (via its service-linked role) may write access logs here, but only
# for THIS distribution — scoped with the same SourceArn condition pattern.
data "aws_iam_policy_document" "logs_write" {
  statement {
    sid     = "CloudFrontWriteLogs"
    effect  = "Allow"
    actions = ["s3:PutObject"]

    resources = ["${aws_s3_bucket.logs.arn}/cloudfront/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"

      values = [aws_cloudfront_distribution.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_write.json
}

output "bucket" {
  description = "Site bucket name (target for `aws s3 sync`)."
  value       = aws_s3_bucket.site.bucket
}

output "bucket_arn" {
  description = "Site bucket ARN."
  value       = aws_s3_bucket.site.arn
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain name."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (for invalidations after deploys)."
  value       = aws_cloudfront_distribution.this.id
}

output "cloudfront_arn" {
  description = "CloudFront distribution ARN."
  value       = aws_cloudfront_distribution.this.arn
}
