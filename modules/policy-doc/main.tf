# ---------------------------------------------------------------------------
# policy-doc: tiny helper module that turns a list of statement objects into a
# rendered IAM policy JSON. One audited code path for every policy in the repo
# means one place to enforce conventions (sids required, no wildcard actions
# next to wildcard resources, etc.).
# ---------------------------------------------------------------------------

variable "statements" {
  description = <<-EOT
    List of statement objects. Each object:
      sid       (required) — forces every statement to be named and auditable
      effect    (required) — "Allow" or "Deny"
      actions   (required) — list of IAM actions
      resources (required) — list of resource ARNs; use ["*"] only when the
                             action genuinely has no resource-level scoping
      principals         (optional) — list of principal type/identifier pairs
      condition_test     (optional) — e.g. "StringEquals"
      condition_variable (optional) — e.g. "aws:SourceArn"
      condition_values   (optional) — list of values
  EOT

  type = list(object({
    sid                = string
    effect             = string
    actions            = list(string)
    resources          = list(string)
    principals         = optional(list(object({ type = string, identifiers = list(string) })))
    condition_test     = optional(string)
    condition_variable = optional(string)
    condition_values   = optional(list(string))
  }))
}

locals {
  rendered_statements = [
    for s in var.statements : merge(
      {
        Sid      = s.sid
        Effect   = s.effect
        Action   = s.actions
        Resource = s.resources
      },
      s.principals != null ? {
        Principal = merge([for p in s.principals : { (p.type) = p.identifiers }]...)
      } : {},
      s.condition_test != null ? {
        Condition = {
          (s.condition_test) = {
            (s.condition_variable) = s.condition_values
          }
        }
      } : {}
    )
  ]
}

output "policy_json" {
  description = "Rendered IAM policy document."
  value       = jsonencode({ Version = "2012-10-17", Statement = local.rendered_statements })
}
