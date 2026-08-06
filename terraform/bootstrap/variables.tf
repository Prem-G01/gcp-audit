variable "project_id" {
  description = "GCP project id that hosts the WIF pool and deploy service accounts."
  type        = string
  default     = "prj-dg-devops-test"
}

variable "github_repository" {
  description = <<-EOT
    GitHub repository allowed to assume the deploy identities, in
    "owner/repo" form. PLACEHOLDER -- set this to your real repository
    before applying; the WIF provider's attribute_condition is scoped to
    exactly this value.
  EOT
  type        = string
  default     = "CHANGE_ME/gcp-audit"
}

variable "deploy_branch" {
  description = "Branch allowed to assume the apply-capable (write) identity."
  type        = string
  default     = "main"
}

variable "pool_id" {
  description = "Workload Identity Pool id."
  type        = string
  default     = "audit-platform-github"
}
