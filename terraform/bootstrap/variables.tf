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

variable "runtime_service_account_email" {
  description = <<-EOT
    Pre-existing Cloud Function runtime SA. The apply SA needs actAs rights
    on exactly this SA (roles/iam.serviceAccountUser, scoped to this SA
    only -- not project-wide) to attach it to the Cloud Function resource
    that module.cloud_function creates. Must match
    terraform/variables.tf's runtime_service_account_email.
  EOT
  type        = string
  default     = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
}
