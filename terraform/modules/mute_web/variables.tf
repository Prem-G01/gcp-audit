variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "service_name" {
  description = "Cloud Run service name for the mute-button confirmation app."
  type        = string
  default     = "mute-web"
}

variable "image" {
  description = <<-EOT
    Container image for the mute-web service (e.g.
    REGION-docker.pkg.dev/PROJECT/mute-web/mute-web:TAG). The placeholder
    default only exists so `terraform plan`/`apply` succeed before the
    first real image has been pushed -- see scripts/deploy_mute_web.ps1/.sh,
    which builds and pushes the real image, then updates the running
    revision directly via `gcloud run deploy --image=...`. Terraform's own
    `ignore_changes` on this field (see main.tf) means it never reverts
    that imperative update on a later `terraform apply`.
  EOT
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "admin_members" {
  description = <<-EOT
    Principals allowed to open the mute-button link and mute alerts
    (granted roles/iap.httpsResourceAccessor, scoped to this one Cloud Run
    service). Each entry must include its IAM principal type prefix, e.g.
    "user:premkumar.gunasekaran@securekloud.com" for an individual account
    or "group:infrastructure-admin@docugenieai.com" for a Google Group.
    Starting with individual users is fine -- add more people later by
    appending to this list and re-applying; switch to a "group:" entry
    once a real admin group exists, so membership can be managed in
    Google Groups instead of here.
  EOT
  type        = list(string)
}

variable "firestore_project_id" {
  description = "Project the Firestore mute-state database lives in (src/muting.py's FIRESTORE_PROJECT)."
  type        = string
}

variable "terraform_deploy_service_account_email" {
  description = <<-EOT
    Service account Terraform impersonates to apply (see
    terraform/bootstrap/). Needs roles/iam.serviceAccountUser scoped to
    the mute-web SA this module creates, to attach it to the Cloud Run
    service -- unlike the pre-existing runtime SA (which bootstrap already
    grants this on), this SA is created fresh in this same apply, so
    nothing grants actAs on it until this module does.
  EOT
  type        = string
}

variable "labels" {
  type    = map(string)
  default = {}
}
