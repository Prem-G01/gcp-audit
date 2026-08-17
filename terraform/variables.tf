variable "project_id" {
  description = "GCP project id."
  type        = string
  default     = "prj-dg-devops-test"
}

variable "region" {
  description = "Region for the Cloud Function, Pub/Sub, and BigQuery dataset."
  type        = string
  default     = "asia-south1"
}

variable "vertex_location" {
  description = "Vertex AI region for Gemini calls -- independent of `region`; Gemini model availability is regionally limited."
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment label applied to every resource that supports labels."
  type        = string
  default     = "prod"
}

variable "deployment_mode" {
  description = <<-EOT
    "project_only" skips the org-level aggregated log sink and its IAM
    entirely, so the stack applies without org-level permissions.
    "full" additionally provisions the org sink -- requires `org_id`.
  EOT
  type        = string
  default     = "project_only"

  validation {
    condition     = contains(["project_only", "full"], var.deployment_mode)
    error_message = "deployment_mode must be \"project_only\" or \"full\"."
  }
}

variable "project_sink_enabled_override" {
  description = <<-EOT
    Explicitly force the interim project-level sink for THIS stack's own
    project_id on (true) or off (false). Defaults to null, meaning "derive
    from deployment_mode" (on whenever deployment_mode != "full"). Set to
    false if a folder-level sink (monitored_folder_ids) or the org-level
    sink already covers project_id's own folder -- otherwise both sinks
    would capture and forward the same events, double-publishing every
    real event in project_id and causing duplicate alerts.
  EOT
  type        = bool
  default     = null
}

variable "org_id" {
  description = "GCP organization id. Required when deployment_mode = \"full\"; ignored otherwise."
  type        = string
  default     = ""
}

variable "enable_data_access_logs" {
  description = <<-EOT
    Whether to monitor Data Access audit logs (BigQuery + Cloud Storage
    DATA_READ/DATA_WRITE, per modules/logging's data_access_audit_services)
    in addition to the always-on Admin Activity + Policy Denied logs. Off
    by default -- Data Access logs are high-volume (every query/object
    read counts) and need a separate, explicit opt-in. When true, the
    deploy SA also needs roles/resourcemanager.folderIamAdmin (not just
    the roles/logging.admin already required for monitored_folder_ids) on
    every folder in monitored_folder_ids, since Data Access log
    GENERATION is controlled by a folder IAM audit config, a different
    permission than creating a log sink:

      gcloud resource-manager folders add-iam-policy-binding FOLDER_ID \
        --member="serviceAccount:tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com" \
        --role="roles/resourcemanager.folderIamAdmin"
  EOT
  type        = bool
  default     = false
}

check "org_id_required_for_full_deployment" {
  assert {
    condition     = var.deployment_mode != "full" || var.org_id != ""
    error_message = "org_id must be set when deployment_mode = \"full\"."
  }
}

variable "additional_monitored_project_ids" {
  description = <<-EOT
    Additional GCP project IDs to monitor, each via its own project-level
    log sink forwarding to this stack's central Pub/Sub topic. A middle
    ground when org-level monitoring (deployment_mode = "full") isn't
    available yet but specific other projects still need coverage now.
    Each project listed here needs the apply SA
    (terraform_deploy_service_account_email) granted roles/logging.admin
    at THAT project's level first:

      gcloud projects add-iam-policy-binding OTHER_PROJECT_ID \
        --member="serviceAccount:tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com" \
        --role="roles/logging.admin"
  EOT
  type        = list(string)
  default     = []
}

variable "monitored_folder_ids" {
  description = <<-EOT
    Folder IDs (bare numeric id, not "folders/123..." prefixed) to
    monitor via their own folder-level sink -- covers that folder and
    everything nested under it (sub-folders, every current and future
    project) automatically, without a grant or sink per individual
    project. Unlike deployment_mode = "full", a folder NOT listed here
    stays completely uncovered -- use this to deliberately keep e.g. a
    sandbox/pre-production folder quiet, only alerting once a project is
    moved into a monitored folder. Each folder listed here needs the
    apply SA granted roles/logging.admin at THAT folder's level first:

      gcloud resource-manager folders add-iam-policy-binding FOLDER_ID \
        --member="serviceAccount:tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com" \
        --role="roles/logging.admin"
  EOT
  type        = list(string)
  default     = []
}

variable "terraform_deploy_service_account_email" {
  description = <<-EOT
    Service account the Terraform providers impersonate (see
    terraform/bootstrap/). Pass the plan SA for `terraform plan` and the
    apply SA for `terraform apply` -- CI sets this per-job via
    TF_VAR_terraform_deploy_service_account_email.
  EOT
  type        = string
}

variable "runtime_service_account_email" {
  description = <<-EOT
    Pre-existing service account the Cloud Function runs as (created
    outside Terraform -- Gmail domain-wide delegation is already registered
    against it in the Workspace Admin Console, which Terraform can't
    manage). Also used as the Gmail delegation `sub`/GMAIL_DELEGATED_SA.
  EOT
  type        = string
  default     = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
}

variable "github_repository" {
  description = "GitHub repository in \"owner/repo\" form -- must match terraform/bootstrap's github_repository. Informational only at this layer (used in labels/outputs); the actual trust binding lives in bootstrap."
  type        = string
  default     = "CHANGE_ME/gcp-audit"
}

# --- Pub/Sub --------------------------------------------------------------

variable "main_topic_name" {
  description = "Pub/Sub topic the org sink publishes audit log entries to, and the Cloud Function's trigger topic."
  type        = string
  default     = "audit-platform-logs"
}

variable "dlq_topic_name" {
  description = "Pub/Sub topic for permanently-undeliverable findings (DLQ_TOPIC env var)."
  type        = string
  default     = "audit-platform-dlq"
}

# --- Cloud Function ---------------------------------------------------------

variable "function_name" {
  description = "Cloud Function (Gen2) name."
  type        = string
  default     = "process-audit-log-gmail-alerts"
}

variable "function_memory" {
  description = "Cloud Function memory allocation."
  type        = string
  default     = "512Mi"
}

variable "function_timeout_seconds" {
  description = "Cloud Function timeout, in seconds."
  type        = number
  default     = 120
}

variable "function_max_instances" {
  description = "Cloud Function max instance count."
  type        = number
  default     = 20
}

# --- Gmail alerting (values become the function's env vars) --------------

variable "gmail_sender" {
  description = "Workspace mailbox impersonated when sending alerts (GMAIL_SENDER). Must hold a Gmail license."
  type        = string
  default     = "premkumar.gunasekaran@docugenieai.com"
}

variable "gmail_sender_name" {
  type    = string
  default = "GCP Audit Platform"
}

variable "gmail_max_attempts" {
  type    = number
  default = 4
}

variable "gmail_timeout_seconds" {
  type    = number
  default = 30
}

# --- Cloud Asset Inventory enrichment --------------------------------------

variable "cai_cache_ttl_seconds" {
  type    = number
  default = 300
}

variable "cai_timeout_seconds" {
  type    = number
  default = 10
}

# --- Gemini / Vertex AI ----------------------------------------------------

variable "gemini_model" {
  type    = string
  default = "gemini-2.5-flash"
}

variable "gemini_max_tokens" {
  type    = number
  default = 400
}

variable "gemini_timeout_seconds" {
  type    = number
  default = 20
}

# --- BigQuery ---------------------------------------------------------------

variable "bq_dataset_id" {
  type    = string
  default = "audit_platform"
}

variable "bq_table_id" {
  type    = string
  default = "alert_events"
}

# --- Mute-button web service (Cloud Run + IAP) ------------------------------

variable "mute_web_admin_members" {
  description = <<-EOT
    Principals allowed to click the "Mute this alert" link in alert
    emails (granted roles/iap.httpsResourceAccessor on the mute-web Cloud
    Run service only -- see modules/mute_web). Each entry needs its IAM
    principal type prefix, e.g. "user:name@domain.com" for an individual
    account or "group:name@domain.com" for a Google Group. Add more
    people later by appending to this list and re-applying.
  EOT
  type        = list(string)
  default     = ["user:premkumar.gunasekaran@securekloud.com"]
}

# --- Observability -----------------------------------------------------------

variable "notification_channels" {
  description = <<-EOT
    Cloud Monitoring notification channel IDs (e.g.
    "projects/PROJECT/notificationChannels/1234567890") to attach to every
    alert policy. Empty by default -- create channels for real email/
    Slack/PagerDuty destinations first (not provisioned here; channel
    creation needs real destination addresses this repo doesn't have), then
    populate this in terraform.tfvars.
  EOT
  type        = list(string)
  default     = []
}
