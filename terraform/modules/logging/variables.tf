variable "enabled" {
  description = "Whether to create the org-level sink at all (deployment_mode == \"full\")."
  type        = bool
  default     = false
}

variable "org_id" {
  description = "GCP organization id. Required when enabled = true."
  type        = string
  default     = ""
}

variable "sink_name" {
  type    = string
  default = "audit-platform-activity-sink"
}

variable "destination_project_id" {
  description = "Project that owns the destination Pub/Sub topic."
  type        = string
}

variable "destination_topic_name" {
  description = "Short name of the destination Pub/Sub topic (for the IAM binding)."
  type        = string
}

variable "destination_topic_id" {
  description = "Full resource id of the destination Pub/Sub topic, e.g. projects/P/topics/T."
  type        = string
}

variable "include_data_access_logs" {
  description = <<-EOT
    Whether to (a) add Data Access audit logs ("%2Fdata_access") to the
    sink filter, alongside the always-on Admin Activity + Policy Denied
    categories, and (b) create the google_folder_iam_audit_config
    resources (data_access_audit_services, below) needed to actually
    make GCP generate those log entries in the first place -- Data
    Access logs are entirely absent by default; a sink filter alone
    forwards nothing without this. Off by default: Data Access logs are
    high-volume (every read counts), so this is a deliberate opt-in, not
    part of the baseline. config/rules.yaml's bulk_data_export_or_download
    rule is the only rule that matches this log category -- every other
    rule explicitly excludes raw.logName containing "%2Fdata_access", for
    the same reason every rule already excludes "%2Fpolicy": a BigQuery
    query job's method_name legitimately contains "InsertJob", which
    would otherwise misfire resource_created's "insert|create" pattern on
    a plain SELECT.
  EOT
  type        = bool
  default     = false
}

variable "include_system_event_logs" {
  description = <<-EOT
    Whether to add System Event audit logs ("%2Fsystem_event") to the sink
    filter. Unlike include_data_access_logs, there's no equivalent
    google_folder_iam_audit_config needed -- Google writes System Event
    entries unconditionally for every project (VM host maintenance/
    preemption, live migration, instance-group auto-healing recreating an
    instance, etc.), so this flag purely controls whether they're
    forwarded to this pipeline. Off by default for the same "explicit
    opt-in per log category" reasoning as include_data_access_logs, even
    though System Event volume is typically much lower (bounded by actual
    infrastructure churn, not every read/query).
  EOT
  type        = bool
  default     = false
}

variable "data_access_audit_services" {
  description = <<-EOT
    Services to enable Data Access (DATA_READ + DATA_WRITE) audit
    logging for, applied at every folder in monitored_folder_ids via
    google_folder_iam_audit_config. Only takes effect when
    include_data_access_logs = true. Keep this list narrow -- each
    additional service can add significant log volume/cost ("allServices"
    would log every read of every GCP API call, org-wide). ADMIN_READ is
    deliberately never enabled here -- it logs every metadata Get/List
    call (bucket/dataset listings, etc.), which is pure noise for this
    platform's purpose and not something config/rules.yaml's Data Access
    rule looks for.
  EOT
  type        = list(string)
  default     = ["bigquery.googleapis.com", "storage.googleapis.com"]
}

variable "project_sink_enabled" {
  description = <<-EOT
    Whether to create a project-scoped sink for destination_project_id's
    own Admin Activity logs. This is what makes the pipeline fire on real
    activity in "project_only" mode -- without it (or the org sink), no
    real Cloud Audit Log entry ever reaches the Pub/Sub topic at all.
    Deliberately mutually exclusive with `enabled` (the org sink) at the
    root module's call site: running both at once would double-publish
    every event inside this project, causing duplicate alerts.
  EOT
  type        = bool
  default     = false
}

variable "additional_monitored_project_ids" {
  description = <<-EOT
    Additional GCP project IDs to monitor, each via its own project-level
    sink forwarding to the same central Pub/Sub topic. A middle ground
    when org-level monitoring isn't available yet (needs org-admin
    access) but specific other projects still need coverage now. Each
    project here needs the apply SA granted roles/logging.admin at that
    project's level first.
  EOT
  type        = list(string)
  default     = []
}

variable "monitored_folder_ids" {
  description = <<-EOT
    Folder IDs (bare numeric id, not "folders/123..." prefixed) to
    monitor via their own folder-level sink -- covers that folder and
    everything nested under it (sub-folders, every current and future
    project) automatically via include_children, without a grant or sink
    per individual project. Unlike the org-level sink, a folder NOT
    listed here stays completely uncovered -- use this to deliberately
    keep e.g. a sandbox/pre-production folder quiet, only alerting once a
    project is moved into a monitored folder. Each folder here needs the
    apply SA granted roles/logging.admin at THAT folder's level first.
  EOT
  type        = list(string)
  default     = []
}
