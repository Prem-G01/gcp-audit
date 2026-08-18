# The effective sink filter -- Admin Activity + Policy Denied are always
# on; Data Access and System Event are appended only when their respective
# include_* flags are true. A plain string default (like the old `filter`
# variable) can't depend on another variable's value, so this is computed
# as a local instead.
#
# System Event is simpler than Data Access: Google writes these
# unconditionally for every project (VM host maintenance/preemption,
# instance-group auto-healing, etc.) -- unlike Data Access, there's no
# equivalent "log generation" switch to turn on (no IAM audit config
# resource needed here), only the filter decides whether they reach this
# pipeline at all.
locals {
  filter_categories = concat(
    [
      "logName:\"/logs/cloudaudit.googleapis.com%2Factivity\"",
      "logName:\"/logs/cloudaudit.googleapis.com%2Fpolicy\"",
    ],
    var.include_data_access_logs ? ["logName:\"/logs/cloudaudit.googleapis.com%2Fdata_access\""] : [],
    var.include_system_event_logs ? ["logName:\"/logs/cloudaudit.googleapis.com%2Fsystem_event\""] : [],
  )
  effective_filter = join(" OR ", local.filter_categories)

  # Every (folder, service) pair needing a google_folder_iam_audit_config,
  # e.g. {"159249143908/bigquery.googleapis.com" = {folder = ..., service = ...}}.
  # Empty (no resources created) unless include_data_access_logs = true --
  # this is what actually makes GCP START GENERATING Data Access log
  # entries; the filter change above only controls what an already-existing
  # entry gets forwarded to.
  #
  # Scoped to monitored_folder_ids only, matching this platform's actual
  # sink topology today (deployment_mode = "project_only", no org sink, no
  # additional_monitored_project_ids in use) -- a project brought in via
  # the org sink or additional_monitored_project_ids instead would need an
  # equivalent org/project-level audit config added alongside this if this
  # feature is ever needed there too.
  data_access_audit_pairs = var.include_data_access_logs ? {
    for pair in setproduct(var.monitored_folder_ids, var.data_access_audit_services) :
    "${pair[0]}/${pair[1]}" => { folder = pair[0], service = pair[1] }
  } : {}

  # Folders needing the iamcredentials.googleapis.com ADMIN_READ audit
  # config -- only when include_impersonation_logs = true. Kept as its
  # own resource (below), not folded into data_access_audit_pairs, since
  # it's a different log type (ADMIN_READ, not DATA_READ/DATA_WRITE) for
  # a service deliberately excluded from data_access_audit_services.
  impersonation_audit_folders = var.include_impersonation_logs ? toset(var.monitored_folder_ids) : toset([])
}

# Turns on Data Access (DATA_READ + DATA_WRITE) log GENERATION for the
# listed services on every monitored folder -- without this, no Data
# Access log entry is ever created in the first place, regardless of the
# sink filter above. The `folder` argument requires the "folders/" prefix
# (unlike google_logging_folder_sink's bare-or-prefixed flexibility).
resource "google_folder_iam_audit_config" "data_access" {
  for_each = local.data_access_audit_pairs

  folder  = "folders/${each.value.folder}"
  service = each.value.service

  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Turns on ADMIN_READ log GENERATION for iamcredentials.googleapis.com --
# the calls behind service account impersonation (GenerateAccessToken/
# GenerateIdToken/SignJwt/SignBlob). A separate, narrower resource from
# google_folder_iam_audit_config.data_access above because this is a
# different log type (ADMIN_READ) for a service that's intentionally NOT
# in data_access_audit_services (blanket ADMIN_READ on BigQuery/GCS would
# be pure Get/List metadata noise; iamcredentials is the one service
# where ADMIN_READ is exactly the signal wanted).
resource "google_folder_iam_audit_config" "impersonation" {
  for_each = local.impersonation_audit_folders

  folder  = "folders/${each.value}"
  service = "iamcredentials.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

# Org-wide aggregated log sink -> Pub/Sub, gated by `enabled`
# (deployment_mode == "full"). google_logging_organization_sink does not
# support the `labels` argument -- GCP log sinks don't have resource
# labels, so this module is the one place in the stack without them.
#
# The sink's `writer_identity` is a service-agent identity GCP computes at
# creation time (not knowable in advance), so granting it publish rights on
# the destination topic is necessarily a two-step dependency: sink first,
# then an IAM binding using the sink's own output.

resource "google_logging_organization_sink" "audit_activity" {
  count = var.enabled ? 1 : 0

  name             = var.sink_name
  org_id           = var.org_id
  destination      = "pubsub.googleapis.com/${var.destination_topic_id}"
  filter           = local.effective_filter
  include_children = true

  description = "Org-wide Admin Activity audit logs, aggregated for the alerting pipeline."
}

resource "google_pubsub_topic_iam_member" "sink_writer" {
  count = var.enabled ? 1 : 0

  project = var.destination_project_id
  topic   = var.destination_topic_name
  role    = "roles/pubsub.publisher"
  member  = google_logging_organization_sink.audit_activity[0].writer_identity
}

# Project-scoped sink -- an interim/fallback path so destination_project_id's
# OWN audit logs reach the pipeline even when the org-level sink above is
# disabled ("project_only" mode). Needs no org-level permissions: the apply
# SA already has project-level roles/logging.admin (terraform/bootstrap).
# See `project_sink_enabled`'s description for why this and the org sink
# are meant to be mutually exclusive, not both on at once.
resource "google_logging_project_sink" "audit_activity" {
  count = var.project_sink_enabled ? 1 : 0

  name                   = "${var.sink_name}-project"
  project                = var.destination_project_id
  destination            = "pubsub.googleapis.com/${var.destination_topic_id}"
  filter                 = local.effective_filter
  unique_writer_identity = true

  description = "This project's own Admin Activity audit logs, feeding the alerting pipeline while the org-level sink is disabled."
}

resource "google_pubsub_topic_iam_member" "project_sink_writer" {
  count = var.project_sink_enabled ? 1 : 0

  project = var.destination_project_id
  topic   = var.destination_topic_name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.audit_activity[0].writer_identity
}

# Explicitly-named additional projects to monitor, each via its own
# project-level sink forwarding to the SAME central topic in
# destination_project_id -- a middle ground when org-level monitoring
# (the sink above, gated by `enabled`) isn't available yet (needs
# org-admin access) but specific other projects still need coverage now.
# Each project in this list needs the apply SA granted roles/logging.admin
# at THAT project's level (not org-level) before it can be added here --
# see the root module's README/runbook for the exact grant command.
resource "google_logging_project_sink" "additional_monitored" {
  for_each = toset(var.additional_monitored_project_ids)

  name                   = "${var.sink_name}-project"
  project                = each.value
  destination            = "pubsub.googleapis.com/${var.destination_topic_id}"
  filter                 = local.effective_filter
  unique_writer_identity = true

  description = "Admin Activity audit logs from ${each.value}, feeding the central alerting pipeline in ${var.destination_project_id}."
}

resource "google_pubsub_topic_iam_member" "additional_monitored_writer" {
  for_each = google_logging_project_sink.additional_monitored

  project = var.destination_project_id
  topic   = var.destination_topic_name
  role    = "roles/pubsub.publisher"
  member  = each.value.writer_identity
}

# Folder-scoped sinks -- covers a folder AND everything nested under it
# (sub-folders, every current and future project in them) via
# include_children, without a grant or sink per individual project. Unlike
# the org-level sink, folders NOT listed here stay completely uncovered --
# lets you deliberately keep e.g. a sandbox/pre-production folder quiet
# and only start alerting on a project once it's moved into a monitored
# folder. Each folder here needs the apply SA granted roles/logging.admin
# at THAT folder's level first.
resource "google_logging_folder_sink" "monitored_folder" {
  for_each = toset(var.monitored_folder_ids)

  name             = "${var.sink_name}-folder"
  folder           = each.value
  destination      = "pubsub.googleapis.com/${var.destination_topic_id}"
  filter           = local.effective_filter
  include_children = true

  description = "Admin Activity audit logs from folder ${each.value} and everything nested under it, feeding the central alerting pipeline in ${var.destination_project_id}."
}

resource "google_pubsub_topic_iam_member" "monitored_folder_writer" {
  for_each = google_logging_folder_sink.monitored_folder

  project = var.destination_project_id
  topic   = var.destination_topic_name
  role    = "roles/pubsub.publisher"
  member  = each.value.writer_identity
}
