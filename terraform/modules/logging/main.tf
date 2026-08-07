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
  filter           = var.filter
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
  filter                 = var.filter
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
