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
