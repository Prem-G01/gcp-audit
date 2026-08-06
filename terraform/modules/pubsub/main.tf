# Pub/Sub topics for the audit pipeline.
#
# IMPORTANT ASYMMETRY: this module does NOT create a subscription on
# `main_topic` -- the Cloud Function's Eventarc trigger (wired up in the
# cloud_function module) auto-creates and owns its own subscription on this
# topic, which Terraform cannot directly manage a dead-letter policy for
# (see scripts/configure_eventarc_dlq.ps1/.sh, run once after apply). Don't
# go looking for a google_pubsub_subscription resource for the main topic
# here -- there isn't one.
#
# The DLQ topic DOES get a Terraform-managed pull subscription for ops to
# drain it, with its own dead-letter policy forwarding to a third,
# subscription-less "exhausted" topic -- every subscription this module
# creates has both a dead-letter policy and a retry policy, per platform
# constraint (no infinite redelivery, including for the DLQ itself).

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_pubsub_topic" "main" {
  project = var.project_id
  name    = var.main_topic_name
  labels  = var.labels
}

resource "google_pubsub_topic" "dlq" {
  project = var.project_id
  name    = var.dlq_topic_name
  labels  = var.labels
}

# Final landing zone if even DLQ redelivery is exhausted (e.g. nobody drains
# it in time). No subscription here deliberately -- this is where automatic
# redelivery stops; a human inspects it via `gcloud pubsub subscriptions
# pull` after creating an ad-hoc subscription, or via a log-based alert on
# this topic's un-acked message count (see the monitoring module).
resource "google_pubsub_topic" "dlq_exhausted" {
  project = var.project_id
  name    = "${var.dlq_topic_name}-exhausted"
  labels  = var.labels
}

resource "google_pubsub_subscription" "dlq_drain" {
  project = var.project_id
  name    = "${var.dlq_topic_name}-drain"
  topic   = google_pubsub_topic.dlq.id
  labels  = var.labels

  ack_deadline_seconds       = 60
  message_retention_duration = "604800s" # 7 days

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dlq_exhausted.id
    max_delivery_attempts = 5
  }
}

# Pub/Sub's own service agent must be able to publish to the dead-letter
# topic and pull+ack from the source subscription for dead-lettering itself
# to function -- required by GCP, not optional.
resource "google_pubsub_topic_iam_member" "dlq_exhausted_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.dlq_exhausted.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_pubsub_subscription_iam_member" "dlq_drain_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.dlq_drain.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}
