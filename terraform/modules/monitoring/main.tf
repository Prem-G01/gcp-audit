# Log-based metrics + alert policies for the pipeline's already-caught
# failure classes, plus coarse function-health signals.
#
# IMPORTANT: main.py configures plain `logging.basicConfig(level=
# logging.INFO)` with no JSON formatter (verified by reading the frozen
# source, not assumed) -- so structured `extra={...}` fields do NOT surface
# as Cloud Logging jsonPayload. Every log line lands as plain textPayload
# (Cloud Run's logging agent only parses a line into jsonPayload if the
# line itself is valid JSON). These filters therefore match on
# `textPayload:"..."` substring search against the log message names the
# app already emits, not precise structured field equality. If a future
# round adds a JSON log formatter to src/, these filters should switch to
# `jsonPayload.message=`. google_logging_metric does not support the
# `labels` resource-label argument -- log-based metrics don't have GCP
# resource labels (noted, not silently skipped, same as the logging sink).

locals {
  failure_metrics = {
    audit_platform_gmail_send_failures = {
      display_name = "Gmail send failures"
      needle       = "gmail_alert_send_failed"
    }
    audit_platform_dlq_write_failures = {
      display_name = "DLQ write failures"
      needle       = "dlq_write_failed"
    }
    audit_platform_bigquery_persist_failures = {
      display_name = "BigQuery persist failures"
      needle       = "bigquery_persist_failed"
    }
    audit_platform_payload_decode_failures = {
      display_name = "Malformed Pub/Sub payloads"
      needle       = "payload_decode_failed"
    }
    audit_platform_finding_processing_failures = {
      display_name = "Unexpected per-finding failures"
      needle       = "finding_processing_failed"
    }
  }
}

resource "google_logging_metric" "failure_counters" {
  for_each = local.failure_metrics

  project     = var.project_id
  name        = each.key
  description = "Count of \"${each.value.needle}\" log lines from the audit platform Cloud Function."
  filter      = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.function_name}\" AND textPayload:\"${each.value.needle}\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# 1. Coarse function health: any non-"ok" execution status.
resource "google_monitoring_alert_policy" "function_error_rate" {
  project      = var.project_id
  display_name = "audit-platform: Cloud Function execution errors"
  combiner     = "OR"
  user_labels  = var.labels

  conditions {
    display_name = "Non-ok executions"
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND resource.labels.function_name=\"${var.function_name}\" AND metric.type=\"cloudfunctions.googleapis.com/function/execution_count\" AND metric.labels.status!=\"ok\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = var.notification_channels
}

# 2. DLQ depth: a nonzero, sustained backlog means nobody is draining it.
resource "google_monitoring_alert_policy" "dlq_depth" {
  project      = var.project_id
  display_name = "audit-platform: DLQ has undelivered messages"
  combiner     = "OR"
  user_labels  = var.labels

  conditions {
    display_name = "DLQ drain subscription backlog > 0 for 15m"
    condition_threshold {
      filter          = "resource.type=\"pubsub_subscription\" AND resource.labels.subscription_id=\"${var.dlq_drain_subscription_name}\" AND metric.type=\"pubsub.googleapis.com/subscription/num_undelivered_messages\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "900s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = var.notification_channels
}

# 3. Silent breakage canary: zero executions for a full hour is suspicious
# for an org-wide audit log pipeline (the sink stopped exporting, the
# Eventarc trigger broke, etc.) -- otherwise invisible since nothing here
# raises an exception.
resource "google_monitoring_alert_policy" "execution_count_absent" {
  project      = var.project_id
  display_name = "audit-platform: no function executions in 1h"
  combiner     = "OR"
  user_labels  = var.labels

  conditions {
    display_name = "execution_count absent"
    condition_absent {
      filter   = "resource.type=\"cloud_function\" AND resource.labels.function_name=\"${var.function_name}\" AND metric.type=\"cloudfunctions.googleapis.com/function/execution_count\""
      duration = "3600s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = var.notification_channels
}

# A freshly created log-based metric is not immediately queryable by the
# alert-policy API -- unlike the pubsub-service-identity issue elsewhere in
# this stack (which turned out to be unnecessary entirely), this one is a
# real, GCP-acknowledged propagation delay: the 404 error itself states
# "If a metric was created recently, it could take up to 10 minutes to
# become available." Using that stated bound directly rather than guessing
# at a smaller number and risking another failed apply cycle.
resource "time_sleep" "wait_for_failure_metrics" {
  create_duration = "600s"

  depends_on = [google_logging_metric.failure_counters]
}

# 4. The app's own caught-and-logged failures (Gmail/BigQuery/DLQ/decode) --
# these deliberately don't fail the function (constraint: never block the
# email), which is exactly why they need external alerting instead of
# relying on policy 1 above.
resource "google_monitoring_alert_policy" "caught_failures" {
  project      = var.project_id
  display_name = "audit-platform: caught pipeline failures"
  combiner     = "OR"
  user_labels  = var.labels

  dynamic "conditions" {
    for_each = local.failure_metrics
    content {
      display_name = "${conditions.value.display_name} > 0"
      condition_threshold {
        filter          = "resource.type=\"cloud_run_revision\" AND metric.type=\"logging.googleapis.com/user/${conditions.key}\""
        comparison      = "COMPARISON_GT"
        threshold_value = 0
        duration        = "0s"

        aggregations {
          alignment_period   = "300s"
          per_series_aligner = "ALIGN_SUM"
        }
      }
    }
  }

  notification_channels = var.notification_channels

  depends_on = [time_sleep.wait_for_failure_metrics]
}
