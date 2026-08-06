# BigQuery dataset + table for persisted alert findings.
#
# Migrated from the original flat terraform/bigquery.tf -- schema,
# partitioning (DAY on event_timestamp), and clustering (severity, rule_id)
# are unchanged from that version, just parameterized and labeled.

resource "google_bigquery_dataset" "audit_platform" {
  project    = var.project_id
  dataset_id = var.dataset_id
  location   = var.region
  labels     = var.labels

  description = "GCP audit platform alert findings and delivery outcomes."
}

resource "google_bigquery_table" "alert_events" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.audit_platform.dataset_id
  table_id   = var.table_id
  labels     = var.labels

  time_partitioning {
    type  = "DAY"
    field = "event_timestamp"
  }

  clustering = ["severity", "rule_id"]

  schema = jsonencode([
    { name = "event_timestamp", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "ingest_timestamp", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "rule_id", type = "STRING", mode = "REQUIRED" },
    { name = "severity", type = "STRING", mode = "REQUIRED" },
    { name = "title", type = "STRING", mode = "REQUIRED" },
    { name = "project_id", type = "STRING", mode = "NULLABLE" },
    { name = "resource_name", type = "STRING", mode = "NULLABLE" },
    { name = "resource_type", type = "STRING", mode = "NULLABLE" },
    { name = "principal_email", type = "STRING", mode = "NULLABLE" },
    { name = "method_name", type = "STRING", mode = "NULLABLE" },
    { name = "caller_ip", type = "STRING", mode = "NULLABLE" },
    { name = "ai_analysis", type = "STRING", mode = "NULLABLE" },
    { name = "enrichment_ok", type = "BOOL", mode = "REQUIRED" },
    { name = "recipients", type = "STRING", mode = "REPEATED" },
    { name = "gmail_message_id", type = "STRING", mode = "NULLABLE" },
    { name = "delivery_status", type = "STRING", mode = "REQUIRED" },
    { name = "delivery_error", type = "STRING", mode = "NULLABLE" },
    { name = "raw_log_id", type = "STRING", mode = "NULLABLE" },
  ])
}

# Dataset-scoped, not project-scoped -- least privilege for insert_rows_json.
resource "google_bigquery_dataset_iam_member" "runtime_data_editor" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.audit_platform.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${var.runtime_service_account_email}"
}
