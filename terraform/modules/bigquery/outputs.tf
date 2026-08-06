output "dataset_id" {
  value = google_bigquery_dataset.audit_platform.dataset_id
}

output "table_id" {
  value = google_bigquery_table.alert_events.table_id
}

output "table_fqn" {
  description = "project.dataset.table"
  value       = "${var.project_id}.${google_bigquery_dataset.audit_platform.dataset_id}.${google_bigquery_table.alert_events.table_id}"
}
