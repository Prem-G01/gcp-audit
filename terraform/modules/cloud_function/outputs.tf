output "function_name" {
  value = google_cloudfunctions2_function.process_audit_log.name
}

output "function_uri" {
  value = google_cloudfunctions2_function.process_audit_log.url
}

output "cloud_run_service_name" {
  value = google_cloudfunctions2_function.process_audit_log.name
}
