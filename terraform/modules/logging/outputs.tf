output "sink_writer_identity" {
  description = "null when disabled (deployment_mode == \"project_only\")."
  value       = var.enabled ? google_logging_organization_sink.audit_activity[0].writer_identity : null
}

output "sink_name" {
  value = var.enabled ? google_logging_organization_sink.audit_activity[0].name : null
}

output "project_sink_writer_identity" {
  description = "null when disabled (org sink is active, or deployment_mode == \"full\")."
  value       = var.project_sink_enabled ? google_logging_project_sink.audit_activity[0].writer_identity : null
}

output "project_sink_name" {
  value = var.project_sink_enabled ? google_logging_project_sink.audit_activity[0].name : null
}

output "additional_monitored_project_writer_identities" {
  description = "Map of project_id -> writer_identity, one per entry in additional_monitored_project_ids."
  value       = { for project_id, sink in google_logging_project_sink.additional_monitored : project_id => sink.writer_identity }
}
