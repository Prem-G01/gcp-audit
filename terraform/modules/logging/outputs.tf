output "sink_writer_identity" {
  description = "null when disabled (deployment_mode == \"project_only\")."
  value       = var.enabled ? google_logging_organization_sink.audit_activity[0].writer_identity : null
}

output "sink_name" {
  value = var.enabled ? google_logging_organization_sink.audit_activity[0].name : null
}
