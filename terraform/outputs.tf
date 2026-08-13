output "main_topic_name" {
  value = module.pubsub.main_topic_name
}

output "dlq_topic_name" {
  value = module.pubsub.dlq_topic_name
}

output "dlq_exhausted_topic_name" {
  value = module.pubsub.dlq_exhausted_topic_name
}

output "function_name" {
  value = module.cloud_function.function_name
}

output "function_uri" {
  value = module.cloud_function.function_uri
}

output "bigquery_dataset_id" {
  value = module.bigquery.dataset_id
}

output "bigquery_table_fqn" {
  value = module.bigquery.table_fqn
}

output "runtime_service_account_email" {
  value = data.google_service_account.runtime.email
}

output "org_sink_writer_identity" {
  description = "null unless deployment_mode = \"full\"."
  value       = module.logging.sink_writer_identity
}

output "project_sink_writer_identity" {
  description = "null once deployment_mode = \"full\" (the org sink takes over)."
  value       = module.logging.project_sink_writer_identity
}

output "additional_monitored_project_writer_identities" {
  description = "Map of project_id -> writer_identity, one per entry in additional_monitored_project_ids."
  value       = module.logging.additional_monitored_project_writer_identities
}

output "monitored_folder_writer_identities" {
  description = "Map of folder_id -> writer_identity, one per entry in monitored_folder_ids."
  value       = module.logging.monitored_folder_writer_identities
}

output "mute_web_service_url" {
  description = "Also injected into the pipeline function as MUTE_SERVICE_URL."
  value       = module.mute_web.service_url
}

output "mute_web_artifact_registry_repository" {
  description = "Push images here (see scripts/deploy_mute_web.ps1/.sh)."
  value       = module.mute_web.artifact_registry_repository
}
