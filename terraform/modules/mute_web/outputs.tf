output "service_url" {
  description = "The Cloud Run service URL -- becomes MUTE_SERVICE_URL for the pipeline function's env vars."
  value       = google_cloud_run_v2_service.mute_web.uri
}

output "service_name" {
  value = google_cloud_run_v2_service.mute_web.name
}

output "service_account_email" {
  value = google_service_account.mute_web.email
}

output "artifact_registry_repository" {
  description = "Full repository id -- used by scripts/deploy_mute_web.ps1/.sh to build the image reference."
  value       = google_artifact_registry_repository.mute_web.id
}
