output "workload_identity_pool_name" {
  description = "Full resource name of the Workload Identity Pool."
  value       = google_iam_workload_identity_pool.github.name
}

output "plan_provider_resource_name" {
  description = "Full resource name of the plan-only WIF provider -- set as GH Actions var TF_PLAN_WIF_PROVIDER."
  value       = google_iam_workload_identity_pool_provider.github_plan.name
}

output "apply_provider_resource_name" {
  description = "Full resource name of the apply-capable WIF provider -- set as GH Actions var TF_APPLY_WIF_PROVIDER."
  value       = google_iam_workload_identity_pool_provider.github_apply.name
}

output "plan_service_account_email" {
  description = "Plan-only deploy SA email -- set as GH Actions var TF_PLAN_SERVICE_ACCOUNT."
  value       = google_service_account.terraform_plan.email
}

output "apply_service_account_email" {
  description = "Apply-capable deploy SA email -- set as GH Actions var TF_APPLY_SERVICE_ACCOUNT."
  value       = google_service_account.terraform_apply.email
}
