# Keyless auth: both providers impersonate the Terraform apply service
# account (created once in terraform/bootstrap/) rather than using a key
# file. Locally, this relies on your own `gcloud auth application-default
# login` identity holding roles/iam.serviceAccountTokenCreator on that SA;
# in CI, google-github-actions/auth already authenticates as this exact SA
# via Workload Identity Federation, so the impersonation call is a
# self-impersonation token mint (see terraform/bootstrap/main.tf for the
# self-grant that makes that work).

provider "google" {
  project                     = var.project_id
  region                      = var.region
  impersonate_service_account = var.terraform_deploy_service_account_email
}

# Only needed for modules/mute_web's google_cloud_run_v2_service.iap_enabled,
# which is still a Beta-launch-stage field on the GA google provider as of
# v6.50.0 (confirmed against that exact installed version's own docs --
# earlier attempts elsewhere in this repo to guess provider schema instead
# of checking it directly have cost real apply-time failures, not just
# plan-time ones).
provider "google-beta" {
  project                     = var.project_id
  region                      = var.region
  impersonate_service_account = var.terraform_deploy_service_account_email
}
