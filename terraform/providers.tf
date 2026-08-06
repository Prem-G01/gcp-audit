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

provider "google-beta" {
  project                     = var.project_id
  region                      = var.region
  impersonate_service_account = var.terraform_deploy_service_account_email
}
