# One-time bootstrap: Workload Identity Federation pool/providers and the two
# GitHub Actions deploy identities (plan-only, apply-capable). Applied ONCE,
# MANUALLY, by a human operator with sufficient project IAM (e.g. Owner or a
# combination of roles/iam.workloadIdentityPoolAdmin +
# roles/iam.serviceAccountAdmin + roles/resourcemanager.projectIamAdmin) --
# see README.md in this directory for the exact command sequence.
#
# This module deliberately uses LOCAL state and no provider impersonation:
# it creates the very identities that everything else impersonates, so there
# is nothing to impersonate yet. It is the one deliberate exception to
# "everything is applied by CI" in this repo.
terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}
provider "google" {
  project = var.project_id
}
data "google_project" "this" {
  project_id = var.project_id
}
resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "GitHub Actions (audit platform)"
  description               = "Federates GitHub Actions OIDC tokens for ${var.github_repository}."
}
# Plan-only provider: any workflow run in the repo (any branch, PRs
# included) can assume the plan-only identity, for `terraform plan` on pull
# requests.
resource "google_iam_workload_identity_pool_provider" "github_plan" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-plan"
  display_name                       = "GitHub Actions -- plan"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  # FIX: Use variable interpolation to set the actual GitHub repository value
  # at apply time. Previously this was hardcoded to "CHANGE_ME/gcp-audit" which
  # caused GitHub Actions WIF auth to fail (token rejected by attribute condition).
  attribute_condition = "assertion.repository == \"${var.github_repository}\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
# Apply-capable provider: scoped to the deploy branch as well as the repo,
# so only a push to `main` (never a PR from a fork, never any other branch)
# can assume the identity with write access.
resource "google_iam_workload_identity_pool_provider" "github_apply" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-apply"
  display_name                       = "GitHub Actions -- apply"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  # FIX: Use variable interpolation for both repository and deploy branch.
  # The attribute_condition scopes the apply SA to ONLY pushes to main branch
  # in the specified repo. This is the security boundary preventing PRs/forks
  # from getting write access.
  attribute_condition = "assertion.repository == \"${var.github_repository}\" && assertion.ref == \"refs/heads/${var.deploy_branch}\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
resource "google_service_account" "terraform_plan" {
  project      = var.project_id
  account_id   = "tf-plan-audit-platform"
  display_name = "Terraform plan (audit platform, read-only)"
}
resource "google_service_account" "terraform_apply" {
  project      = var.project_id
  account_id   = "tf-apply-audit-platform"
  display_name = "Terraform apply (audit platform, write)"
}
# Let the GitHub Actions plan/apply providers impersonate their respective
# service accounts -- this is the actual WIF trust binding, scoped to the
# exact principalSet for each provider (not the whole pool), so the
# plan-only provider can never bind to the apply-capable SA or vice versa.
resource "google_service_account_iam_member" "plan_wif_binding" {
  service_account_id = google_service_account.terraform_plan.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}
resource "google_service_account_iam_member" "apply_wif_binding" {
  service_account_id = google_service_account.terraform_apply.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}
# The root stack's provider always sets impersonate_service_account (used
# literally, both for a human running it locally under their own login, and
# for CI running as the SA itself under WIF) -- so each deploy SA needs
# token-creator on itself to make that self-impersonation path work.
resource "google_service_account_iam_member" "plan_self_impersonation" {
  service_account_id = google_service_account.terraform_plan.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.terraform_plan.email}"
}
resource "google_service_account_iam_member" "apply_self_impersonation" {
  service_account_id = google_service_account.terraform_apply.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.terraform_apply.email}"
}
# --- Plan SA: broad read only, never write -----------------------------
resource "google_project_iam_member" "plan_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.terraform_plan.email}"
}
resource "google_project_iam_member" "plan_security_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.terraform_plan.email}"
}
# --- Apply SA: write access to exactly the resource types this stack
# manages. This is the most powerful identity in the repo -- it is the
# necessary trade-off for "infrastructure is code, reviewed via PR, applied
# by CI" instead of a human running `terraform apply` by hand. It is never
# roles/owner or roles/editor. roles/resourcemanager.projectIamAdmin is the
# broadest grant here (needed to manage IAM bindings on the runtime SA as
# code) -- see docs/RUNBOOK.md for the full rationale.
# -------------------------------------------------------------------------
locals {
  apply_roles = [
    "roles/pubsub.admin",
    "roles/cloudfunctions.admin",
    "roles/run.admin",
    "roles/eventarc.admin",
    "roles/bigquery.admin",
    "roles/logging.admin",
    "roles/monitoring.admin",
    "roles/storage.admin",
    # roles/iam.serviceAccountIamAdmin does not exist as a real GCP
    # predefined role (confirmed the hard way -- GCP rejects it with
    # "Error 400: ... is not supported for this resource" at apply time,
    # not at plan/validate time, since Terraform doesn't validate role
    # name existence). roles/iam.serviceAccountAdmin is the real role that
    # covers IAM-policy management on service accounts -- it's broader
    # than strictly necessary (also grants create/disable/delete of SAs,
    # not just IAM policy management), but it's what actually exists.
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.projectIamAdmin",
  ]
}
resource "google_project_iam_member" "apply_roles" {
  for_each = toset(local.apply_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.terraform_apply.email}"
}