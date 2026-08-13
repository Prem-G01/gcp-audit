# Cloud Run service backing the "Mute this alert" link in every alert
# email (see mute_web/app.py). Deliberately a separate plain Cloud Run
# service, not part of the Cloud Functions Gen2 pipeline -- IAP's direct,
# no-load-balancer integration (`iap_enabled` below) is only available on
# Cloud Run, not on Cloud Functions Gen2, even though Gen2 is itself
# Cloud-Run-backed under the hood.
#
# Access control has two independent layers:
#   1. IAP itself (iap_enabled + the httpsResourceAccessor grant below) --
#      only the principals in var.admin_members can reach the service at all.
#   2. mute_web/app.py additionally verifies IAP's signed JWT server-side
#      and records the real caller email as `muted_by` -- defense in depth,
#      not a substitute for layer 1.

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_service_account" "mute_web" {
  project      = var.project_id
  account_id   = "mute-web-sa"
  display_name = "Mute-button web service (Cloud Run)"
}

# Firestore read+write -- this SA creates/clears mute documents on behalf
# of whichever admin clicked the email link (main.py's runtime SA, by
# contrast, only ever reads mute state -- see modules/firestore).
resource "google_project_iam_member" "mute_web_datastore_user" {
  project = var.firestore_project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.mute_web.email}"
}

# The deploy SA's project-wide roles/iam.serviceAccountAdmin (granted in
# terraform/bootstrap) covers *managing* IAM policy on this SA (i.e.
# creating this very binding) but not actAs itself -- that's the separate
# permission bundled only in roles/iam.serviceAccountUser, and unlike the
# pre-existing runtime SA, nothing grants it on this freshly-created SA
# until this resource does. Without it, attaching mute-web to the Cloud
# Run service below fails with a 403 on iam.serviceAccounts.actAs.
resource "google_service_account_iam_member" "deploy_sa_can_actas_mute_web" {
  service_account_id = google_service_account.mute_web.name
  role                = "roles/iam.serviceAccountUser"
  member              = "serviceAccount:${var.terraform_deploy_service_account_email}"
}

# IAM writes are eventually consistent -- without this, google_cloud_run_v2
# _service.mute_web (below) has no dependency on the actAs grant above (both
# only depend on the SA resource, not on each other), so Terraform is free
# to create them in parallel and the Cloud Run create can race ahead of the
# grant, or land right after it before it's actually propagated. 60s is the
# commonly-cited bound for IAM propagation, not a GCP-documented guarantee
# the way the monitoring module's metric-availability wait is -- if this
# still races occasionally, increase it before adding retry logic.
resource "time_sleep" "wait_for_actas_propagation" {
  create_duration = "60s"

  depends_on = [google_service_account_iam_member.deploy_sa_can_actas_mute_web]
}

resource "google_artifact_registry_repository" "mute_web" {
  project       = var.project_id
  location      = var.region
  repository_id = "mute-web"
  format        = "DOCKER"
  description   = "Container images for the mute-web Cloud Run service."
  labels        = var.labels
}

resource "google_cloud_run_v2_service" "mute_web" {
  # iap_enabled is still a Beta launch-stage field on the GA google
  # provider (confirmed against the exact provider version pinned in
  # versions.tf) -- requires both the google-beta provider and
  # launch_stage = "BETA" below.
  provider = google-beta

  project      = var.project_id
  name         = var.service_name
  location     = var.region
  labels       = var.labels
  launch_stage = "BETA"
  iap_enabled  = true

  # Required for IAP to front this service at all -- IAP fails closed
  # (403) on any request that doesn't carry its own signed assertion, so
  # opening ingress here does not bypass access control.
  ingress = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.mute_web.email

    containers {
      image = var.image

      env {
        name  = "FIRESTORE_PROJECT"
        value = var.firestore_project_id
      }
      env {
        name  = "IAP_AUDIENCE"
        value = "/projects/${data.google_project.this.number}/locations/${var.region}/services/${var.service_name}"
      }

      ports {
        container_port = 8080
      }
    }

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image]
  }

  depends_on = [time_sleep.wait_for_actas_propagation]
}

# The IAP service agent is what actually invokes this Cloud Run service on
# a verified caller's behalf -- without this grant, IAP itself gets a 403
# calling through to the backend and every request dead-ends there.
resource "google_cloud_run_v2_service_iam_member" "iap_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.mute_web.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-iap.iam.gserviceaccount.com"
}

# The actual human-access grant: only these principals can pass IAP's
# check. One binding per entry in var.admin_members -- add a name, append
# to the list, re-apply.
resource "google_iap_web_cloud_run_service_iam_member" "admin_access" {
  for_each               = toset(var.admin_members)
  project                = var.project_id
  location               = var.region
  cloud_run_service_name = google_cloud_run_v2_service.mute_web.name
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = each.value
}
