# Least-privilege application permissions for the pre-existing runtime SA.
# Never roles/owner, roles/editor, or any *.admin/organizationAdmin role.
# Resource-scoped wherever GCP supports it; project-level only where GCP
# offers no finer grain (cloudasset.viewer, aiplatform.user).
#
# NOT here: roles/bigquery.dataEditor (dataset-scoped, lives in the
# bigquery module next to the dataset it applies to) and the
# Eventarc/Cloud Run invocation bindings (function-scoped, live in the
# cloud_function module next to the function they apply to). Keeping each
# binding next to the resource it's scoped to avoids an implicit ordering
# dependency between unrelated modules.

# Self-grant: signJwt (src/senders/gmail_sender.py) requires the caller to
# hold serviceAccountTokenCreator on the SA being signed as -- here, that's
# the runtime SA signing as itself.
resource "google_service_account_iam_member" "self_token_creator" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${var.runtime_service_account_email}"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${var.runtime_service_account_email}"
}

# Cloud Asset Inventory search_all_resources -- no dataset/resource-scoped
# equivalent exists for this role; project-level is the minimum GCP offers.
resource "google_project_iam_member" "cloud_asset_viewer" {
  project = var.project_id
  role    = "roles/cloudasset.viewer"
  member  = "serviceAccount:${var.runtime_service_account_email}"
}

# write_to_dlq() publish rights -- topic-scoped, not project-scoped.
resource "google_pubsub_topic_iam_member" "dlq_publisher" {
  project = var.project_id
  topic   = var.dlq_topic_name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${var.runtime_service_account_email}"
}

# Gemini calls via Vertex AI -- no finer-grained resource-level IAM exists
# for this typical generate_content usage; project-level is standard here.
resource "google_project_iam_member" "vertex_ai_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${var.runtime_service_account_email}"
}
