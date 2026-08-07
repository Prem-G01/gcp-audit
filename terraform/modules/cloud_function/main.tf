# Cloud Function v2 (process_audit_log) + its source archive/upload +
# every IAM binding the Eventarc/Pub/Sub trigger wiring needs beyond the
# application-level permissions in the iam module.
#
# NOTE on cache excludes: hashicorp/archive's `excludes` matches relative
# paths at the level given, not a recursive glob into every subdirectory --
# fine here because CI always applies from a fresh `actions/checkout` (no
# stray __pycache__ dirs to begin with); a local `terraform apply` from a
# dev checkout may bundle a few harmless stray .pyc caches.

data "archive_file" "function_source" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/.build/function-source.zip"

  excludes = [
    ".git", ".github", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".claude",
    "terraform", "tests", "docs", "scripts",
    ".env", ".env.example", ".gitignore", ".gitattributes",
    "requirements-dev.txt", "pyproject.toml", "README.md", "CLAUDE.md",
  ]
}

resource "google_storage_bucket" "function_source" {
  project                     = var.project_id
  name                        = "${var.project_id}-function-source"
  location                    = var.region
  uniform_bucket_level_access = true
  labels                      = var.labels

  versioning {
    enabled = true
  }
}

resource "google_storage_bucket_object" "function_source" {
  name   = "source-${data.archive_file.function_source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.function_source.output_path
}

resource "google_cloudfunctions2_function" "process_audit_log" {
  project  = var.project_id
  name     = var.function_name
  location = var.region
  labels   = var.labels

  build_config {
    runtime     = "python312"
    entry_point = "process_audit_log"
    # Without this, Cloud Build (which performs the actual build behind
    # google_cloudfunctions2_function) defaults to the project's implicit
    # default Compute Engine SA (PROJECT_NUMBER-compute@developer.gserv
    # iceaccount.com) -- an identity nothing else in this stack references
    # or grants actAs on. Point it at the runtime SA instead, which the
    # apply SA already has roles/iam.serviceAccountUser on (see
    # terraform/bootstrap/main.tf's apply_runtime_sa_user) -- no new IAM
    # grant needed.
    service_account = "projects/${var.project_id}/serviceAccounts/${var.runtime_service_account_email}"
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    available_memory      = var.memory
    timeout_seconds       = var.timeout_seconds
    max_instance_count    = var.max_instances
    service_account_email = var.runtime_service_account_email

    environment_variables = {
      GMAIL_DELEGATED_SA    = var.runtime_service_account_email
      GMAIL_SENDER          = var.gmail_sender
      GMAIL_SENDER_NAME     = var.gmail_sender_name
      GMAIL_MAX_ATTEMPTS    = tostring(var.gmail_max_attempts)
      GMAIL_TIMEOUT         = tostring(var.gmail_timeout_seconds)
      CAI_CACHE_TTL_SECONDS = tostring(var.cai_cache_ttl_seconds)
      CAI_TIMEOUT_SECONDS   = tostring(var.cai_timeout_seconds)
      VERTEX_PROJECT        = var.project_id
      VERTEX_LOCATION       = var.vertex_location
      GEMINI_MODEL          = var.gemini_model
      GEMINI_MAX_TOKENS     = tostring(var.gemini_max_tokens)
      GEMINI_TIMEOUT        = tostring(var.gemini_timeout_seconds)
      BQ_PROJECT            = var.project_id
      BQ_DATASET            = var.bq_dataset_id
      BQ_TABLE              = var.bq_table_id
      DLQ_TOPIC             = var.dlq_topic_name
      DLQ_PROJECT           = var.project_id
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = var.main_topic_id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = var.runtime_service_account_email
  }
}

# --- Eventarc/Pub/Sub trigger wiring IAM -- required for the trigger to
# actually invoke the function; `gcloud functions deploy` sets these up
# silently, Terraform needs them explicit. -------------------------------

resource "google_project_iam_member" "eventarc_event_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = "serviceAccount:${var.runtime_service_account_email}"
}

# Assumes the underlying Cloud Run service shares the function's name,
# which is GCP's standard behavior for a Gen2 function created fresh.
resource "google_cloud_run_v2_service_iam_member" "invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloudfunctions2_function.process_audit_log.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.runtime_service_account_email}"
}

# Required because build_config.service_account (above) points Cloud Build
# at the runtime SA instead of the default compute SA. The default compute
# SA has broad implicit access historically; our deliberately narrow
# runtime SA does not, and needs this explicitly to pull/push build
# layers and cache to the "gcf-artifacts" Artifact Registry repo Cloud
# Functions auto-manages. Project-scoped, not repo-scoped, because that
# repository doesn't exist until the first successful build creates it --
# a genuine chicken-and-egg case, unlike every other binding in this
# stack, which are all resource-scoped.
resource "google_project_iam_member" "build_artifact_registry_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${var.runtime_service_account_email}"
}

# REMOVED (was: google_project_service_identity.pubsub +
# time_sleep.wait_for_pubsub_service_identity +
# google_service_account_iam_member.pubsub_sa_token_creator).
#
# This chain granted roles/iam.serviceAccountTokenCreator to the Pub/Sub
# service agent on itself, to support authenticated Pub/Sub push
# requests. Verified against Google's own documentation: that grant is
# only needed for service agents enabled on or before April 8, 2021 --
# for any project created after that date (this one included), the role
# is already granted by default. Three separate attempts to fix a
# persistent 404 by waiting longer (30s, then 90s, then 180s, each
# confirmed as a genuine fresh wait via the `triggers` mechanism) all
# failed because there was nothing to wait for -- the underlying
# assumption that this grant was necessary was wrong from the start, not
# a timing problem. Removing it outright, not waiting longer for it.
