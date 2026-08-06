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

resource "google_project_service_identity" "pubsub" {
  provider = google-beta
  project  = var.project_id
  service  = "pubsub.googleapis.com"
}

# NOT a Terraform ordering bug -- the IAM member below already has an
# implicit dependency on the service identity via the direct attribute
# reference in service_account_id, so Terraform already sequences these
# calls correctly. The 404 is a genuine GCP eventual-consistency race:
# google_project_service_identity reports success (and returns an email)
# before the resulting Google-managed service agent is reliably readable
# by other APIs for IAM operations. depends_on wouldn't fix this -- it
# only controls order, not wall-clock delay. This deliberate wait does.
resource "time_sleep" "wait_for_pubsub_service_identity" {
  create_duration = "30s"

  depends_on = [google_project_service_identity.pubsub]
}

resource "google_service_account_iam_member" "pubsub_sa_token_creator" {
  service_account_id = "projects/${var.project_id}/serviceAccounts/${google_project_service_identity.pubsub.email}"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_project_service_identity.pubsub.email}"

  depends_on = [time_sleep.wait_for_pubsub_service_identity]
}
