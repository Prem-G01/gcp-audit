# Root module: composition only. No raw resources here -- every resource
# lives in a child module under modules/.

locals {
  labels = {
    managed-by  = "terraform"
    platform    = "audit-alerting"
    environment = var.environment
  }

  # terraform/ is one directory below the repo root; path.root always
  # refers to this root module's own directory regardless of which module
  # evaluates it, so this resolves consistently everywhere it's used.
  app_source_dir = abspath("${path.root}/..")

  # See project_sink_enabled_override's description: null means "derive
  # from deployment_mode" (the original behavior); a non-null value lets a
  # folder/org sink that already covers project_id's own folder switch
  # this off explicitly, avoiding double-published events.
  project_sink_enabled = (
    var.project_sink_enabled_override != null
    ? var.project_sink_enabled_override
    : var.deployment_mode != "full"
  )
}

# Existence check only -- this SA is pre-existing and never created,
# modified, or deleted by Terraform (DWD is registered against it in the
# Workspace Admin Console, which Terraform can't manage anyway).
data "google_service_account" "runtime" {
  project    = var.project_id
  account_id = var.runtime_service_account_email
}

module "pubsub" {
  source = "./modules/pubsub"

  project_id      = var.project_id
  main_topic_name = var.main_topic_name
  dlq_topic_name  = var.dlq_topic_name
  labels          = local.labels
}

module "logging" {
  source = "./modules/logging"

  enabled                          = var.deployment_mode == "full"
  project_sink_enabled             = local.project_sink_enabled
  additional_monitored_project_ids = var.additional_monitored_project_ids
  monitored_folder_ids             = var.monitored_folder_ids
  org_id                           = var.org_id
  destination_project_id           = var.project_id
  destination_topic_name           = module.pubsub.main_topic_name
  destination_topic_id             = module.pubsub.main_topic_id
}

module "bigquery" {
  source = "./modules/bigquery"

  project_id                    = var.project_id
  region                        = var.region
  dataset_id                    = var.bq_dataset_id
  table_id                      = var.bq_table_id
  labels                        = local.labels
  runtime_service_account_email = data.google_service_account.runtime.email
}

module "iam" {
  source = "./modules/iam"

  project_id                    = var.project_id
  runtime_service_account_email = data.google_service_account.runtime.email
  dlq_topic_name                = module.pubsub.dlq_topic_name
}

module "firestore" {
  source = "./modules/firestore"

  project_id                    = var.project_id
  location_id                   = var.region
  runtime_service_account_email = data.google_service_account.runtime.email
}

module "cloud_function" {
  source = "./modules/cloud_function"

  project_id      = var.project_id
  region          = var.region
  vertex_location = var.vertex_location
  labels          = local.labels
  source_dir      = local.app_source_dir

  function_name   = var.function_name
  memory          = var.function_memory
  timeout_seconds = var.function_timeout_seconds
  max_instances   = var.function_max_instances

  runtime_service_account_email = data.google_service_account.runtime.email
  main_topic_id                 = module.pubsub.main_topic_id

  gmail_sender          = var.gmail_sender
  gmail_sender_name     = var.gmail_sender_name
  gmail_max_attempts    = var.gmail_max_attempts
  gmail_timeout_seconds = var.gmail_timeout_seconds

  cai_cache_ttl_seconds = var.cai_cache_ttl_seconds
  cai_timeout_seconds   = var.cai_timeout_seconds

  gemini_model           = var.gemini_model
  gemini_max_tokens      = var.gemini_max_tokens
  gemini_timeout_seconds = var.gemini_timeout_seconds

  bq_dataset_id  = module.bigquery.dataset_id
  bq_table_id    = module.bigquery.table_id
  dlq_topic_name = module.pubsub.dlq_topic_name

  depends_on = [module.iam]
}

module "monitoring" {
  source = "./modules/monitoring"

  project_id                  = var.project_id
  function_name               = module.cloud_function.function_name
  dlq_drain_subscription_name = module.pubsub.dlq_drain_subscription_name
  notification_channels       = var.notification_channels
  labels                      = local.labels
}
