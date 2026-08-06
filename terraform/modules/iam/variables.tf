variable "project_id" {
  type = string
}

variable "runtime_service_account_email" {
  description = "Pre-existing Cloud Function runtime SA -- this module only grants it application permissions, never creates or deletes it."
  type        = string
}

variable "dlq_topic_name" {
  type = string
}
