variable "enabled" {
  description = "Whether to create the org-level sink at all (deployment_mode == \"full\")."
  type        = bool
  default     = false
}

variable "org_id" {
  description = "GCP organization id. Required when enabled = true."
  type        = string
  default     = ""
}

variable "sink_name" {
  type    = string
  default = "audit-platform-activity-sink"
}

variable "destination_project_id" {
  description = "Project that owns the destination Pub/Sub topic."
  type        = string
}

variable "destination_topic_name" {
  description = "Short name of the destination Pub/Sub topic (for the IAM binding)."
  type        = string
}

variable "destination_topic_id" {
  description = "Full resource id of the destination Pub/Sub topic, e.g. projects/P/topics/T."
  type        = string
}

variable "filter" {
  description = "Log sink filter. Defaults to Admin Activity audit logs only -- every shipped rule targets mutating calls, and Data Access logs are high-volume/often disabled by default."
  type        = string
  default     = "logName:\"/logs/cloudaudit.googleapis.com%2Factivity\""
}
