variable "project_id" {
  type = string
}

variable "region" {
  type = string
}

variable "vertex_location" {
  type = string
}

variable "labels" {
  type = map(string)
}

variable "source_dir" {
  description = "Absolute path to the repo root (main.py, src/, config/, requirements.txt live here)."
  type        = string
}

variable "function_name" {
  type = string
}

variable "memory" {
  type = string
}

variable "timeout_seconds" {
  type = number
}

variable "max_instances" {
  type = number
}

variable "runtime_service_account_email" {
  type = string
}

variable "main_topic_id" {
  description = "Full resource id (projects/P/topics/T) of the trigger topic."
  type        = string
}

# --- passed straight through to the function's environment variables ------

variable "gmail_sender" {
  type = string
}

variable "gmail_sender_name" {
  type = string
}

variable "gmail_max_attempts" {
  type = number
}

variable "gmail_timeout_seconds" {
  type = number
}

variable "cai_cache_ttl_seconds" {
  type = number
}

variable "cai_timeout_seconds" {
  type = number
}

variable "gemini_model" {
  type = string
}

variable "gemini_max_tokens" {
  type = number
}

variable "gemini_timeout_seconds" {
  type = number
}

variable "bq_dataset_id" {
  type = string
}

variable "bq_table_id" {
  type = string
}

variable "dlq_topic_name" {
  type = string
}

variable "mute_service_url" {
  description = <<-EOT
    Base URL of the mute-web Cloud Run service (module.mute_web.service_url),
    used to build the "Mute this alert" link in emails. Empty string omits
    the button entirely (src/email_template.py's mute_url is optional).
  EOT
  type        = string
  default     = ""
}
