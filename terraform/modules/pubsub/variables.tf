variable "project_id" {
  type = string
}

variable "main_topic_name" {
  description = "Topic the log sink publishes to and the Cloud Function's Eventarc trigger reads from."
  type        = string
}

variable "dlq_topic_name" {
  description = "Topic write_to_dlq() publishes permanently-undeliverable findings to."
  type        = string
}

variable "labels" {
  type = map(string)
}
