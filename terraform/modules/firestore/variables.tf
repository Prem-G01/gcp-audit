variable "project_id" {
  type = string
}

variable "location_id" {
  description = "Firestore location -- a regional location (e.g. \"asia-south1\") or a multi-region (e.g. \"nam5\", \"eur3\")."
  type        = string
}

variable "runtime_service_account_email" {
  description = "The Cloud Function's runtime SA -- granted read-only access to check mute state."
  type        = string
}
