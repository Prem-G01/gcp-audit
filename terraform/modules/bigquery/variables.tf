variable "project_id" {
  type = string
}

variable "region" {
  description = "BigQuery dataset location."
  type        = string
}

variable "dataset_id" {
  type = string
}

variable "table_id" {
  type = string
}

variable "labels" {
  type = map(string)
}

variable "runtime_service_account_email" {
  description = "Granted roles/bigquery.dataEditor on the dataset (dataset-scoped, not project-scoped)."
  type        = string
}
