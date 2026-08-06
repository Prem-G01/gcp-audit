variable "project_id" {
  type = string
}

variable "function_name" {
  type = string
}

variable "dlq_drain_subscription_name" {
  type = string
}

variable "notification_channels" {
  type    = list(string)
  default = []
}

variable "labels" {
  type = map(string)
}
