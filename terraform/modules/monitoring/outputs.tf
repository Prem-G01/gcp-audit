output "failure_metric_names" {
  value = [for k, v in google_logging_metric.failure_counters : v.name]
}

output "alert_policy_names" {
  value = [
    google_monitoring_alert_policy.function_error_rate.display_name,
    google_monitoring_alert_policy.dlq_depth.display_name,
    google_monitoring_alert_policy.execution_count_absent.display_name,
    google_monitoring_alert_policy.caught_failures.display_name,
  ]
}
