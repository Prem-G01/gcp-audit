output "main_topic_id" {
  value = google_pubsub_topic.main.id
}

output "main_topic_name" {
  value = google_pubsub_topic.main.name
}

output "dlq_topic_id" {
  value = google_pubsub_topic.dlq.id
}

output "dlq_topic_name" {
  value = google_pubsub_topic.dlq.name
}

output "dlq_exhausted_topic_name" {
  value = google_pubsub_topic.dlq_exhausted.name
}

output "dlq_drain_subscription_name" {
  value = google_pubsub_subscription.dlq_drain.name
}
