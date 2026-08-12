# Firestore (Native mode) database backing temporary alert muting. A
# single small collection (audit_platform_mutes), one document per active
# mute, TTL-configured on `expire_at` so expired mutes clean themselves up
# eventually. See src/muting.py for why correctness never depends on TTL
# deletion timing (Firestore's own docs say TTL deletion can lag up to
# ~24h -- is_muted() always compares expire_at against the current time
# itself; TTL here is purely a housekeeping optimization for the
# collection, never the source of truth for "is this currently muted").

resource "google_firestore_database" "audit_platform" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.location_id
  type        = "FIRESTORE_NATIVE"

  concurrency_mode            = "OPTIMISTIC"
  app_engine_integration_mode = "DISABLED"
}

resource "google_firestore_field" "mute_expiry_ttl" {
  project    = var.project_id
  database   = google_firestore_database.audit_platform.name
  collection = "audit_platform_mutes"
  field      = "expire_at"

  ttl_config {}

  # index_config left at provider default (Firestore auto-indexes single
  # fields) -- this resource exists here purely to declare the TTL policy.
}

# Runtime SA only ever READS mute state (main.py's muting.is_muted()) --
# writes happen via scripts/mute_alert.py, run by a human under their own
# gcloud identity (keyless, same pattern as every other operator script
# in this repo), never by the Cloud Function itself. Whoever should be
# allowed to create/clear mutes needs roles/datastore.user granted to
# their own account separately -- that's a human-access decision, not
# something to hardcode into this module.
resource "google_project_iam_member" "runtime_datastore_viewer" {
  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${var.runtime_service_account_email}"
}
