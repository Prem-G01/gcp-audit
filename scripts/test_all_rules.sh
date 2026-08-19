#!/usr/bin/env bash
# Publishes one synthetic audit-log event per shipped rule in
# config/rules.yaml (covering create, modify, a delete, a Workload
# Identity Federation caller, a new-project creation, a billing change,
# a denied attempt, Data Access egress, a System Event, an IAM custom
# role change, and service account impersonation), so you can confirm
# all sixteen rules -- and all five email templates -- actually fire
# against the live deployed pipeline, not just the one rule
# (iam_policy_change) the original smoke test covered.
# resource_created/resource_deleted (rules 11-12) don't get a dedicated
# event -- they're exercised incidentally via overlap on events 4, 7, 8.
#
# Events 11-16 (the Policy Denied/Data Access/System Event rules) set
# `logName` explicitly in the payload, since those rules match on it --
# events 1-10 omit it entirely (a missing raw.logName is a non-match for
# every rule's `not: contains %2Fpolicy/%2Fdata_access/%2Fsystem_event`
# exclusion, so they're correctly treated as Admin Activity). Because
# this script injects directly into Pub/Sub, downstream of the log
# sink/audit-config entirely, events 11-16 exercise the RULE MATCHING
# and email/Gemini pipeline regardless of whether
# enable_data_access_logs/enable_system_event_logs/
# enable_impersonation_logs are actually turned on in Terraform -- this
# script can't tell you whether that plumbing itself is live, only
# whether the rules fire correctly once an event of that shape arrives.
#
# Uses the Pub/Sub REST API directly via curl + jq (not `gcloud pubsub
# topics publish --message=...`) -- jq builds the JSON safely with proper
# escaping, and curl sends it as an HTTP body, avoiding any shell-quoting
# risk with embedded double quotes.
#
# Nothing here creates, deletes, or modifies any real GCP resource --
# every event is synthetic, injected directly into the Pub/Sub topic the
# real org-wide log sink would otherwise feed. It DOES cause real emails to
# be sent and (for the ai_analysis: true rules) real Vertex AI/Gemini
# calls, so it's not entirely free or silent -- hence the confirmation
# prompt below.
#
# Events 17-20 are REGRESSION CHECKS, not rule-coverage events -- each one
# is shaped exactly like a self-noise source that has ACTUALLY fired a
# real false alert in production before being caught and excluded
# (numeric-ID-form impersonation of this platform's own two SAs; reads of
# its own tfstate/function-source buckets). Every one of these MUST
# produce zero findings. Unlike events 1-16, this script does NOT just
# tell you to go read logs for these -- it waits, then automatically
# queries BigQuery (every finding is persisted whether sent or not) for
# any of them by their tagged raw_log_id, and prints PASS/FAIL. This is
# the whole point: the last two live incidents (impersonation self-
# signing, tfstate reads) were only caught because someone happened to
# run a manual bq query well after the fact. Run this script BEFORE a
# terraform apply that touches config/rules.yaml, and a regression like
# either of those gets caught here instead of in production.
#
# Requires: jq, bq CLI (already authenticated -- same gcloud session used
# for the Pub/Sub publish calls below)
#
# Events 21-22 are OPTIONAL and off by default -- they validate the real
# data-size lookup in src/enrichment/data_volume.py (GCS object size /
# BigQuery job bytes) against an actual existing resource, rather than just
# confirming bulk_data_export_or_download matches (which events 12-13
# already do with fake resource names that can never resolve). Fill in
# REAL_GCS_OBJECT_RESOURCE_NAME / REAL_BQ_EXTRACT_JOB_RESOURCE_NAME below to
# enable them; unlike the automated regression check, their result can only
# be confirmed by reading the resulting email, not by querying BigQuery.
set -euo pipefail

PROJECT="prj-dg-devops-test"
TOPIC="audit-platform-logs"
DELAY_BETWEEN_EVENTS_SECONDS=5

# OPTIONAL -- fill these in with a REAL resource (not the excluded
# tfstate/function-source buckets) to exercise the actual data-size lookup
# (events 21-22 below). Requires terraform apply to have already granted
# roles/storage.objectViewer / roles/bigquery.jobUser to the runtime SA.
# Leave blank to skip both -- everything else in this script still runs.
REAL_GCS_OBJECT_RESOURCE_NAME=""    # e.g. "projects/_/buckets/some-real-bucket/objects/some-real-object.csv"
REAL_BQ_EXTRACT_JOB_RESOURCE_NAME="" # e.g. "projects/prj-dg-devops-test/jobs/bqjob_r123_abc456"

echo "Project: ${PROJECT}"
echo "Topic:   ${TOPIC}"
echo "This publishes 20 synthetic events (16 matching all 16 rules, several with"
echo "intentional overlap, plus 4 regression checks for known self-noise sources)"
echo "and will trigger real emails and some real Gemini calls."
echo

read -r -p "Type 'test' to continue: " CONFIRMATION
if [[ "${CONFIRMATION}" != "test" ]]; then
  echo "Aborted."
  exit 1
fi

now_ts() {
  date -u +"%Y-%m-%dT%H:%M:%S.%6NZ"
}

insert_id() {
  echo "$1-$RANDOM$RANDOM"
}

publish_event() {
  local name="$1"
  local payload_json="$2"

  local base64_data
  base64_data="$(printf '%s' "${payload_json}" | base64 | tr -d '\n')"
  local token
  token="$(gcloud auth print-access-token)"
  local body
  body="$(jq -n --arg data "${base64_data}" '{messages: [{data: $data}]}')"

  echo "Publishing: ${name}"
  local result
  result="$(curl -s -X POST \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "${body}" \
    "https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${TOPIC}:publish")"
  echo "  -> ${result}"
}

# --- 1. MODIFY -- generic IAM policy change --------------------------------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-modify-iam)" '{
  protoPayload: {
    methodName: "SetIamPolicy",
    resourceName: ("projects/" + $project),
    authenticationInfo: {principalEmail: "test-modify@example.com"},
    requestMetadata: {callerIp: "203.0.113.10"},
    request: {policy: {bindings: [{role: "roles/editor", members: ["user:test-modify@example.com"]}]}}
  },
  resource: {type: "project", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "MODIFY: SetIamPolicy (expect: iam_policy_change, HIGH)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 2. CREATE -- service account key ---------------------------------------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-create-sakey)" '{
  protoPayload: {
    methodName: "google.iam.admin.v1.CreateServiceAccountKey",
    resourceName: ("projects/" + $project + "/serviceAccounts/test-sa@" + $project + ".iam.gserviceaccount.com/keys/testkey123"),
    authenticationInfo: {principalEmail: "test-create@example.com"},
    requestMetadata: {callerIp: "198.51.100.20"}
  },
  resource: {type: "service_account", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "CREATE: CreateServiceAccountKey (expect: service_account_key_created, HIGH)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 3. MODIFY -- org policy update (ai_analysis: true) --------------------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-orgpolicy)" '{
  protoPayload: {
    methodName: "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy",
    resourceName: "organizations/123456789012/policies/compute.vmExternalIpAccess",
    authenticationInfo: {principalEmail: "test-orgpolicy@example.com"},
    requestMetadata: {callerIp: "192.0.2.5"}
  },
  resource: {type: "organization", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "MODIFY: OrgPolicy.UpdatePolicy (expect: org_policy_modified, HIGH, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 4. CREATE -- firewall rule open to the internet ------------------------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-firewall)" '{
  protoPayload: {
    methodName: "v1.compute.firewalls.insert",
    resourceName: ("projects/" + $project + "/global/firewalls/test-allow-all"),
    authenticationInfo: {principalEmail: "test-firewall@example.com"},
    requestMetadata: {callerIp: "203.0.113.99"},
    request: {sourceRanges: ["0.0.0.0/0"], allowed: [{IPProtocol: "tcp", ports: ["22"]}]}
  },
  resource: {type: "gce_firewall_rule", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "CREATE: firewalls.insert with 0.0.0.0/0 (expect: firewall_open_to_internet CRITICAL + resource_created HIGH)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 5. MODIFY -- public IAM/bucket grant (ai_analysis: true) --------------
payload="$(jq -n --arg ts "$(now_ts)" --arg iid "$(insert_id test-public-grant)" --arg project "${PROJECT}" '{
  protoPayload: {
    methodName: "SetIamPolicy",
    resourceName: "projects/_/buckets/test-public-bucket",
    authenticationInfo: {principalEmail: "test-public@example.com"},
    requestMetadata: {callerIp: "203.0.113.77"},
    request: {policy: {bindings: [{role: "roles/storage.objectViewer", members: ["allUsers"]}]}}
  },
  resource: {type: "storage_bucket", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "MODIFY: SetIamPolicy with allUsers (expect: public_iam_grant, CRITICAL, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 6. MODIFY -- audit logging config change (ai_analysis: true) ----------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-auditconfig)" '{
  protoPayload: {
    methodName: "SetIamPolicy",
    resourceName: ("projects/" + $project),
    authenticationInfo: {principalEmail: "test-auditconfig@example.com"},
    requestMetadata: {callerIp: "203.0.113.88"},
    request: {policy: {auditConfigs: [{service: "allServices", auditLogConfigs: [{logType: "DATA_READ"}]}]}}
  },
  resource: {type: "project", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "MODIFY: SetIamPolicy with auditConfigs (expect: audit_config_changed, HIGH, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 7. DELETE -- no rule 1-6 specifically covers deletes; this now exercises
# rule 12 (resource_deleted, HIGH, org-wide) instead of a true zero-match --
# see config/rules.yaml rule 12's comment.
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-delete-sa)" '{
  protoPayload: {
    methodName: "google.iam.admin.v1.DeleteServiceAccount",
    resourceName: ("projects/" + $project + "/serviceAccounts/old-unused-sa@" + $project + ".iam.gserviceaccount.com"),
    authenticationInfo: {principalEmail: "test-delete@example.com"},
    requestMetadata: {callerIp: "203.0.113.55"}
  },
  resource: {type: "service_account", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "DELETE: DeleteServiceAccount (expect: resource_deleted, HIGH)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 8. Federated (Workload Identity Federation) identity, no principalEmail
# at all -- only principalSubject, matching how GCP actually logs a pure WIF
# caller. Expected to match BOTH resource_created (rule 11, an "insert") and
# federated_identity_action (rule 8, ai_analysis: true).
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-wif-instance)" '{
  protoPayload: {
    methodName: "v1.compute.instances.insert",
    resourceName: ("projects/" + $project + "/zones/asia-south1-a/instances/ci-deployed-vm"),
    authenticationInfo: {
      principalSubject: "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-pool/subject/repo:example-org/example-repo:ref:refs/heads/main"
    },
    requestMetadata: {callerIp: "203.0.113.201", callerSuppliedUserAgent: "google-api-go-client/0.5 GitHubActions"},
    request: {name: "ci-deployed-vm", machineType: ("zones/asia-south1-a/machineTypes/e2-medium")}
  },
  resource: {type: "gce_instance", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "WIF: compute.instances.insert via Workload Identity Federation (expect: resource_created + federated_identity_action, HIGH, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 9. New project created -- only rule 9's own match condition covers
# this ("CreateProject"); deliberately excluded from resource_created
# (rule 11) and the unclassified_admin_activity safety net, since rule 9
# already gives this its own dedicated, more detailed HIGH alert.
payload="$(jq -n --arg ts "$(now_ts)" --arg iid "$(insert_id test-project-created)" '{
  protoPayload: {
    methodName: "google.cloud.resourcemanager.v3.Projects.CreateProject",
    resourceName: "projects/test-shadow-project-999",
    authenticationInfo: {principalEmail: "test-newproject@example.com"},
    requestMetadata: {callerIp: "203.0.113.210"},
    request: {project: {projectId: "test-shadow-project-999", displayName: "test-shadow-project-999", parent: "organizations/123456789012"}}
  },
  resource: {type: "project", labels: {project_id: "test-shadow-project-999"}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "CREATE: CreateProject (expect: project_created, HIGH, +Gemini -- Template A)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 10. Billing account linked to a project -- matches rule 10's
# (BillingAccount|ProjectBillingInfo) regex; also picked up by the
# unclassified_admin_activity safety net since "Update" is a mutating verb.
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-billing-changed)" '{
  protoPayload: {
    methodName: "google.cloud.billing.v1.CloudBilling.UpdateProjectBillingInfo",
    resourceName: ("projects/" + $project),
    authenticationInfo: {principalEmail: "test-billing@example.com"},
    requestMetadata: {callerIp: "203.0.113.220"},
    request: {projectBillingInfo: {billingAccountName: "billingAccounts/000000-111111-222222"}}
  },
  resource: {type: "project", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "MODIFY: UpdateProjectBillingInfo (expect: billing_account_changed, CRITICAL, +Gemini -- Template D)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 11. DENIED -- IAM blocks an attempted SetIamPolicy ---------------------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-policy-denied)" '{
  protoPayload: {
    methodName: "SetIamPolicy",
    resourceName: ("projects/" + $project),
    status: {code: 7, message: "PERMISSION_DENIED"},
    authenticationInfo: {principalEmail: "test-denied@example.com"},
    authorizationInfo: [{permission: "resourcemanager.projects.setIamPolicy", granted: false}],
    requestMetadata: {callerIp: "203.0.113.230"}
  },
  resource: {type: "project", labels: {project_id: $project}},
  severity: "ERROR",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fpolicy")
}')"
publish_event "DENIED: SetIamPolicy blocked (expect: policy_denied_access_attempt, MEDIUM)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 12. DATA ACCESS -- BigQuery EXTRACT job (bulk export) ------------------
# Requires enable_data_access_logs = true for the real pipeline, but this
# script injects past the sink -- fires regardless (see header comment).
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-bq-extract)" '{
  protoPayload: {
    methodName: "google.cloud.bigquery.v2.JobService.InsertJob",
    resourceName: ("projects/" + $project + "/jobs/test-extract-job-001"),
    authenticationInfo: {principalEmail: "test-export@example.com"},
    requestMetadata: {callerIp: "203.0.113.240"},
    metadata: {jobChange: {job: {jobConfig: {type: "EXTRACT"}}}}
  },
  resource: {type: "bigquery_dataset", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
}')"
publish_event "DATA ACCESS: BigQuery EXTRACT job (expect: bulk_data_export_or_download, HIGH, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 13. DATA ACCESS -- GCS object download ---------------------------------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-gcs-download)" '{
  protoPayload: {
    methodName: "storage.objects.get",
    resourceName: "projects/_/buckets/test-sensitive-bucket/objects/report.csv",
    authenticationInfo: {principalEmail: "test-download@example.com"},
    requestMetadata: {callerIp: "203.0.113.250"}
  },
  resource: {type: "gcs_bucket", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
}')"
publish_event "DATA ACCESS: GCS object download (expect: bulk_data_export_or_download, HIGH, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 14. SYSTEM EVENT -- VM preempted ---------------------------------------
# Requires enable_system_event_logs = true for the real pipeline; see
# header comment on why this script fires regardless.
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-system-event)" '{
  protoPayload: {
    methodName: "compute.instances.preempted",
    resourceName: ("projects/" + $project + "/zones/asia-south1-a/instances/test-spot-vm"),
    authenticationInfo: {}
  },
  resource: {type: "gce_instance", labels: {project_id: $project}},
  severity: "INFO",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fsystem_event")
}')"
publish_event "SYSTEM EVENT: VM preempted (expect: system_event_occurred, LOW)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 15. MODIFY -- custom IAM role definition changed -----------------------
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-update-role)" '{
  protoPayload: {
    methodName: "google.iam.admin.v1.UpdateRole",
    resourceName: ("projects/" + $project + "/roles/testCustomRole"),
    authenticationInfo: {principalEmail: "test-role@example.com"},
    requestMetadata: {callerIp: "203.0.113.99"},
    request: {role: {includedPermissions: ["resourcemanager.projects.setIamPolicy"]}}
  },
  resource: {type: "iam_role", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"
publish_event "MODIFY: UpdateRole (expect: iam_custom_role_modified, HIGH, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 16. DATA ACCESS -- service account impersonation -----------------------
# Uses a made-up target SA (test-target-sa@...), NOT this platform's own
# two real service accounts -- those are deliberately excluded by
# service_account_impersonation's self-noise exclusion (see
# config/rules.yaml rule 17's comment), so using them here would test the
# wrong thing (a rule that correctly does NOT fire).
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-impersonation)" '{
  protoPayload: {
    methodName: "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken",
    resourceName: ("projects/-/serviceAccounts/test-target-sa@" + $project + ".iam.gserviceaccount.com"),
    authenticationInfo: {principalEmail: "test-impersonator@example.com"},
    requestMetadata: {callerIp: "203.0.113.19"}
  },
  resource: {type: "service_account", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
}')"
publish_event "DATA ACCESS: GenerateAccessToken impersonation (expect: service_account_impersonation, HIGH, +Gemini)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 17. REGRESSION CHECK -- runtime SA self-signs a JWT, numeric-ID form ---
# This is EXACTLY what fired a real HIGH alert (with a real Gemini call)
# on every single Gmail send until caught live and fixed -- the first
# version of service_account_impersonation's self-noise exclusion only
# matched the SA's EMAIL form; GCP actually logs SignJwt's target in
# numeric uniqueId form. MUST produce zero findings.
REGRESSION_INSERT_IDS=()
iid="$(insert_id test-noise-selfsign-jwt)"
REGRESSION_INSERT_IDS+=("${iid}")
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "${iid}" '{
  protoPayload: {
    methodName: "google.iam.credentials.v1.IAMCredentials.SignJwt",
    resourceName: "projects/-/serviceAccounts/108550589402351078214",
    authenticationInfo: {principalEmail: ("audit-platform-sa-prj-dg-devop@" + $project + ".iam.gserviceaccount.com")}
  },
  resource: {type: "service_account", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
}')"
publish_event "REGRESSION CHECK: runtime SA self-signs JWT, numeric-ID form (MUST be zero alerts)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 18. REGRESSION CHECK -- Terraform impersonates the deploy SA, numeric-ID form
iid="$(insert_id test-noise-tf-impersonation)"
REGRESSION_INSERT_IDS+=("${iid}")
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "${iid}" '{
  protoPayload: {
    methodName: "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken",
    resourceName: "projects/-/serviceAccounts/113755025732014374847",
    authenticationInfo: {principalEmail: "test-operator@example.com"}
  },
  resource: {type: "service_account", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
}')"
publish_event "REGRESSION CHECK: Terraform impersonates deploy SA, numeric-ID form (MUST be zero alerts)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 19. REGRESSION CHECK -- read of this platform's own tfstate bucket ----
iid="$(insert_id test-noise-tfstate-read)"
REGRESSION_INSERT_IDS+=("${iid}")
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "${iid}" '{
  protoPayload: {
    methodName: "storage.objects.get",
    resourceName: ("projects/_/buckets/" + $project + "-tfstate/objects/audit-platform/state/default.tfstate"),
    authenticationInfo: {principalEmail: "test-operator@example.com"}
  },
  resource: {type: "gcs_bucket", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
}')"
publish_event "REGRESSION CHECK: GCS read of the tfstate bucket (MUST be zero alerts)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 20. REGRESSION CHECK -- read of this platform's own function-source bucket
iid="$(insert_id test-noise-function-source-read)"
REGRESSION_INSERT_IDS+=("${iid}")
payload="$(jq -n --arg project "${PROJECT}" --arg ts "$(now_ts)" --arg iid "${iid}" '{
  protoPayload: {
    methodName: "storage.objects.get",
    resourceName: ("projects/_/buckets/" + $project + "-function-source/objects/source-test.zip"),
    authenticationInfo: {principalEmail: "service-88240501906@gcf-admin-robot.iam.gserviceaccount.com"}
  },
  resource: {type: "gcs_bucket", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid,
  logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
}')"
publish_event "REGRESSION CHECK: GCS read of the function-source bucket (MUST be zero alerts)" "${payload}"

# --- 21. OPTIONAL: real GCS object download -- validates the actual data-
# size LOOKUP (src/enrichment/data_volume.py's Storage API call), not just
# that the rule matches like event 13 already does. Cannot be auto-checked
# via BigQuery like events 17-20 -- data_size_display only ever reaches the
# rendered email, it's not a persisted column -- so this requires checking
# the resulting email's "Data Size" field by eye.
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"
if [[ -n "${REAL_GCS_OBJECT_RESOURCE_NAME}" ]]; then
  payload="$(jq -n --arg project "${PROJECT}" --arg resource "${REAL_GCS_OBJECT_RESOURCE_NAME}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-real-gcs-size)" '{
    protoPayload: {
      methodName: "storage.objects.get",
      resourceName: $resource,
      authenticationInfo: {principalEmail: "test-real-download@example.com"},
      requestMetadata: {callerIp: "203.0.113.251"}
    },
    resource: {type: "gcs_bucket", labels: {project_id: $project}},
    severity: "NOTICE",
    timestamp: $ts,
    insertId: $iid,
    logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
  }')"
  publish_event "REAL DATA SIZE: GCS object download (expect: bulk_data_export_or_download, HIGH -- check email's Data Size field)" "${payload}"
else
  echo "Skipping event 21 (real GCS data-size lookup) -- set REAL_GCS_OBJECT_RESOURCE_NAME at the top of this script to exercise it."
fi
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 22. OPTIONAL: real BigQuery EXTRACT job -- validates the actual
# jobs.get byte-count lookup against a job that really ran, same caveat as
# event 21 (email-only, not BigQuery-checkable).
if [[ -n "${REAL_BQ_EXTRACT_JOB_RESOURCE_NAME}" ]]; then
  payload="$(jq -n --arg project "${PROJECT}" --arg resource "${REAL_BQ_EXTRACT_JOB_RESOURCE_NAME}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-real-bq-size)" '{
    protoPayload: {
      methodName: "google.cloud.bigquery.v2.JobService.InsertJob",
      resourceName: $resource,
      authenticationInfo: {principalEmail: "test-real-export@example.com"},
      requestMetadata: {callerIp: "203.0.113.252"},
      metadata: {jobChange: {job: {jobConfig: {type: "EXTRACT"}}}}
    },
    resource: {type: "bigquery_dataset", labels: {project_id: $project}},
    severity: "NOTICE",
    timestamp: $ts,
    insertId: $iid,
    logName: ("projects/" + $project + "/logs/cloudaudit.googleapis.com%2Fdata_access")
  }')"
  publish_event "REAL DATA SIZE: BigQuery EXTRACT job (expect: bulk_data_export_or_download, HIGH -- check email's Data Size field)" "${payload}"
else
  echo "Skipping event 22 (real BigQuery data-size lookup) -- set REAL_BQ_EXTRACT_JOB_RESOURCE_NAME at the top of this script to exercise it."
fi

echo
echo "All 20 events published (16 rule-coverage + 4 regression checks)."
echo "Plus any of events 21-22 (real data-size lookups) you enabled above."
echo
echo "To inspect the full run manually, check:"
echo
echo "  gcloud functions logs read process-audit-log-gmail-alerts \\"
echo "    --project=${PROJECT} --region=asia-south1 --gen2 --limit=350"
echo
echo "Expect 16x 'findings_evaluated' and 21x 'gmail_alert_sent' total --"
echo "several events match more than one rule by design (see rule 7's"
echo "comment in config/rules.yaml for why). 10 findings get an AI Analysis"
echo "section: the original 6 (org_policy_modified, public_iam_grant,"
echo "audit_config_changed, federated_identity_action, project_created,"
echo "billing_account_changed) plus 4 new ones (bulk_data_export_or_download"
echo "fires on both events 12 and 13, iam_custom_role_modified on event 15,"
echo "service_account_impersonation on event 16). Events 11-16 are each"
echo "designed to match exactly one rule apiece -- no overlap, unlike some"
echo "of events 1-10."
echo "resource_created/resource_deleted (rules 11-12, HIGH) also fire for"
echo "events 4, 7, and 8."
echo
echo "This run also exercises all 5 email templates (see"
echo "src/email_template.py's _select_template -- explicit rule-id overrides"
echo "win; everything else falls through by severity: CRITICAL->D, HIGH->A,"
echo "else->C):"
echo "  A (Executive Dark)      -- project_created, resource_created, resource_deleted,"
echo "                             bulk_data_export_or_download, iam_custom_role_modified,"
echo "                             service_account_impersonation (HIGH fallback)"
echo "  B (Security Operations) -- iam_policy_change, org_policy_modified,"
echo "                             audit_config_changed, federated_identity_action"
echo "  C (Clean Enterprise)    -- unclassified_admin_activity,"
echo "                             policy_denied_access_attempt, system_event_occurred"
echo "  D (Executive Summary)   -- public_iam_grant, billing_account_changed"
echo "  E (Engineer Detail)     -- firewall_open_to_internet, service_account_key_created"
echo
if [[ -n "${REAL_GCS_OBJECT_RESOURCE_NAME}" || -n "${REAL_BQ_EXTRACT_JOB_RESOURCE_NAME}" ]]; then
  echo "You enabled one or more real data-size lookups (events 21-22). Check the"
  echo "resulting email(s)' Data Size field by eye -- this can't be verified via"
  echo "BigQuery like the regression checks below, since data_size_display is"
  echo "only ever rendered into the email, never persisted as its own column."
  echo
fi

# --- Automated regression check -------------------------------------------
# This is the actual point of events 17-20: don't just print instructions
# and hope someone remembers to check -- wait for processing, then query
# BigQuery (every finding is persisted whether sent or not) for any of the
# 4 tagged noise-shaped events, and give a clear PASS/FAIL. Run this BEFORE
# a terraform apply that touches config/rules.yaml -- the last two live
# incidents (impersonation self-signing, tfstate reads) were only caught
# because someone happened to run this exact kind of query well after the
# fact, in production.
REGRESSION_WAIT_SECONDS=90
echo "Waiting ${REGRESSION_WAIT_SECONDS}s for processing, then checking for noise regressions..."
sleep "${REGRESSION_WAIT_SECONDS}"

id_list="$(printf "'%s'," "${REGRESSION_INSERT_IDS[@]}")"
id_list="${id_list%,}"
query="SELECT rule_id, raw_log_id, resource_name FROM \`${PROJECT}.audit_platform.alert_events\` WHERE raw_log_id IN (${id_list})"
result_json="$(bq query --use_legacy_sql=false --format=json "${query}")"

echo
if [[ "$(echo "${result_json}" | jq 'length')" -gt 0 ]]; then
  echo "REGRESSION DETECTED -- $(echo "${result_json}" | jq 'length') noise-shaped event(s) that should"
  echo "have produced ZERO findings actually matched a rule:"
  echo
  echo "${result_json}" | jq -r '.[] | "  rule_id=\(.rule_id)  raw_log_id=\(.raw_log_id)\n    resource_name=\(.resource_name)"'
  echo
  echo "A self-noise exclusion in config/rules.yaml is broken. Do NOT consider"
  echo "config changes safe to ship until this is fixed -- check the matching"
  echo "rule's exclusions against the resource_name/method_name shapes above."
  exit 1
else
  echo "PASS -- all 4 noise-shaped regression events correctly produced zero findings."
fi
