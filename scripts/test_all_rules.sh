#!/usr/bin/env bash
# Publishes one synthetic audit-log event per shipped rule in
# config/rules.yaml (covering create, modify, a delete, and a Workload
# Identity Federation caller), so you can confirm all eight rules actually
# fire against the live deployed pipeline -- not just the one rule
# (iam_policy_change) the original smoke test covered.
#
# Uses the Pub/Sub REST API directly via curl + jq (not `gcloud pubsub
# topics publish --message=...`) -- jq builds the JSON safely with proper
# escaping, and curl sends it as an HTTP body, avoiding any shell-quoting
# risk with embedded double quotes.
#
# Nothing here creates, deletes, or modifies any real GCP resource --
# every event is synthetic, injected directly into the Pub/Sub topic the
# real org-wide log sink would otherwise feed. It DOES cause real emails to
# be sent and (for the four ai_analysis: true rules) real Vertex AI/Gemini
# calls, so it's not entirely free or silent -- hence the confirmation
# prompt below.
#
# Requires: jq
set -euo pipefail

PROJECT="prj-dg-devops-test"
TOPIC="audit-platform-logs"
DELAY_BETWEEN_EVENTS_SECONDS=5

echo "Project: ${PROJECT}"
echo "Topic:   ${TOPIC}"
echo "This publishes 8 synthetic events (matching all 8 rules, several with"
echo "intentional overlap) and will trigger real emails and some real Gemini calls."
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
publish_event "CREATE: firewalls.insert with 0.0.0.0/0 (expect: firewall_open_to_internet, CRITICAL)" "${payload}"
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
# the unclassified_admin_activity safety-net rule instead of a true zero-match
# (that catch-all rule is what "no dark spots" coverage means in practice --
# see config/rules.yaml rule 7's comment).
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
publish_event "DELETE: DeleteServiceAccount (expect: unclassified_admin_activity, LOW)" "${payload}"
sleep "${DELAY_BETWEEN_EVENTS_SECONDS}"

# --- 8. Federated (Workload Identity Federation) identity, no principalEmail
# at all -- only principalSubject, matching how GCP actually logs a pure WIF
# caller. Expected to match BOTH unclassified_admin_activity (an "insert" not
# covered by rules 1-6) and federated_identity_action (rule 8, ai_analysis:
# true).
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
publish_event "WIF: compute.instances.insert via Workload Identity Federation (expect: unclassified_admin_activity + federated_identity_action, HIGH, +Gemini)" "${payload}"

echo
echo "All 8 events published. Wait ~60s (4 events also call Gemini, which"
echo "adds latency), then check:"
echo
echo "  gcloud functions logs read process-audit-log-gmail-alerts \\"
echo "    --project=${PROJECT} --region=asia-south1 --gen2 --limit=200"
echo
echo "Expect 8x 'findings_evaluated' and 12x 'gmail_alert_sent' total --"
echo "several events now match more than one rule (rules 1-6 already overlap"
echo "for events 5/6, and the unclassified_admin_activity safety net"
echo "additionally overlaps events 4, 7, and 8 by design -- see rule 7's"
echo "comment in config/rules.yaml). 4 findings get an AI Analysis section"
echo "populated (org_policy_modified, public_iam_grant, audit_config_changed,"
echo "federated_identity_action)."
