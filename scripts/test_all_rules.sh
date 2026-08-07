#!/usr/bin/env bash
# Publishes one synthetic audit-log event per shipped rule in
# config/rules.yaml (covering create, modify, and a delete that should NOT
# match anything), so you can confirm all six rules actually fire against
# the live deployed pipeline -- not just the one rule (iam_policy_change)
# the original smoke test covered.
#
# Uses the Pub/Sub REST API directly via curl + jq (not `gcloud pubsub
# topics publish --message=...`) -- jq builds the JSON safely with proper
# escaping, and curl sends it as an HTTP body, avoiding any shell-quoting
# risk with embedded double quotes.
#
# Nothing here creates, deletes, or modifies any real GCP resource --
# every event is synthetic, injected directly into the Pub/Sub topic the
# real org-wide log sink would otherwise feed. It DOES cause real emails to
# be sent and (for the three ai_analysis: true rules) real Vertex AI/Gemini
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
echo "This publishes 7 synthetic events (6 rule matches + 1 deliberate"
echo "non-match) and will trigger real emails and some real Gemini calls."
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

# --- 7. DELETE -- no shipped rule covers deletes; confirms the zero-match --
# path works cleanly (evaluated, no findings, no email, no error).
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
publish_event "DELETE: DeleteServiceAccount (expect: NO MATCH -- zero findings, no email)" "${payload}"

echo
echo "All 7 events published. Wait ~60s (the org_policy/public_grant/"
echo "audit_config events also call Gemini, which adds latency), then check:"
echo
echo "  gcloud functions logs read process-audit-log-gmail-alerts \\"
echo "    --project=${PROJECT} --region=asia-south1 --gen2 --limit=50"
echo
echo "Expect 6x 'gmail_alert_sent' and 1x 'findings_evaluated' with"
echo "finding_count: 0 and no send attempt (the DeleteServiceAccount event)."
echo "Also expect 6 emails in your inbox with 6 different severity colors"
echo "and rule titles, and 3 of them ('org_policy_modified',"
echo "'public_iam_grant', 'audit_config_changed') should have an AI Analysis"
echo "section populated in the email body."
