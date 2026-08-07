#!/usr/bin/env bash
# Publishes ONE synthetic audit-log event with a project_id that is NOT
# prj-dg-devops-test, straight to the same Pub/Sub topic the real org-wide
# log sink would otherwise feed. This does not require the org-level log
# sink to exist -- the Cloud Function processes whatever is published to
# the topic regardless of where it came from -- so it's a way to verify
# cross-project behaviour today, before the org sink is wired up:
#
#   - the rule still matches (iam_policy_change, HIGH) for a project_id
#     the platform has never seen
#   - the email correctly shows the OTHER project, not prj-dg-devops-test
#   - Cloud Asset Inventory enrichment (scoped only to prj-dg-devops-test's
#     runtime SA grant) fails permission-denied for this other project and
#     degrades gracefully (enrichment_ok=False) instead of blocking the
#     alert -- confirm this in the logs afterward (look for
#     "cai_enrichment_failed")
#
# Nothing here creates, deletes, or modifies any real GCP resource in any
# project -- it's a synthetic event only. It DOES cause a real email to be
# sent (iam_policy_change is not a Gemini/ai_analysis rule, so no Vertex AI
# call).
#
# Requires: jq
set -euo pipefail

PROJECT="prj-dg-devops-test"        # the function's OWN project (topic lives here)
OTHER_PROJECT_ID="cross-project-demo-999"  # the project INSIDE the synthetic event's payload
TOPIC="audit-platform-logs"

echo "Publishing topic project: ${PROJECT}"
echo "Topic:                    ${TOPIC}"
echo "Synthetic event's project_id (NOT prj-dg-devops-test): ${OTHER_PROJECT_ID}"
echo
echo "This publishes 1 synthetic event and will trigger 1 real email."
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

payload="$(jq -n --arg project "${OTHER_PROJECT_ID}" --arg ts "$(now_ts)" --arg iid "$(insert_id test-cross-project)" '{
  protoPayload: {
    methodName: "SetIamPolicy",
    resourceName: ("projects/" + $project),
    authenticationInfo: {principalEmail: "cross-project-tester@example.com"},
    requestMetadata: {callerIp: "203.0.113.222", callerSuppliedUserAgent: "google-cloud-sdk"},
    request: {policy: {bindings: [{role: "roles/viewer", members: ["user:cross-project-tester@example.com"]}]}}
  },
  resource: {type: "project", labels: {project_id: $project}},
  severity: "NOTICE",
  timestamp: $ts,
  insertId: $iid
}')"

base64_data="$(printf '%s' "${payload}" | base64 | tr -d '\n')"
token="$(gcloud auth print-access-token)"
body="$(jq -n --arg data "${base64_data}" '{messages: [{data: $data}]}')"

result="$(curl -s -X POST \
  -H "Authorization: Bearer ${token}" \
  -H "Content-Type: application/json" \
  -d "${body}" \
  "https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${TOPIC}:publish")"

echo "Published. -> ${result}"
echo
echo "Wait ~20-30s, then check:"
echo
echo "  gcloud functions logs read process-audit-log-gmail-alerts \\"
echo "    --project=${PROJECT} --region=asia-south1 --gen2 --limit=100 |"
echo "    grep -E 'gmail_alert_sent|findings_evaluated|cai_enrichment_failed|cai_resource_not_found'"
echo
echo "Expect: 1x findings_evaluated (finding_count: 1), 1x gmail_alert_sent,"
echo "and 1x cai_enrichment_failed (permission-denied on ${OTHER_PROJECT_ID} --"
echo "confirms the degrade-gracefully caveat). Check your inbox for an email"
echo "whose Project field shows '${OTHER_PROJECT_ID}', not prj-dg-devops-test."
