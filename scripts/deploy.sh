#!/usr/bin/env bash
# Deploys the Gmail alerting Cloud Function.
#
# Edit the variables below before running. This script does not deploy
# anything without an explicit "yes" typed at the confirmation prompt.
set -euo pipefail

# ---------------------------------------------------------------------------
# Variables -- edit these, do not inline values into the gcloud command below.
# ---------------------------------------------------------------------------
PROJECT="prj-dg-devops-test"
REGION="asia-south1"
TOPIC="audit-platform-logs"
SERVICE_ACCOUNT="audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
GMAIL_SENDER="premkumar.gunasekaran@docugenieai.com"
GMAIL_SENDER_NAME="GCP Audit Platform"
GMAIL_MAX_ATTEMPTS="4"
GMAIL_TIMEOUT="30"
CAI_CACHE_TTL_SECONDS="300"
CAI_TIMEOUT_SECONDS="10"
VERTEX_PROJECT="prj-dg-devops-test"
VERTEX_LOCATION="us-central1"
GEMINI_MODEL="gemini-2.5-flash"
GEMINI_MAX_TOKENS="400"
GEMINI_TIMEOUT="20"
BQ_PROJECT="prj-dg-devops-test"
BQ_DATASET="audit_platform"
BQ_TABLE="alert_events"
DLQ_TOPIC="audit-platform-dlq"
DLQ_PROJECT="prj-dg-devops-test"
FIRESTORE_PROJECT="prj-dg-devops-test"
# PLACEHOLDER -- fill in once the mute-web Cloud Run service is deployed
# (terraform output mute_web_service_url). Empty omits the "Mute this
# alert" button from emails entirely; it isn't a hard requirement.
MUTE_SERVICE_URL=""
FUNCTION_NAME="process-audit-log-gmail-alerts"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Project:        ${PROJECT}"
echo "Region:         ${REGION}"
echo "Function:       ${FUNCTION_NAME}"
echo "Service account: ${SERVICE_ACCOUNT}"
echo "Active gcloud account: $(gcloud config get-value account 2>/dev/null)"
echo "Active gcloud project: $(gcloud config get-value project 2>/dev/null)"
echo
echo "Recipient routing comes from config/routing.yaml -- review it before deploying."
echo

read -r -p "Type 'deploy' to continue: " CONFIRMATION
if [[ "${CONFIRMATION}" != "deploy" ]]; then
  echo "Aborted."
  exit 1
fi

echo "Compiling sources..."
python -m py_compile main.py
find src scripts -name "*.py" -print0 | xargs -0 -n1 python -m py_compile

echo "Running tests..."
pytest -q

echo "Deploying..."
gcloud functions deploy "${FUNCTION_NAME}" \
  --project="${PROJECT}" \
  --gen2 \
  --region="${REGION}" \
  --runtime=python312 \
  --entry-point=process_audit_log \
  --trigger-topic="${TOPIC}" \
  --service-account="${SERVICE_ACCOUNT}" \
  --memory=512Mi \
  --timeout=120s \
  --max-instances=20 \
  --retry \
  --set-env-vars="GMAIL_DELEGATED_SA=${SERVICE_ACCOUNT},GMAIL_SENDER=${GMAIL_SENDER},GMAIL_SENDER_NAME=${GMAIL_SENDER_NAME},GMAIL_MAX_ATTEMPTS=${GMAIL_MAX_ATTEMPTS},GMAIL_TIMEOUT=${GMAIL_TIMEOUT},CAI_CACHE_TTL_SECONDS=${CAI_CACHE_TTL_SECONDS},CAI_TIMEOUT_SECONDS=${CAI_TIMEOUT_SECONDS},VERTEX_PROJECT=${VERTEX_PROJECT},VERTEX_LOCATION=${VERTEX_LOCATION},GEMINI_MODEL=${GEMINI_MODEL},GEMINI_MAX_TOKENS=${GEMINI_MAX_TOKENS},GEMINI_TIMEOUT=${GEMINI_TIMEOUT},BQ_PROJECT=${BQ_PROJECT},BQ_DATASET=${BQ_DATASET},BQ_TABLE=${BQ_TABLE},DLQ_TOPIC=${DLQ_TOPIC},DLQ_PROJECT=${DLQ_PROJECT},FIRESTORE_PROJECT=${FIRESTORE_PROJECT},MUTE_SERVICE_URL=${MUTE_SERVICE_URL}"

echo "Done."
