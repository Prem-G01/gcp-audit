#!/usr/bin/env bash
# One-time (and re-run-after-recreate) operator step: attaches a real
# dead-letter policy to the Pub/Sub subscription Eventarc auto-creates for
# the Cloud Function's trigger.
#
# WHY THIS EXISTS: as of this writing, google_cloudfunctions2_function's
# event_trigger has no dead_letter_topic field, and google_eventarc_trigger
# can't point at a pre-existing subscription either (Eventarc always
# creates and owns it) -- see terraform/modules/pubsub/main.tf's header
# comment and the tracking issue linked there. This script is the
# documented workaround: discover the Eventarc-managed subscription name,
# then attach a dead-letter policy to it directly. Re-run this if the
# function/trigger is ever destroyed and recreated (the subscription name
# is not stable across recreation).
set -euo pipefail

# ---------------------------------------------------------------------------
# Variables -- edit these, do not inline values into the gcloud commands below.
# ---------------------------------------------------------------------------
PROJECT="prj-dg-devops-test"
REGION="asia-south1"
FUNCTION_NAME="process-audit-log-gmail-alerts"
DLQ_TOPIC="audit-platform-dlq"
MAX_DELIVERY_ATTEMPTS="5"
MIN_RETRY_BACKOFF="10s"
MAX_RETRY_BACKOFF="600s"

echo "Project:               ${PROJECT}"
echo "Region:                ${REGION}"
echo "Function:              ${FUNCTION_NAME}"
echo "DLQ topic:             ${DLQ_TOPIC}"
echo "Active gcloud account: $(gcloud config get-value account 2>/dev/null)"
echo "Active gcloud project: $(gcloud config get-value project 2>/dev/null)"
echo

read -r -p "Type 'configure' to continue: " CONFIRMATION
if [[ "${CONFIRMATION}" != "configure" ]]; then
  echo "Aborted."
  exit 1
fi

echo "Discovering the Eventarc-managed trigger for ${FUNCTION_NAME}..."
# Cloud Functions v2 names its auto-created trigger "<function>-<random-suffix>"
# (NOT "<function>-<region>" -- confirmed wrong the hard way against a real
# deployment). Filter by destination instead of guessing the name pattern.
# The destination field is `destination.cloudFunction`, holding the FULL
# resource path (projects/P/locations/L/functions/NAME), not a bare name
# under `destination.cloudRun.service` -- also confirmed wrong the hard way
# (that field doesn't exist on a function-type trigger's destination).
TRIGGER_NAME="$(gcloud eventarc triggers list \
  --project="${PROJECT}" --location="${REGION}" \
  --filter="destination.cloudFunction:functions/${FUNCTION_NAME}" \
  --format="value(name)")"

if [[ -z "${TRIGGER_NAME}" ]]; then
  echo "Could not find a trigger whose destination is ${FUNCTION_NAME}."
  echo "List all triggers to find it manually:"
  echo "  gcloud eventarc triggers list --project=${PROJECT} --location=${REGION}"
  exit 1
fi

SUBSCRIPTION="$(gcloud eventarc triggers describe "${TRIGGER_NAME}" \
  --project="${PROJECT}" --location="${REGION}" \
  --format="value(transport.pubsub.subscription)")"

if [[ -z "${SUBSCRIPTION}" ]]; then
  echo "Found trigger ${TRIGGER_NAME} but could not read its subscription."
  echo "Describe it manually:"
  echo "  gcloud eventarc triggers describe ${TRIGGER_NAME} --project=${PROJECT} --location=${REGION}"
  exit 1
fi

echo "Found subscription: ${SUBSCRIPTION}"
echo "Attaching dead-letter policy -> ${DLQ_TOPIC} (max attempts: ${MAX_DELIVERY_ATTEMPTS})..."

gcloud pubsub subscriptions update "${SUBSCRIPTION}" \
  --project="${PROJECT}" \
  --dead-letter-topic="${DLQ_TOPIC}" \
  --dead-letter-topic-project="${PROJECT}" \
  --max-delivery-attempts="${MAX_DELIVERY_ATTEMPTS}" \
  --min-retry-delay="${MIN_RETRY_BACKOFF}" \
  --max-retry-delay="${MAX_RETRY_BACKOFF}"

echo "Done. Verify with:"
echo "  gcloud pubsub subscriptions describe ${SUBSCRIPTION} --project=${PROJECT}"
