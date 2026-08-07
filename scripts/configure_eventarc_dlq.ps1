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

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Variables -- edit these, do not inline values into the gcloud commands below.
# ---------------------------------------------------------------------------
$Project              = "prj-dg-devops-test"
$Region                = "asia-south1"
$FunctionName          = "process-audit-log-gmail-alerts"
$DlqTopic              = "audit-platform-dlq"
$MaxDeliveryAttempts   = "5"
$MinRetryBackoff       = "10s"
$MaxRetryBackoff       = "600s"

$ActiveAccount = (gcloud config get-value account 2>$null)
$ActiveProject = (gcloud config get-value project 2>$null)

Write-Host "Project:               $Project"
Write-Host "Region:                $Region"
Write-Host "Function:              $FunctionName"
Write-Host "DLQ topic:             $DlqTopic"
Write-Host "Active gcloud account: $ActiveAccount"
Write-Host "Active gcloud project: $ActiveProject"
Write-Host ""

$Confirmation = Read-Host "Type 'configure' to continue"
if ($Confirmation -ne "configure") {
    Write-Host "Aborted."
    exit 1
}

Write-Host "Discovering the Eventarc-managed trigger for $FunctionName..."
# Cloud Functions v2 names its auto-created trigger "<function>-<random-suffix>"
# (NOT "<function>-<region>" -- confirmed wrong the hard way against a real
# deployment). Filter by destination instead of guessing the name pattern.
# The destination field is `destination.cloudFunction`, holding the FULL
# resource path (projects/P/locations/L/functions/NAME), not a bare name
# under `destination.cloudRun.service` -- also confirmed wrong the hard way
# (that field doesn't exist on a function-type trigger's destination).
$TriggerName = gcloud eventarc triggers list `
    --project=$Project --location=$Region `
    --filter="destination.cloudFunction:functions/$FunctionName" `
    --format="value(name)"

if ([string]::IsNullOrWhiteSpace($TriggerName)) {
    Write-Host "Could not find a trigger whose destination is $FunctionName."
    Write-Host "List all triggers to find it manually:"
    Write-Host "  gcloud eventarc triggers list --project=$Project --location=$Region"
    exit 1
}

$Subscription = gcloud eventarc triggers describe $TriggerName `
    --project=$Project --location=$Region `
    --format="value(transport.pubsub.subscription)"

if ([string]::IsNullOrWhiteSpace($Subscription)) {
    Write-Host "Found trigger $TriggerName but could not read its subscription."
    Write-Host "Describe it manually:"
    Write-Host "  gcloud eventarc triggers describe $TriggerName --project=$Project --location=$Region"
    exit 1
}

Write-Host "Found subscription: $Subscription"
Write-Host "Attaching dead-letter policy -> $DlqTopic (max attempts: $MaxDeliveryAttempts)..."

gcloud pubsub subscriptions update $Subscription `
    --project=$Project `
    --dead-letter-topic=$DlqTopic `
    --dead-letter-topic-project=$Project `
    --max-delivery-attempts=$MaxDeliveryAttempts `
    --min-retry-delay=$MinRetryBackoff `
    --max-retry-delay=$MaxRetryBackoff

Write-Host "Done. Verify with:"
Write-Host "  gcloud pubsub subscriptions describe $Subscription --project=$Project"
