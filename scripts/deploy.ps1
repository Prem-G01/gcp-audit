# Deploys the Gmail alerting Cloud Function.
#
# Edit the variables below before running. This script does not deploy
# anything without an explicit "deploy" typed at the confirmation prompt.

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Variables -- edit these, do not inline values into the gcloud command below.
# ---------------------------------------------------------------------------
$Project           = "prj-dg-devops-test"
$Region            = "asia-south1"
$Topic             = "audit-platform-logs"
$ServiceAccount    = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
$GmailSender       = "premkumar.gunasekaran@docugenieai.com"
$GmailSenderName   = "GCP Audit Platform"
$GmailMaxAttempts  = "4"
$GmailTimeout      = "30"
$CaiCacheTtl       = "300"
$CaiTimeout        = "10"
$VertexProject     = "prj-dg-devops-test"
$VertexLocation    = "us-central1"
$GeminiModel       = "gemini-2.5-flash"
$GeminiMaxTokens   = "400"
$GeminiTimeout     = "20"
$BqProject         = "prj-dg-devops-test"
$BqDataset         = "audit_platform"
$BqTable           = "alert_events"
$DlqTopic          = "audit-platform-dlq"
$DlqProject        = "prj-dg-devops-test"
$FirestoreProject  = "prj-dg-devops-test"
$FunctionName      = "process-audit-log-gmail-alerts"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$ActiveAccount = (gcloud config get-value account 2>$null)
$ActiveProject = (gcloud config get-value project 2>$null)

Write-Host "Project:               $Project"
Write-Host "Region:                $Region"
Write-Host "Function:              $FunctionName"
Write-Host "Service account:       $ServiceAccount"
Write-Host "Active gcloud account: $ActiveAccount"
Write-Host "Active gcloud project: $ActiveProject"
Write-Host ""
Write-Host "Recipient routing comes from config/routing.yaml -- review it before deploying."
Write-Host ""

$Confirmation = Read-Host "Type 'deploy' to continue"
if ($Confirmation -ne "deploy") {
    Write-Host "Aborted."
    exit 1
}

Write-Host "Compiling sources..."
python -m py_compile main.py
if (-not $?) { exit 1 }
Get-ChildItem -Path src, scripts -Filter *.py -Recurse | ForEach-Object {
    python -m py_compile $_.FullName
    if (-not $?) { exit 1 }
}

Write-Host "Running tests..."
pytest -q
if (-not $?) { exit 1 }

Write-Host "Deploying..."
gcloud functions deploy $FunctionName `
    --project=$Project `
    --gen2 `
    --region=$Region `
    --runtime=python312 `
    --entry-point=process_audit_log `
    --trigger-topic=$Topic `
    --service-account=$ServiceAccount `
    --memory=512Mi `
    --timeout=120s `
    --max-instances=20 `
    --retry `
    --set-env-vars="GMAIL_DELEGATED_SA=$ServiceAccount,GMAIL_SENDER=$GmailSender,GMAIL_SENDER_NAME=$GmailSenderName,GMAIL_MAX_ATTEMPTS=$GmailMaxAttempts,GMAIL_TIMEOUT=$GmailTimeout,CAI_CACHE_TTL_SECONDS=$CaiCacheTtl,CAI_TIMEOUT_SECONDS=$CaiTimeout,VERTEX_PROJECT=$VertexProject,VERTEX_LOCATION=$VertexLocation,GEMINI_MODEL=$GeminiModel,GEMINI_MAX_TOKENS=$GeminiMaxTokens,GEMINI_TIMEOUT=$GeminiTimeout,BQ_PROJECT=$BqProject,BQ_DATASET=$BqDataset,BQ_TABLE=$BqTable,DLQ_TOPIC=$DlqTopic,DLQ_PROJECT=$DlqProject,FIRESTORE_PROJECT=$FirestoreProject"

Write-Host "Done."
