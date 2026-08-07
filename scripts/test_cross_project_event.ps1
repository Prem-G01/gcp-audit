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

$ErrorActionPreference = "Stop"

$Project        = "prj-dg-devops-test"  # the function's OWN project (topic lives here)
$OtherProjectId = "cross-project-demo-999"  # the project INSIDE the synthetic event's payload
$Topic          = "audit-platform-logs"

Write-Host "Publishing topic project: $Project"
Write-Host "Topic:                    $Topic"
Write-Host "Synthetic event's project_id (NOT prj-dg-devops-test): $OtherProjectId"
Write-Host ""
Write-Host "This publishes 1 synthetic event and will trigger 1 real email."
Write-Host ""
$Confirmation = Read-Host "Type 'test' to continue"
if ($Confirmation -ne "test") {
    Write-Host "Aborted."
    exit 1
}

function New-Timestamp {
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
}

function New-InsertId([string]$Prefix) {
    "$Prefix-$(Get-Random)"
}

$json = @{
    protoPayload = @{
        methodName          = "SetIamPolicy"
        resourceName        = "projects/$OtherProjectId"
        authenticationInfo  = @{ principalEmail = "cross-project-tester@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.222"; callerSuppliedUserAgent = "google-cloud-sdk" }
        request             = @{ policy = @{ bindings = @(@{ role = "roles/viewer"; members = @("user:cross-project-tester@example.com") }) } }
    }
    resource  = @{ type = "project"; labels = @{ project_id = $OtherProjectId } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-cross-project"
} | ConvertTo-Json -Depth 10 -Compress

$base64Data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
$token = gcloud auth print-access-token
$body = @{ messages = @(@{ data = $base64Data }) } | ConvertTo-Json -Depth 5

$result = Invoke-RestMethod `
    -Uri "https://pubsub.googleapis.com/v1/projects/$Project/topics/${Topic}:publish" `
    -Method Post `
    -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
    -Body $body

Write-Host "Published. messageId: $($result.messageIds[0])"
Write-Host ""
Write-Host "Wait ~20-30s, then check:"
Write-Host ""
Write-Host "  gcloud functions logs read process-audit-log-gmail-alerts ``"
Write-Host "    --project=$Project --region=asia-south1 --gen2 --limit=100 |"
Write-Host "    Select-String 'gmail_alert_sent|findings_evaluated|cai_enrichment_failed|cai_resource_not_found'"
Write-Host ""
Write-Host "Expect: 1x findings_evaluated (finding_count: 1), 1x gmail_alert_sent,"
Write-Host "and 1x cai_enrichment_failed (permission-denied on $OtherProjectId --"
Write-Host "confirms the degrade-gracefully caveat). Check your inbox for an email"
Write-Host "whose Project field shows '$OtherProjectId', not prj-dg-devops-test."
