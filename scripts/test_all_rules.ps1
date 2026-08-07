# Publishes one synthetic audit-log event per shipped rule in
# config/rules.yaml (covering create, modify, and a delete that should NOT
# match anything), so you can confirm all six rules actually fire against
# the live deployed pipeline -- not just the one rule (iam_policy_change)
# the original smoke test covered.
#
# Uses the Pub/Sub REST API directly (not `gcloud pubsub topics publish
# --message=...`) -- the CLI approach was proven unreliable earlier in this
# project: multi-layered PowerShell -> cmd.exe -> Python argument quoting
# corrupts JSON containing embedded double quotes. This avoids that
# entirely by sending the JSON as an HTTP body, never a shell argument.
#
# Nothing here creates, deletes, or modifies any real GCP resource --
# every event is synthetic, injected directly into the Pub/Sub topic the
# real org-wide log sink would otherwise feed. It DOES cause real emails to
# be sent and (for the three ai_analysis: true rules) real Vertex AI/Gemini
# calls, so it's not entirely free or silent -- hence the confirmation
# prompt below.

$ErrorActionPreference = "Stop"

$Project = "prj-dg-devops-test"
$Topic = "audit-platform-logs"
$DelayBetweenEventsSeconds = 5

Write-Host "Project: $Project"
Write-Host "Topic:   $Topic"
Write-Host "This publishes 7 synthetic events (6 rule matches + 1 deliberate"
Write-Host "non-match) and will trigger real emails and some real Gemini calls."
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

function Publish-AuditEvent {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [hashtable]$Payload
    )
    $json = $Payload | ConvertTo-Json -Depth 10 -Compress
    $base64Data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
    $token = gcloud auth print-access-token
    $body = @{ messages = @(@{ data = $base64Data }) } | ConvertTo-Json -Depth 5

    Write-Host "Publishing: $Name"
    $result = Invoke-RestMethod `
        -Uri "https://pubsub.googleapis.com/v1/projects/$Project/topics/${Topic}:publish" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
        -Body $body
    Write-Host "  -> messageId: $($result.messageIds[0])"
}

# --- 1. MODIFY -- generic IAM policy change --------------------------------
Publish-AuditEvent -Name "MODIFY: SetIamPolicy (expect: iam_policy_change, HIGH)" -Payload @{
    protoPayload = @{
        methodName          = "SetIamPolicy"
        resourceName        = "projects/$Project"
        authenticationInfo  = @{ principalEmail = "test-modify@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.10" }
        request             = @{ policy = @{ bindings = @(@{ role = "roles/editor"; members = @("user:test-modify@example.com") }) } }
    }
    resource  = @{ type = "project"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-modify-iam"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 2. CREATE -- service account key ---------------------------------------
Publish-AuditEvent -Name "CREATE: CreateServiceAccountKey (expect: service_account_key_created, HIGH)" -Payload @{
    protoPayload = @{
        methodName          = "google.iam.admin.v1.CreateServiceAccountKey"
        resourceName        = "projects/$Project/serviceAccounts/test-sa@$Project.iam.gserviceaccount.com/keys/testkey123"
        authenticationInfo  = @{ principalEmail = "test-create@example.com" }
        requestMetadata     = @{ callerIp = "198.51.100.20" }
    }
    resource  = @{ type = "service_account"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-create-sakey"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 3. MODIFY -- org policy update (ai_analysis: true) --------------------
Publish-AuditEvent -Name "MODIFY: OrgPolicy.UpdatePolicy (expect: org_policy_modified, HIGH, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "google.cloud.orgpolicy.v2.OrgPolicy.UpdatePolicy"
        resourceName        = "organizations/123456789012/policies/compute.vmExternalIpAccess"
        authenticationInfo  = @{ principalEmail = "test-orgpolicy@example.com" }
        requestMetadata     = @{ callerIp = "192.0.2.5" }
    }
    resource  = @{ type = "organization"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-orgpolicy"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 4. CREATE -- firewall rule open to the internet ------------------------
Publish-AuditEvent -Name "CREATE: firewalls.insert with 0.0.0.0/0 (expect: firewall_open_to_internet, CRITICAL)" -Payload @{
    protoPayload = @{
        methodName          = "v1.compute.firewalls.insert"
        resourceName        = "projects/$Project/global/firewalls/test-allow-all"
        authenticationInfo  = @{ principalEmail = "test-firewall@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.99" }
        request             = @{ sourceRanges = @("0.0.0.0/0"); allowed = @(@{ IPProtocol = "tcp"; ports = @("22") }) }
    }
    resource  = @{ type = "gce_firewall_rule"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-firewall"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 5. MODIFY -- public IAM/bucket grant (ai_analysis: true) --------------
Publish-AuditEvent -Name "MODIFY: SetIamPolicy with allUsers (expect: public_iam_grant, CRITICAL, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "SetIamPolicy"
        resourceName        = "projects/_/buckets/test-public-bucket"
        authenticationInfo  = @{ principalEmail = "test-public@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.77" }
        request             = @{ policy = @{ bindings = @(@{ role = "roles/storage.objectViewer"; members = @("allUsers") }) } }
    }
    resource  = @{ type = "storage_bucket"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-public-grant"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 6. MODIFY -- audit logging config change (ai_analysis: true) ----------
Publish-AuditEvent -Name "MODIFY: SetIamPolicy with auditConfigs (expect: audit_config_changed, HIGH, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "SetIamPolicy"
        resourceName        = "projects/$Project"
        authenticationInfo  = @{ principalEmail = "test-auditconfig@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.88" }
        request             = @{ policy = @{ auditConfigs = @(@{ service = "allServices"; auditLogConfigs = @(@{ logType = "DATA_READ" }) }) } }
    }
    resource  = @{ type = "project"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-auditconfig"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 7. DELETE -- no shipped rule covers deletes; confirms the zero-match --
# path works cleanly (evaluated, no findings, no email, no error).
Publish-AuditEvent -Name "DELETE: DeleteServiceAccount (expect: NO MATCH -- zero findings, no email)" -Payload @{
    protoPayload = @{
        methodName          = "google.iam.admin.v1.DeleteServiceAccount"
        resourceName        = "projects/$Project/serviceAccounts/old-unused-sa@$Project.iam.gserviceaccount.com"
        authenticationInfo  = @{ principalEmail = "test-delete@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.55" }
    }
    resource  = @{ type = "service_account"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-delete-sa"
}

Write-Host ""
Write-Host "All 7 events published. Wait ~60s (the org_policy/public_grant/"
Write-Host "audit_config events also call Gemini, which adds latency), then check:"
Write-Host ""
Write-Host "  gcloud functions logs read process-audit-log-gmail-alerts ``"
Write-Host "    --project=$Project --region=asia-south1 --gen2 --limit=50"
Write-Host ""
Write-Host "Expect 6x 'gmail_alert_sent' and 1x 'findings_evaluated' with"
Write-Host "finding_count: 0 and no send attempt (the DeleteServiceAccount event)."
Write-Host "Also expect 6 emails in your inbox with 6 different severity colors"
Write-Host "and rule titles, and 3 of them ('org_policy_modified',"
Write-Host "'public_iam_grant', 'audit_config_changed') should have an AI Analysis"
Write-Host "section populated in the email body."
