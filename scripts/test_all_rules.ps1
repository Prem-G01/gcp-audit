# Publishes one synthetic audit-log event per shipped rule in
# config/rules.yaml (covering create, modify, a delete, a Workload
# Identity Federation caller, a new-project creation, and a billing
# change), so you can confirm all twelve rules -- and all five email
# templates -- actually fire against the live deployed pipeline, not
# just the one rule (iam_policy_change) the original smoke test covered.
# resource_created/resource_deleted (rules 11-12) don't get a dedicated
# event -- they're exercised incidentally via overlap on events 4, 7, 8.
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
# be sent and (for the four ai_analysis: true rules) real Vertex AI/Gemini
# calls, so it's not entirely free or silent -- hence the confirmation
# prompt below.

$ErrorActionPreference = "Stop"

$Project = "prj-dg-devops-test"
$Topic = "audit-platform-logs"
$DelayBetweenEventsSeconds = 5

Write-Host "Project: $Project"
Write-Host "Topic:   $Topic"
Write-Host "This publishes 10 synthetic events (matching all 10 rules, several with"
Write-Host "intentional overlap) and will trigger real emails and some real Gemini calls."
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
Publish-AuditEvent -Name "CREATE: firewalls.insert with 0.0.0.0/0 (expect: firewall_open_to_internet CRITICAL + resource_created HIGH)" -Payload @{
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

# --- 7. DELETE -- no rule 1-6 specifically covers deletes; this now exercises
# rule 12 (resource_deleted, HIGH, org-wide) instead of a true zero-match --
# see config/rules.yaml rule 12's comment.
Publish-AuditEvent -Name "DELETE: DeleteServiceAccount (expect: resource_deleted, HIGH)" -Payload @{
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
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 8. Federated (Workload Identity Federation) identity, no principalEmail
# at all -- only principalSubject, matching how GCP actually logs a pure WIF
# caller. Expected to match BOTH resource_created (rule 11, an "insert") and
# federated_identity_action (rule 8, ai_analysis: true).
Publish-AuditEvent -Name "WIF: compute.instances.insert via Workload Identity Federation (expect: resource_created + federated_identity_action, HIGH, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "v1.compute.instances.insert"
        resourceName        = "projects/$Project/zones/asia-south1-a/instances/ci-deployed-vm"
        authenticationInfo  = @{
            principalSubject = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github-pool/subject/repo:example-org/example-repo:ref:refs/heads/main"
        }
        requestMetadata     = @{ callerIp = "203.0.113.201"; callerSuppliedUserAgent = "google-api-go-client/0.5 GitHubActions" }
        request             = @{ name = "ci-deployed-vm"; machineType = "zones/asia-south1-a/machineTypes/e2-medium" }
    }
    resource  = @{ type = "gce_instance"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-wif-instance"
}

Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 9. New project created -- only rule 9's own match condition covers
# this ("CreateProject"); deliberately excluded from resource_created
# (rule 11) and the unclassified_admin_activity safety net, since rule 9
# already gives this its own dedicated, more detailed HIGH alert.
Publish-AuditEvent -Name "CREATE: CreateProject (expect: project_created, HIGH, +Gemini -- Template A)" -Payload @{
    protoPayload = @{
        methodName          = "google.cloud.resourcemanager.v3.Projects.CreateProject"
        resourceName        = "projects/test-shadow-project-999"
        authenticationInfo  = @{ principalEmail = "test-newproject@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.210" }
        request             = @{ project = @{ projectId = "test-shadow-project-999"; displayName = "test-shadow-project-999"; parent = "organizations/123456789012" } }
    }
    resource  = @{ type = "project"; labels = @{ project_id = "test-shadow-project-999" } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-project-created"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 10. Billing account linked to a project -- matches rule 10's
# (BillingAccount|ProjectBillingInfo) regex; also picked up by the
# unclassified_admin_activity safety net since "Update" is a mutating verb.
Publish-AuditEvent -Name "MODIFY: UpdateProjectBillingInfo (expect: billing_account_changed, CRITICAL, +Gemini -- Template D)" -Payload @{
    protoPayload = @{
        methodName          = "google.cloud.billing.v1.CloudBilling.UpdateProjectBillingInfo"
        resourceName        = "projects/$Project"
        authenticationInfo  = @{ principalEmail = "test-billing@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.220" }
        request             = @{ projectBillingInfo = @{ billingAccountName = "billingAccounts/000000-111111-222222" } }
    }
    resource  = @{ type = "project"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-billing-changed"
}

Write-Host ""
Write-Host "All 10 events published. Wait ~60s (6 events also call Gemini, which"
Write-Host "adds latency), then check:"
Write-Host ""
Write-Host "  gcloud functions logs read process-audit-log-gmail-alerts ``"
Write-Host "    --project=$Project --region=asia-south1 --gen2 --limit=250"
Write-Host ""
Write-Host "Expect 10x 'findings_evaluated' and 15x 'gmail_alert_sent' total --"
Write-Host "several events match more than one rule by design (see rule 7's"
Write-Host "comment in config/rules.yaml for why). 6 findings get an AI"
Write-Host "Analysis section (org_policy_modified, public_iam_grant,"
Write-Host "audit_config_changed, federated_identity_action, project_created,"
Write-Host "billing_account_changed). resource_created/resource_deleted"
Write-Host "(rules 11-12, HIGH) also fire for events 4, 7, and 8."
Write-Host ""
Write-Host "This run also exercises all 5 email templates:"
Write-Host "  A (Executive Dark)      -- project_created, resource_created, resource_deleted"
Write-Host "  B (Security Operations) -- iam_policy_change, org_policy_modified,"
Write-Host "                             audit_config_changed, federated_identity_action"
Write-Host "  C (Clean Enterprise)    -- unclassified_admin_activity"
Write-Host "  D (Executive Summary)   -- public_iam_grant, billing_account_changed"
Write-Host "  E (Engineer Detail)     -- firewall_open_to_internet, service_account_key_created"
