# Publishes one synthetic audit-log event per shipped rule in
# config/rules.yaml (covering create, modify, a delete, a Workload
# Identity Federation caller, a new-project creation, a billing change,
# a denied attempt, Data Access egress, a System Event, an IAM custom
# role change, and service account impersonation), so you can confirm
# all sixteen rules -- and all five email templates -- actually fire
# against the live deployed pipeline, not just the one rule
# (iam_policy_change) the original smoke test covered.
# resource_created/resource_deleted (rules 11-12) don't get a dedicated
# event -- they're exercised incidentally via overlap on events 4, 7, 8.
#
# Events 11-16 (the Policy Denied/Data Access/System Event rules) set
# `logName` explicitly in the payload, since those rules match on it --
# events 1-10 omit it entirely (a missing raw.logName is a non-match for
# every rule's `not: contains %2Fpolicy/%2Fdata_access/%2Fsystem_event`
# exclusion, so they're correctly treated as Admin Activity). Because
# this script injects directly into Pub/Sub, downstream of the log
# sink/audit-config entirely, events 11-16 exercise the RULE MATCHING
# and email/Gemini pipeline regardless of whether
# enable_data_access_logs/enable_system_event_logs/
# enable_impersonation_logs are actually turned on in Terraform -- this
# script can't tell you whether that plumbing itself is live, only
# whether the rules fire correctly once an event of that shape arrives.
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
# be sent and (for the ai_analysis: true rules) real Vertex AI/Gemini
# calls, so it's not entirely free or silent -- hence the confirmation
# prompt below.
#
# Events 17-20 are REGRESSION CHECKS, not rule-coverage events -- each one
# is shaped exactly like a self-noise source that has ACTUALLY fired a
# real false alert in production before being caught and excluded
# (numeric-ID-form impersonation of this platform's own two SAs; reads of
# its own tfstate/function-source buckets). Every one of these MUST
# produce zero findings. Unlike events 1-16, this script does NOT just
# tell you to go read logs for these -- it waits, then automatically
# queries BigQuery (every finding is persisted whether sent or not) for
# any of them by their tagged raw_log_id, and prints PASS/FAIL. This is
# the whole point: the last two live incidents (impersonation self-
# signing, tfstate reads) were only caught because someone happened to
# run a manual bq query well after the fact. Run this script BEFORE a
# terraform apply that touches config/rules.yaml, and a regression like
# either of those gets caught here instead of in production.
#
# Requires: bq CLI, already authenticated (same gcloud session used for
# the Pub/Sub publish calls below).
#
# Events 21-22 are OPTIONAL and off by default -- they validate the real
# data-size lookup in src/enrichment/data_volume.py (GCS object size /
# BigQuery job bytes) against an actual existing resource, rather than just
# confirming bulk_data_export_or_download matches (which events 12-13
# already do with fake resource names that can never resolve). Fill in
# $RealGcsObjectResourceName / $RealBqExtractJobResourceName below to
# enable them; unlike the automated regression check, their result can only
# be confirmed by reading the resulting email, not by querying BigQuery.

$ErrorActionPreference = "Stop"

$Project = "prj-dg-devops-test"
$Topic = "audit-platform-logs"
$DelayBetweenEventsSeconds = 5

# OPTIONAL -- fill these in with a REAL resource (not the excluded
# tfstate/function-source buckets) to exercise the actual data-size lookup
# in src/enrichment/data_volume.py (events 21-22 below), rather than just
# confirming the rule matches. Requires terraform apply to have already
# granted roles/storage.objectViewer / roles/bigquery.jobUser to the
# runtime SA. Leave blank to skip both -- everything else in this script
# still runs.
$RealGcsObjectResourceName = ""   # e.g. "projects/_/buckets/some-real-bucket/objects/some-real-object.csv"
$RealBqExtractJobResourceName = "" # e.g. "projects/prj-dg-devops-test/jobs/bqjob_r123_abc456"

Write-Host "Project: $Project"
Write-Host "Topic:   $Topic"
Write-Host "This publishes 20 synthetic events (16 matching all 16 rules, several with"
Write-Host "intentional overlap, plus 4 regression checks for known self-noise sources)"
Write-Host "and will trigger real emails and some real Gemini calls."
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
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 11. DENIED -- IAM blocks an attempted SetIamPolicy ---------------------
Publish-AuditEvent -Name "DENIED: SetIamPolicy blocked (expect: policy_denied_access_attempt, MEDIUM)" -Payload @{
    protoPayload = @{
        methodName          = "SetIamPolicy"
        resourceName        = "projects/$Project"
        status              = @{ code = 7; message = "PERMISSION_DENIED" }
        authenticationInfo  = @{ principalEmail = "test-denied@example.com" }
        authorizationInfo   = @(@{ permission = "resourcemanager.projects.setIamPolicy"; granted = $false })
        requestMetadata     = @{ callerIp = "203.0.113.230" }
    }
    resource  = @{ type = "project"; labels = @{ project_id = $Project } }
    severity  = "ERROR"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-policy-denied"
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fpolicy"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 12. DATA ACCESS -- BigQuery EXTRACT job (bulk export) ------------------
# Requires enable_data_access_logs = true for the real pipeline, but this
# script injects past the sink -- fires regardless (see header comment).
Publish-AuditEvent -Name "DATA ACCESS: BigQuery EXTRACT job (expect: bulk_data_export_or_download, HIGH, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "google.cloud.bigquery.v2.JobService.InsertJob"
        resourceName        = "projects/$Project/jobs/test-extract-job-001"
        authenticationInfo  = @{ principalEmail = "test-export@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.240" }
        metadata            = @{ jobChange = @{ job = @{ jobConfig = @{ type = "EXTRACT" } } } }
    }
    resource  = @{ type = "bigquery_dataset"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-bq-extract"
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 13. DATA ACCESS -- GCS object download ---------------------------------
Publish-AuditEvent -Name "DATA ACCESS: GCS object download (expect: bulk_data_export_or_download, HIGH, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "storage.objects.get"
        resourceName        = "projects/_/buckets/test-sensitive-bucket/objects/report.csv"
        authenticationInfo  = @{ principalEmail = "test-download@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.250" }
    }
    resource  = @{ type = "gcs_bucket"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-gcs-download"
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 14. SYSTEM EVENT -- VM preempted ---------------------------------------
# Requires enable_system_event_logs = true for the real pipeline; see
# header comment on why this script fires regardless.
Publish-AuditEvent -Name "SYSTEM EVENT: VM preempted (expect: system_event_occurred, LOW)" -Payload @{
    protoPayload = @{
        methodName          = "compute.instances.preempted"
        resourceName        = "projects/$Project/zones/asia-south1-a/instances/test-spot-vm"
        authenticationInfo  = @{}
    }
    resource  = @{ type = "gce_instance"; labels = @{ project_id = $Project } }
    severity  = "INFO"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-system-event"
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fsystem_event"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 15. MODIFY -- custom IAM role definition changed -----------------------
Publish-AuditEvent -Name "MODIFY: UpdateRole (expect: iam_custom_role_modified, HIGH, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "google.iam.admin.v1.UpdateRole"
        resourceName        = "projects/$Project/roles/testCustomRole"
        authenticationInfo  = @{ principalEmail = "test-role@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.99" }
        request             = @{ role = @{ includedPermissions = @("resourcemanager.projects.setIamPolicy") } }
    }
    resource  = @{ type = "iam_role"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-update-role"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 16. DATA ACCESS -- service account impersonation -----------------------
# Uses a made-up target SA (test-target-sa@...), NOT this platform's own
# two real service accounts -- those are deliberately excluded by
# service_account_impersonation's self-noise exclusion (see
# config/rules.yaml rule 17's comment), so using them here would test the
# wrong thing (a rule that correctly does NOT fire).
Publish-AuditEvent -Name "DATA ACCESS: GenerateAccessToken impersonation (expect: service_account_impersonation, HIGH, +Gemini)" -Payload @{
    protoPayload = @{
        methodName          = "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken"
        resourceName        = "projects/-/serviceAccounts/test-target-sa@$Project.iam.gserviceaccount.com"
        authenticationInfo  = @{ principalEmail = "test-impersonator@example.com" }
        requestMetadata     = @{ callerIp = "203.0.113.19" }
    }
    resource  = @{ type = "service_account"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = New-InsertId "test-impersonation"
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 17. REGRESSION CHECK -- runtime SA self-signs a JWT, numeric-ID form ---
# This is EXACTLY what fired a real HIGH alert (with a real Gemini call)
# on every single Gmail send until caught live and fixed -- the first
# version of service_account_impersonation's self-noise exclusion only
# matched the SA's EMAIL form; GCP actually logs SignJwt's target in
# numeric uniqueId form. MUST produce zero findings.
$RegressionInsertIds = @()
$iid = New-InsertId "test-noise-selfsign-jwt"
$RegressionInsertIds += $iid
Publish-AuditEvent -Name "REGRESSION CHECK: runtime SA self-signs JWT, numeric-ID form (MUST be zero alerts)" -Payload @{
    protoPayload = @{
        methodName          = "google.iam.credentials.v1.IAMCredentials.SignJwt"
        resourceName        = "projects/-/serviceAccounts/108550589402351078214"
        authenticationInfo  = @{ principalEmail = "audit-platform-sa-prj-dg-devop@$Project.iam.gserviceaccount.com" }
    }
    resource  = @{ type = "service_account"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = $iid
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 18. REGRESSION CHECK -- Terraform impersonates the deploy SA, numeric-ID form
$iid = New-InsertId "test-noise-tf-impersonation"
$RegressionInsertIds += $iid
Publish-AuditEvent -Name "REGRESSION CHECK: Terraform impersonates deploy SA, numeric-ID form (MUST be zero alerts)" -Payload @{
    protoPayload = @{
        methodName          = "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken"
        resourceName        = "projects/-/serviceAccounts/113755025732014374847"
        authenticationInfo  = @{ principalEmail = "test-operator@example.com" }
    }
    resource  = @{ type = "service_account"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = $iid
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 19. REGRESSION CHECK -- read of this platform's own tfstate bucket ----
$iid = New-InsertId "test-noise-tfstate-read"
$RegressionInsertIds += $iid
Publish-AuditEvent -Name "REGRESSION CHECK: GCS read of the tfstate bucket (MUST be zero alerts)" -Payload @{
    protoPayload = @{
        methodName          = "storage.objects.get"
        resourceName        = "projects/_/buckets/$Project-tfstate/objects/audit-platform/state/default.tfstate"
        authenticationInfo  = @{ principalEmail = "test-operator@example.com" }
    }
    resource  = @{ type = "gcs_bucket"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = $iid
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 20. REGRESSION CHECK -- read of this platform's own function-source bucket
$iid = New-InsertId "test-noise-function-source-read"
$RegressionInsertIds += $iid
Publish-AuditEvent -Name "REGRESSION CHECK: GCS read of the function-source bucket (MUST be zero alerts)" -Payload @{
    protoPayload = @{
        methodName          = "storage.objects.get"
        resourceName        = "projects/_/buckets/$Project-function-source/objects/source-test.zip"
        authenticationInfo  = @{ principalEmail = "service-88240501906@gcf-admin-robot.iam.gserviceaccount.com" }
    }
    resource  = @{ type = "gcs_bucket"; labels = @{ project_id = $Project } }
    severity  = "NOTICE"
    timestamp = New-Timestamp
    insertId  = $iid
    logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
}

# --- 21. OPTIONAL: real GCS object download -- validates the actual data-
# size LOOKUP (src/enrichment/data_volume.py's Storage API call), not just
# that the rule matches like event 13 already does. Cannot be auto-checked
# via BigQuery like events 17-20 -- data_size_display only ever reaches the
# rendered email, it's not a persisted column -- so this requires checking
# the resulting email's "Data Size" field by eye.
if ($RealGcsObjectResourceName) {
    Publish-AuditEvent -Name "REAL DATA SIZE: GCS object download (expect: bulk_data_export_or_download, HIGH -- check email's Data Size field)" -Payload @{
        protoPayload = @{
            methodName          = "storage.objects.get"
            resourceName        = $RealGcsObjectResourceName
            authenticationInfo  = @{ principalEmail = "test-real-download@example.com" }
            requestMetadata     = @{ callerIp = "203.0.113.251" }
        }
        resource  = @{ type = "gcs_bucket"; labels = @{ project_id = $Project } }
        severity  = "NOTICE"
        timestamp = New-Timestamp
        insertId  = New-InsertId "test-real-gcs-size"
        logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
    }
} else {
    Write-Host "Skipping event 21 (real GCS data-size lookup) -- set `$RealGcsObjectResourceName at the top of this script to exercise it."
}
Start-Sleep -Seconds $DelayBetweenEventsSeconds

# --- 22. OPTIONAL: real BigQuery EXTRACT job -- validates the actual
# jobs.get byte-count lookup against a job that really ran, same caveat as
# event 21 (email-only, not BigQuery-checkable).
if ($RealBqExtractJobResourceName) {
    Publish-AuditEvent -Name "REAL DATA SIZE: BigQuery EXTRACT job (expect: bulk_data_export_or_download, HIGH -- check email's Data Size field)" -Payload @{
        protoPayload = @{
            methodName          = "google.cloud.bigquery.v2.JobService.InsertJob"
            resourceName        = $RealBqExtractJobResourceName
            authenticationInfo  = @{ principalEmail = "test-real-export@example.com" }
            requestMetadata     = @{ callerIp = "203.0.113.252" }
            metadata            = @{ jobChange = @{ job = @{ jobConfig = @{ type = "EXTRACT" } } } }
        }
        resource  = @{ type = "bigquery_dataset"; labels = @{ project_id = $Project } }
        severity  = "NOTICE"
        timestamp = New-Timestamp
        insertId  = New-InsertId "test-real-bq-size"
        logName   = "projects/$Project/logs/cloudaudit.googleapis.com%2Fdata_access"
    }
} else {
    Write-Host "Skipping event 22 (real BigQuery data-size lookup) -- set `$RealBqExtractJobResourceName at the top of this script to exercise it."
}

Write-Host ""
Write-Host "All 20 events published (16 rule-coverage + 4 regression checks)."
Write-Host "Plus any of events 21-22 (real data-size lookups) you enabled above."
Write-Host ""
Write-Host "To inspect the full run manually, check:"
Write-Host ""
Write-Host "  gcloud functions logs read process-audit-log-gmail-alerts ``"
Write-Host "    --project=$Project --region=asia-south1 --gen2 --limit=350"
Write-Host ""
Write-Host "Expect 16x 'findings_evaluated' and 21x 'gmail_alert_sent' total --"
Write-Host "several events match more than one rule by design (see rule 7's"
Write-Host "comment in config/rules.yaml for why). 10 findings get an AI"
Write-Host "Analysis section: the original 6 (org_policy_modified,"
Write-Host "public_iam_grant, audit_config_changed, federated_identity_action,"
Write-Host "project_created, billing_account_changed) plus 4 new ones"
Write-Host "(bulk_data_export_or_download fires on both events 12 and 13,"
Write-Host "iam_custom_role_modified on event 15, service_account_impersonation"
Write-Host "on event 16). Events 11-16 are each designed to match exactly one"
Write-Host "rule apiece -- no overlap, unlike some of events 1-10."
Write-Host "resource_created/resource_deleted (rules 11-12, HIGH) also fire for"
Write-Host "events 4, 7, and 8."
Write-Host ""
Write-Host "This run also exercises all 5 email templates (see"
Write-Host "src/email_template.py's _select_template -- explicit rule-id overrides"
Write-Host "win; everything else falls through by severity: CRITICAL->D, HIGH->A,"
Write-Host "else->C):"
Write-Host "  A (Executive Dark)      -- project_created, resource_created, resource_deleted,"
Write-Host "                             bulk_data_export_or_download, iam_custom_role_modified,"
Write-Host "                             service_account_impersonation (HIGH fallback)"
Write-Host "  B (Security Operations) -- iam_policy_change, org_policy_modified,"
Write-Host "                             audit_config_changed, federated_identity_action"
Write-Host "  C (Clean Enterprise)    -- unclassified_admin_activity,"
Write-Host "                             policy_denied_access_attempt, system_event_occurred"
Write-Host "  D (Executive Summary)   -- public_iam_grant, billing_account_changed"
Write-Host "  E (Engineer Detail)     -- firewall_open_to_internet, service_account_key_created"
Write-Host ""
if ($RealGcsObjectResourceName -or $RealBqExtractJobResourceName) {
    Write-Host "You enabled one or more real data-size lookups (events 21-22). Check the"
    Write-Host "resulting email(s)' Data Size field by eye -- this can't be verified via"
    Write-Host "BigQuery like the regression checks below, since data_size_display is"
    Write-Host "only ever rendered into the email, never persisted as its own column."
    Write-Host ""
}

# --- Automated regression check -------------------------------------------
# This is the actual point of events 17-20: don't just print instructions
# and hope someone remembers to check -- wait for processing, then query
# BigQuery (every finding is persisted whether sent or not) for any of the
# 4 tagged noise-shaped events, and give a clear PASS/FAIL. Run this BEFORE
# a terraform apply that touches config/rules.yaml -- the last two live
# incidents (impersonation self-signing, tfstate reads) were only caught
# because someone happened to run this exact kind of query well after the
# fact, in production.
$RegressionWaitSeconds = 90
Write-Host "Waiting ${RegressionWaitSeconds}s for processing, then checking for noise regressions..."
Start-Sleep -Seconds $RegressionWaitSeconds

$idList = ($RegressionInsertIds | ForEach-Object { "'$_'" }) -join ", "
$query = "SELECT rule_id, raw_log_id, resource_name FROM ``$Project.audit_platform.alert_events`` WHERE raw_log_id IN ($idList)"
$resultJson = bq query --use_legacy_sql=false --format=json $query
$result = $resultJson | ConvertFrom-Json

Write-Host ""
if ($result -and $result.Count -gt 0) {
    Write-Host "REGRESSION DETECTED -- $($result.Count) noise-shaped event(s) that should have" -ForegroundColor Red
    Write-Host "produced ZERO findings actually matched a rule:" -ForegroundColor Red
    Write-Host ""
    $result | ForEach-Object {
        Write-Host "  rule_id=$($_.rule_id)  raw_log_id=$($_.raw_log_id)" -ForegroundColor Red
        Write-Host "    resource_name=$($_.resource_name)" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "A self-noise exclusion in config/rules.yaml is broken. Do NOT consider" -ForegroundColor Red
    Write-Host "config changes safe to ship until this is fixed -- check the matching" -ForegroundColor Red
    Write-Host "rule's exclusions against the resource_name/method_name shapes above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "PASS -- all 4 noise-shaped regression events correctly produced zero findings." -ForegroundColor Green
}
