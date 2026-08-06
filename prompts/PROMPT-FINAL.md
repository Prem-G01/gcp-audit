# FINAL EXECUTION — Complete this platform end to end

Corrected version -- see inline notes marked **[CORRECTED]** and
**[FLAGGED -- needs your confirmation]** for what changed from the
original draft and why. Nothing in this file is executed automatically;
every command is copy-paste-and-run-yourself, per `CLAUDE.md`'s "Do not
execute" rule.

All questions answered:
- DWD tenant: docugenieai.com
- Sender mailbox: premkumar.gunasekaran@docugenieai.com (Gmail-enabled)
- Runtime SA: audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com
- GitHub repo: (you will provide during bootstrap)

## STEP 1: Verify the environment (no execution, read-only)

Confirm these exist and are correct:
- CLAUDE.md at repo root -- confirmed present, 64 lines
- terraform/ directory with 6 modules -- confirmed: bigquery, cloud_function, iam, logging, monitoring, pubsub
- terraform/bootstrap/ with separate state -- confirmed present
- .github/workflows/ -- confirmed present, but named `ci.yml` + `terraform.yml`, not `ci.yaml` as originally expected (same content, cosmetic naming difference only, no action needed)
- All 103 tests passing (pytest -q) -- confirmed: `103 passed in 8.20s`
- Zero files under src/ or main.py modified since round 3 -- confirmed
- **[CORRECTED]** gcloud is actively authenticated in this environment as `premkumar.gunasekaran@docugenieai.com` -- any command below will run for real against real infrastructure once you run it yourself.
- **[CORRECTED]** No git remote is configured and zero commits exist in this repo across all three build rounds -- Step 4 below now includes the missing initialization.

If all confirmed, proceed. If anything is missing, stop and report.

## STEP 2: Generate the IAM bindings (copy-paste commands)

These commands MUST run before the probe. Copy each, run in a PowerShell
window authenticated as premkumar.gunasekaran@securekloud.com to
prj-dg-devops-test.

**[FLAGGED -- needs your confirmation]** Command 2 grants the role to
`user:premkumar.gunasekaran@securekloud.com`, but the gcloud identity
actually active in this environment is `premkumar.gunasekaran@
docugenieai.com` (different domain). If you run Command 2 unmodified, you
grant impersonation rights to an identity that isn't the one you're
locally authenticated as, and the probe will still fail with a permission
error. Confirm which is correct before running it -- is `securekloud.com`
an org managing this on behalf of the `docugenieai.com` Workspace tenant
(and you'll `gcloud auth login` as that identity separately), or was
`securekloud.com` a typo for `docugenieai.com`?

Command 1 (SA impersonation on itself -- required for signJwt):
```powershell
$SA = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
gcloud iam service-accounts add-iam-policy-binding $SA `
  --member="serviceAccount:$SA" `
  --role="roles/iam.serviceAccountTokenCreator" `
  --project=prj-dg-devops-test
```

Command 2 (your user, for local probe testing -- confirm the domain first):
```powershell
gcloud iam service-accounts add-iam-policy-binding $SA `
  --member="user:premkumar.gunasekaran@REPLACE_WITH_CORRECT_DOMAIN" `
  --role="roles/iam.serviceAccountTokenCreator" `
  --project=prj-dg-devops-test
```

Verify both completed without error. Then wait 30 seconds for IAM propagation.

## STEP 3: Run the probe (mandatory -- blocks everything until STAGE 3 passes)

This proves Gmail DWD auth works end to end. Matches
`scripts/probe_dwd.py`'s actual CLI exactly (verified against source).

```powershell
$env:GMAIL_DELEGATED_SA = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
python scripts\probe_dwd.py premkumar.gunasekaran@docugenieai.com --send-test premkumar.gunasekaran@docugenieai.com
```

Expected output:
```
STAGE 1 OK: signJwt succeeded
STAGE 2 OK: delegated token acquired
STAGE 3 OK: message id <id>
```

If STAGE 1 fails: the IAM bindings didn't propagate. Wait 60s and retry.
If STAGE 2 fails: DWD not registered or scope mismatch. Review Admin Console.
If STAGE 3 fails: sender mailbox has no Gmail license. Confirm in Workspace.

DO NOT PROCEED until you see "STAGE 3 OK: message id".

## STEP 4: Prepare GitHub (one-time setup)

**[CORRECTED]** This repo has zero commits and no remote across all three
build rounds -- the original draft's Step 8 assumed a repo already pushed
to GitHub. Do this first:

```powershell
git add -A
git commit -m "Initial commit: Gmail alerting pipeline, Terraform stack, CI/CD"
git remote add origin https://github.com/YOUR_OWNER/gcp-audit.git
git branch -M main
git push -u origin main
```

You will need:
- Your GitHub username / org name
- The gcp-audit repo created on GitHub and pushed (above)
- GitHub repo Settings access

Do not execute yet beyond the push above; the rest of GitHub configuration
happens in Step 7.

## STEP 5: Bootstrap WIF (one-time, creates permanent infrastructure)

After STAGE 3 passes, run this sequence:

```powershell
cd E:\gcp-audit\terraform\bootstrap
terraform init
terraform apply -var="github_repository=YOUR_OWNER/gcp-audit"
```

Replace YOUR_OWNER with your actual GitHub org/username.

**[CORRECTED]** The original draft's output variable names
(`wif_provider_plan_uri`, `plan_sa_email`, `wif_provider_apply_uri`,
`apply_sa_email`) don't match `terraform/bootstrap/outputs.tf` as actually
written. Corrected names below:

```powershell
terraform output -json | Tee-Object -Variable bootstrap_outputs
$bootstrap_outputs | ConvertFrom-Json | ForEach-Object {
  "TF_PLAN_WIF_PROVIDER = $($_.plan_provider_resource_name.value)"
  "TF_PLAN_SERVICE_ACCOUNT = $($_.plan_service_account_email.value)"
  "TF_APPLY_WIF_PROVIDER = $($_.apply_provider_resource_name.value)"
  "TF_APPLY_SERVICE_ACCOUNT = $($_.apply_service_account_email.value)"
}
```

Copy these 4 values.

## STEP 6: Create the Terraform state bucket

Run once (idempotent):
```powershell
gcloud storage buckets create gs://prj-dg-devops-test-tfstate `
  --project=prj-dg-devops-test `
  --location=asia-south1 `
  --uniform-bucket-level-access
```

## STEP 7: Configure GitHub repo (manual, in the web UI)

**[CORRECTED]** `TF_BACKEND_BUCKET` dropped -- nothing consumes it.
`terraform/backend.hcl` hardcodes the bucket name directly (an explicit
requirement: "GCS backend, hardcoded to avoid interactive prompts"). 5
items below, not 6.

A. Settings -> Variables (repo-level), add these:
```
TF_PLAN_WIF_PROVIDER = <value from step 5>
TF_PLAN_SERVICE_ACCOUNT = <value from step 5>
TF_APPLY_WIF_PROVIDER = <value from step 5>
TF_APPLY_SERVICE_ACCOUNT = <value from step 5>
TF_PROJECT_ID = prj-dg-devops-test
```

B. Settings -> Environments, create "production":
   - Add required reviewers (your GitHub username)
   - Deployment branches: "Selected branches", main only

C. Repo is already committed and pushed (Step 4).

## STEP 8: Trigger the first Terraform deploy

A. Create a branch: `git checkout -b feat/terraform-apply`
B. Make a trivial change to terraform/variables.tf (e.g., add a comment):
   `# Deployment initiated: 2026-08-06`
C. Commit and push:
```powershell
git add terraform/variables.tf
git commit -m "Trigger initial terraform apply"
git push origin feat/terraform-apply
```
D. Open a PR on GitHub. The `terraform.yml` workflow's `plan` job runs
   (triggered by the PR touching `terraform/**`).
   - Wait for fmt-check + plan to complete (~2 min)
   - Review the plan output posted as a PR comment
E. Merge to main. The `terraform.yml` workflow's `apply` job runs.
   - It asks for approval (GitHub Environment protection on "production")
   - Click "Review deployments", select "production", approve
   - `terraform apply` executes in Actions
   - Wait for completion (~3 min)
F. Confirm in Actions: the apply job succeeded.

## STEP 9: Workaround for Eventarc DLQ (Cloud Functions v2 limitation)

After terraform apply completes, run:
```powershell
.\scripts\configure_eventarc_dlq.ps1
```

This manually configures the dead-letter policy on the Pub/Sub subscription
because Terraform does not expose that field yet. See
`terraform/modules/pubsub/main.tf` for the documented limitation and the
workaround.

## STEP 10: Smoke test -- confirm the full pipeline

**[CORRECTED]** Original draft cut off mid-command. Completed below with a
payload shaped to match what `EnrichedEvent.from_log_entry` expects
(same shape as `tests/fixtures/set_iam_policy.json`) -- it will match the
`iam_policy_change` rule end to end.

```powershell
$msg = @{
  protoPayload = @{
    methodName = "SetIamPolicy"
    resourceName = "projects/prj-dg-devops-test"
    authenticationInfo = @{ principalEmail = "smoke-test@example.com" }
    requestMetadata = @{ callerIp = "203.0.113.10" }
    request = @{ policy = @{ bindings = @(@{ role = "roles/editor"; members = @("user:smoke-test@example.com") }) } }
  }
  resource = @{ type = "project"; labels = @{ project_id = "prj-dg-devops-test" } }
  severity = "NOTICE"
  timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
  insertId = "smoke-test-$(Get-Random)"
} | ConvertTo-Json -Depth 10

gcloud pubsub topics publish audit-platform-logs --project=prj-dg-devops-test --message=$msg
```

Note: `gcloud pubsub topics publish` base64-encodes the message
automatically -- no manual encoding needed. Eventarc wraps it in its own
base64 envelope on top of that; manually base64-encoding the payload
yourself before publishing would double-encode it and break decoding.

Check the Cloud Function logs and your inbox after ~30 seconds.
