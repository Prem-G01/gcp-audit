New-Item -ItemType Directory -Force -Path prompts | Out-Null

$troubleshoot = @'
TROUBLESHOOT: Gmail DWD Auth Probe Failure

The probe failed with:
  google.api_core.exceptions.RetryError: Timeout of 60.0s exceeded, last exception:
  503 Getting metadata from plugin failed with error: Reauthentication is needed.

Your job: diagnose and fix. Do NOT execute any commands yourself; generate the
exact commands to run and coach through interpretation of their output.

=============================================================================
DIAGNOSTIC CHECKLIST (read-only, no execution)
=============================================================================

Check 1: ADC State
---
Run this locally to see if ADC is stale:
  gcloud auth application-default print-access-token

Expected: prints a long token string
Actual: if it errors with "Reauthentication is needed", ADC is expired

Check 2: IAM Bindings (verify they actually landed)
---
Run this locally:
  $SA = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
  gcloud iam service-accounts get-iam-policy $SA --project=prj-dg-devops-test

Expected: shows both bindings:
  - serviceAccount:audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam...
  - user:premkumar.gunasekaran@securekloud.com
  with role: roles/iam.serviceAccountTokenCreator

Check 3: Gmail Configuration (verify workspace setup)
---
Cannot check from CLI; manual verification in Google Workspace Admin Console:
  A. Security → API Controls → Domain-wide delegation
     - Client ID: 108550589402351078214 (is it there?)
     - Scopes: https://www.googleapis.com/auth/gmail.send (exact match?)
  
  B. Users → premkumar.gunasekaran@docugenieai.com
     - License: has an active Workspace license assigned? (not Cloud Identity Free)

Check 4: Service Account Permissions (can it sign JWTs?)
---
Run this locally:
  gcloud projects get-iam-policy prj-dg-devops-test `
    --flatten="bindings[].members" `
    --filter="bindings.role:roles/iam.serviceAccountTokenCreator"

Expected: shows the SA itself in the list (for signJwt to work)

=============================================================================
REMEDIATION (if diagnostics reveal problems)
=============================================================================

If Check 1 failed (ADC expired):
---
gcloud auth application-default login
# Follow the browser prompt to authorize
# Return here and proceed to the next check

If Check 2 failed (IAM bindings missing):
---
This should not happen; the gcloud commands earlier printed "Updated IAM policy".
But if the bindings are not there:
  $SA = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
  gcloud iam service-accounts add-iam-policy-binding $SA `
    --member="serviceAccount:$SA" `
    --role="roles/iam.serviceAccountTokenCreator" `
    --project=prj-dg-devops-test
  gcloud iam service-accounts add-iam-policy-binding $SA `
    --member="user:premkumar.gunasekaran@securekloud.com" `
    --role="roles/iam.serviceAccountTokenCreator" `
    --project=prj-dg-devops-test
# Wait 30 seconds for IAM propagation

If Check 3 failed (DWD not set up correctly):
---
This is a Google Workspace Admin console task, not a GCP task.
  1. Go to admin.google.com → Security → API Controls → Domain-wide delegation
  2. Confirm 108550589402351078214 is listed
  3. Click it, confirm scope is EXACTLY https://www.googleapis.com/auth/gmail.send
  If the scope is missing or wrong, delete the entry and re-register it:
    - Go back to the GCP console, find the OAuth consent screen
    - Note the Client ID (should be 108550589402351078214)
    - Return to Workspace Admin and add it with scope gmail.send only

If Check 4 failed (SA not in token creator binding):
---
The SA needs to impersonate itself to sign JWTs. This was supposed to happen
in "Command 1" earlier. Run it now:
  $SA = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
  gcloud iam service-accounts add-iam-policy-binding $SA `
    --member="serviceAccount:$SA" `
    --role="roles/iam.serviceAccountTokenCreator" `
    --project=prj-dg-devops-test
# Wait 30 seconds for IAM propagation

=============================================================================
VERIFY THE FIX (after running remediation)
=============================================================================

After fixing any of the above, run the probe again:

$env:GMAIL_DELEGATED_SA = "audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com"
python scripts\probe_dwd.py premkumar.gunasekaran@docugenieai.com --send-test premkumar.gunasekaran@docugenieai.com

Expected output:
  STAGE 1 OK: signJwt succeeded
  STAGE 2 OK: delegated token acquired
  STAGE 3 OK: message id <id>

If STAGE 1 still fails:
  - Check 1 passed (ADC valid)?
  - Check 4 passed (SA in binding)?
  - Wait another 60 seconds and retry (IAM propagation can be slow)

If STAGE 2 fails:
  - Check 3A passed (DWD registered with correct scope)?
  - Check 3B passed (sender mailbox has a Workspace license)?

If STAGE 3 fails:
  - Check 3B again (sender mailbox must have Gmail-enabled license, not Cloud Identity Free)
  - Check the probe output; it will say which stage failed and why

=============================================================================
COACHING QUESTIONS (for Claude Code to ask you)
=============================================================================

After you run the diagnostic checks, you'll come back with output. Claude Code
will ask:
  1. Which checks passed?
  2. Which checks failed? Show me the output.
  3. Are you blocked on a Workspace Admin task (Check 3), or a GCP task (Checks 1, 2, 4)?
  4. If GCP: did IAM changes require a 60-second wait before retrying?
  5. If Workspace: did you confirm the DWD client ID and scope in Admin Console?

Then Claude Code will recommend which remediation to run, and you'll re-run
the probe to confirm the fix.
'@

$troubleshoot | Set-Content -Path prompts\TROUBLESHOOT.md -Encoding utf8
Get-Item prompts\TROUBLESHOOT.md | Select-Object Name, Length