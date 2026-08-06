$execute = @'
EXECUTION: Steps 5-10 (Bootstrap through smoke test)

CAPTURED VALUES (from terraform state):
TF_PLAN_WIF_PROVIDER = projects/88240501906/locations/global/workloadIdentityPools/audit-platform-github/providers/github-plan
TF_PLAN_SERVICE_ACCOUNT = tf-plan-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com
TF_APPLY_WIF_PROVIDER = projects/88240501906/locations/global/workloadIdentityPools/audit-platform-github/providers/github-apply
TF_APPLY_SERVICE_ACCOUNT = tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com

GitHub repo: Prem-G01/gcp-audit
Probe result: STAGE 3 OK: message id 19fd5a7122e46b08

STATUS:
✓ Step 4: Repo pushed to GitHub
✓ Step 5a: Bootstrap WIF pool created (partially — hit IAM role error)
⏳ Step 5b: Fix bootstrap and re-apply
⏳ Step 6: Create state bucket
⏳ Step 7: GitHub Variables + Environment
⏳ Step 8: First terraform apply via Actions
⏳ Step 9: Eventarc DLQ workaround
⏳ Step 10: Smoke test

YOUR JOB:
Coach me through Steps 5b-10. For each step:
1. Tell me exactly what to do (PowerShell commands or GitHub web UI actions)
2. Tell me what to expect (output, success condition)
3. Ask me to paste the output before proceeding to the next step

START WITH STEP 5B: Fix the bootstrap error (roles/iam.serviceAccountIamAdmin is invalid at project scope) and re-apply.
'@

$execute | Set-Content -Path prompts\EXECUTE.md -Encoding utf8
Get-Item prompts\EXECUTE.md | Select-Object Name, Length