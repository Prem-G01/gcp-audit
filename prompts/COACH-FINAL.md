$coach = @'
COACHING SESSION: Steps 5b-10 to Production

KNOWN GOOD VALUES (from terraform state):
- TF_PLAN_WIF_PROVIDER: projects/88240501906/locations/global/workloadIdentityPools/audit-platform-github/providers/github-plan
- TF_PLAN_SERVICE_ACCOUNT: tf-plan-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com
- TF_APPLY_WIF_PROVIDER: projects/88240501906/locations/global/workloadIdentityPools/audit-platform-github/providers/github-apply
- TF_APPLY_SERVICE_ACCOUNT: tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com

KNOWN ISSUE:
Bootstrap terraform apply failed with: "roles/iam.serviceAccountIamAdmin is not supported for this resource"

STATUS:
✓ Probe passed: STAGE 3 OK
✓ Repo pushed: Prem-G01/gcp-audit on main
✓ Bootstrap WIF pool created
✗ Bootstrap role grant failed (IAM role error)
⏳ Need to fix and re-apply bootstrap

YOUR JOB:
Walk me through Steps 5b-10 step by step. Do NOT ask me to manually extract or paste values. Instead:
1. Tell me exactly what to do (copy/paste PowerShell commands or GitHub web UI steps)
2. Tell me what success looks like
3. When I paste output, interpret it and tell me the next step
4. Do not ask for clarification — just proceed coaching

START NOW: Step 5b is fixing the bootstrap error and re-applying. Tell me:
- Which file to edit (terraform/bootstrap/main.tf, which line, what to delete/comment)
- The exact command to run after fixing it
- What "success" output looks like
- Then ask me to run it and paste the output
'@

$coach | Set-Content -Path prompts\COACH-FINAL.md -Encoding utf8
Get-Item prompts\COACH-FINAL.md | Select-Object Name, Length Hello connect on the DevOps Tesla permission view permissions maximum