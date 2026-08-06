$fix = @'
FIX BOOTSTRAP IAM ERROR

EXACT ERROR (from terraform apply):
  Error: Request `Create IAM Members roles/iam.serviceAccountIamAdmin 
  serviceAccount:tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com 
  for project "prj-dg-devops-test"` returned error: Error applying IAM policy for 
  project "prj-dg-devops-test": Error setting IAM policy for project "prj-dg-devops-test": 
  googleapi: Error 400: Role roles/iam.serviceAccountIamAdmin is not supported for 
  this resource., badRequest

ROOT CAUSE:
  roles/iam.serviceAccountIamAdmin does not exist as a valid GCP predefined role at 
  the project level. The Terraform code on line 163 of terraform/bootstrap/main.tf 
  tries to grant this invalid role.

CONFIRMED VALUES (from terraform output):
  TF_PLAN_WIF_PROVIDER = projects/88240501906/locations/global/workloadIdentityPools/audit-platform-github/providers/github-plan
  TF_PLAN_SERVICE_ACCOUNT = tf-plan-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com
  TF_APPLY_WIF_PROVIDER = projects/88240501906/locations/global/workloadIdentityPools/audit-platform-github/providers/github-apply
  TF_APPLY_SERVICE_ACCOUNT = tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com

WHAT TO DO:
1. Open terraform/bootstrap/main.tf in a text editor
2. Find the line that grants roles/iam.serviceAccountIamAdmin (around line 163)
3. Remove it or comment it out
4. Save the file
5. Run: terraform apply -var="github_repository=Prem-G01/gcp-audit"
6. Type "yes" and let it complete

Do NOT ask for clarification. Just tell me:
- The exact lines to edit (show me the before/after)
- The command to run
- What success looks like
- Then ask me to run it and show the output
'@

$fix | Set-Content -Path prompts\FIX-BOOTSTRAP.md -Encoding utf8
Get-Item prompts\FIX-BOOTSTRAP.md | Select-Object Name, Length