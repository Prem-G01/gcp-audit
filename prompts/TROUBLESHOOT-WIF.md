$wif = @'
TROUBLESHOOT: WIF Attribute Condition

PROBLEM:
GitHub Actions workflow failed with:
  "The given credential is rejected by the attribute condition."

ROOT CAUSE:
The WIF provider has placeholder value:
  assertion.repository == "CHANGE_ME/gcp-audit"

Should be:
  assertion.repository == "Prem-G01/gcp-audit"

HOW TO FIX:
1. Edit terraform/bootstrap/main.tf
2. Find attribute_condition for github_apply provider
3. Change "CHANGE_ME/gcp-audit" to "Prem-G01/gcp-audit"
4. Save file
5. Run: terraform apply -var="github_repository=Prem-G01/gcp-audit"
6. Type yes and let it complete
7. Go to GitHub Actions and re-run the failed workflow

YOUR JOB (Claude Code):
1. Tell me the exact lines to edit (show before/after)
2. Tell me the terraform command to run
3. Ask me to run it and paste the "Apply complete" output
4. Then tell me how to re-run the GitHub Actions workflow
'@

$wif | Set-Content -Path prompts\TROUBLESHOOT-WIF.md -Encoding utf8
Get-Item prompts\TROUBLESHOOT-WIF.md | Select-Object Name, Length