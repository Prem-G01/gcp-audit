# Bootstrap: Workload Identity Federation (one-time, manual)

This is the one deliberate exception to "CI applies everything" in this
repo: it creates the identities that CI later impersonates, so it has
nothing to impersonate yet and must be applied by a human, once, with local
state (no GCS backend -- there's no bucket policy or apply identity to
protect it with before this runs).

Run this **before** any GitHub Actions workflow exists for this repo, and
**before** running `terraform init` in the main `terraform/` stack.

## Prerequisites

- A GCP identity (your own user account) with, at minimum, the union of:
  `roles/iam.workloadIdentityPoolAdmin`, `roles/iam.serviceAccountAdmin`,
  `roles/resourcemanager.projectIamAdmin` on `prj-dg-devops-test` -- or
  simply Owner/Editor on the project for this one-time step only (that
  restriction is about the *pipeline's* service accounts, not the human
  running a one-time bootstrap).
- `gcloud auth application-default login` completed locally.
- The real GitHub repository this code lives in, in `owner/repo` form.

## Commands (generated -- you run these)

```powershell
cd terraform\bootstrap

# Authenticate your own user for this one-time apply.
gcloud auth application-default login

terraform init

terraform apply `
  -var="project_id=prj-dg-devops-test" `
  -var="github_repository=YOUR_GITHUB_OWNER/YOUR_REPO_NAME" `
  -var="deploy_branch=main"
```

```bash
cd terraform/bootstrap

gcloud auth application-default login

terraform init

terraform apply \
  -var="project_id=prj-dg-devops-test" \
  -var="github_repository=YOUR_GITHUB_OWNER/YOUR_REPO_NAME" \
  -var="deploy_branch=main"
```

## After it applies

Copy the five outputs into your GitHub repository's Settings -> Secrets and
variables -> Actions -> **Variables** tab (these are not secrets -- WIF
means there is no long-lived credential to protect):

| Terraform output | GitHub Actions variable |
|---|---|
| `plan_provider_resource_name` | `TF_PLAN_WIF_PROVIDER` |
| `apply_provider_resource_name` | `TF_APPLY_WIF_PROVIDER` |
| `plan_service_account_email` | `TF_PLAN_SERVICE_ACCOUNT` |
| `apply_service_account_email` | `TF_APPLY_SERVICE_ACCOUNT` |

```powershell
terraform output
```

Then configure a GitHub **Environment** named `production` (Settings ->
Environments) with required reviewers -- `.github/workflows/terraform.yml`
gates the apply job behind it.

## If `deployment_mode = "full"` (org-level sink)

The apply SA created here only has **project-level** roles. Granting it
`roles/logging.admin` at the **organization** level (required for
`google_logging_organization_sink`) is deliberately not automated here --
that's an org-level IAM change a project-scoped bootstrap script shouldn't
make on its own. An org admin runs this once, separately:

```powershell
gcloud organizations add-iam-policy-binding YOUR_ORG_ID `
  --member="serviceAccount:tf-apply-audit-platform@prj-dg-devops-test.iam.gserviceaccount.com" `
  --role="roles/logging.admin" `
  --condition=None
```

## Rotating or tearing down

This state is local (`terraform/bootstrap/terraform.tfstate`, gitignored).
Keep it somewhere durable (e.g. copy to a private location) after the first
apply -- losing it means the next `terraform apply` here would try to
recreate resources that already exist. To rotate, `terraform apply` again
with new values; to tear down entirely, `terraform destroy` (this only
touches the WIF pool/providers/plan+apply SAs, nothing in the main stack).
