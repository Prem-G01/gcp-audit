# GCS backend config, hardcoded so `terraform init` never prompts.
#
# PLACEHOLDER bucket name -- it must exist before `terraform init -backend-
# config=backend.hcl` will succeed. Create it once (not run by any script
# here):
#
#   gcloud storage buckets create gs://prj-dg-devops-test-tfstate `
#     --project=prj-dg-devops-test --location=asia-south1 `
#     --uniform-bucket-level-access
#   gcloud storage buckets update gs://prj-dg-devops-test-tfstate --versioning
#
bucket = "prj-dg-devops-test-tfstate"
prefix = "audit-platform/state"
