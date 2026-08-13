# Builds and pushes the mute-web container image, then points the
# Terraform-managed Cloud Run service (terraform/modules/mute_web) at it.
#
# Prerequisite: `terraform apply` has already created the service once
# (with its placeholder image) -- this script only updates the image on
# the existing service; it never creates/deletes the service, its IAP
# config, or its IAM grants. Those stay Terraform-owned.
#
# Builds via Cloud Build (gcloud builds submit), not local Docker -- no
# Docker Desktop dependency on the dev machine. mute_web/cloudbuild.yaml
# points Cloud Build at mute_web/Dockerfile with the repo root as build
# context (needed because the Dockerfile COPYs src/ as well as mute_web/).
#
# This script does not push or deploy anything without an explicit
# 'deploy' typed at the confirmation prompt.

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Variables -- edit these, do not inline values into the commands below.
# ---------------------------------------------------------------------------
$Project     = "prj-dg-devops-test"
$Region      = "asia-south1"
$ServiceName = "mute-web"
$RepoName    = "mute-web"
$ImageTag    = Get-Date -Format "yyyyMMdd-HHmmss"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$Image = "$Region-docker.pkg.dev/$Project/$RepoName/$ServiceName`:$ImageTag"

$ActiveAccount = (gcloud config get-value account 2>$null)
$ActiveProject = (gcloud config get-value project 2>$null)

Write-Host "Project:               $Project"
Write-Host "Region:                $Region"
Write-Host "Cloud Run service:     $ServiceName"
Write-Host "Image:                 $Image"
Write-Host "Active gcloud account: $ActiveAccount"
Write-Host "Active gcloud project: $ActiveProject"
Write-Host ""
Write-Host "This assumes 'terraform apply' has already created the mute-web"
Write-Host "service, its Artifact Registry repo, and its IAP/IAM config."
Write-Host ""

$Confirmation = Read-Host "Type 'deploy' to continue"
if ($Confirmation -ne "deploy") {
    Write-Host "Aborted."
    exit 1
}

Write-Host "Compiling sources..."
Get-ChildItem -Path mute_web, src -Filter *.py -Recurse | ForEach-Object {
    python -m py_compile $_.FullName
    if (-not $?) { exit 1 }
}

Write-Host "Running tests..."
pytest -q
if (-not $?) { exit 1 }

Write-Host "Building and pushing image via Cloud Build (no local Docker needed)..."
gcloud builds submit `
    --project=$Project `
    --config=mute_web/cloudbuild.yaml `
    --substitutions="_IMAGE=$Image" `
    .
if (-not $?) { exit 1 }

Write-Host "Updating Cloud Run service..."
gcloud run deploy $ServiceName `
    --project=$Project `
    --region=$Region `
    --image=$Image

Write-Host "Done."
