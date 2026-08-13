#!/usr/bin/env bash
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
set -euo pipefail

# ---------------------------------------------------------------------------
# Variables -- edit these, do not inline values into the commands below.
# ---------------------------------------------------------------------------
PROJECT="prj-dg-devops-test"
REGION="asia-south1"
SERVICE_NAME="mute-web"
REPO_NAME="mute-web"
IMAGE_TAG="$(date +%Y%m%d-%H%M%S)"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO_NAME}/${SERVICE_NAME}:${IMAGE_TAG}"

ACTIVE_ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
ACTIVE_PROJECT="$(gcloud config get-value project 2>/dev/null || true)"

echo "Project:               $PROJECT"
echo "Region:                $REGION"
echo "Cloud Run service:     $SERVICE_NAME"
echo "Image:                 $IMAGE"
echo "Active gcloud account: $ACTIVE_ACCOUNT"
echo "Active gcloud project: $ACTIVE_PROJECT"
echo ""
echo "This assumes 'terraform apply' has already created the mute-web"
echo "service, its Artifact Registry repo, and its IAP/IAM config."
echo ""

read -r -p "Type 'deploy' to continue: " CONFIRMATION
if [[ "$CONFIRMATION" != "deploy" ]]; then
    echo "Aborted."
    exit 1
fi

echo "Compiling sources..."
python -m py_compile mute_web/*.py src/**/*.py src/*.py

echo "Running tests..."
pytest -q

echo "Building and pushing image via Cloud Build (no local Docker needed)..."
gcloud builds submit \
    --project="$PROJECT" \
    --config=mute_web/cloudbuild.yaml \
    --substitutions="_IMAGE=$IMAGE" \
    .

echo "Updating Cloud Run service..."
gcloud run deploy "$SERVICE_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --image="$IMAGE"

echo "Done."
