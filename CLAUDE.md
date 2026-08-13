# GCP Audit Log -> Email Alerting Platform

## Purpose
Org-wide Cloud Audit Logs -> aggregated log sink -> Pub/Sub -> Cloud Function v2 ->
enrichment (Cloud Asset Inventory) -> YAML rule engine -> conditional Gemini ->
BigQuery + Gmail API HTML email alerts.

## Environment
- Project: prj-dg-devops-test
- Region: asia-south1 (Vertex AI: us-central1)
- Runtime: Python 3.12, Cloud Functions v2
- Runtime SA: audit-platform-sa-prj-dg-devop@prj-dg-devops-test.iam.gserviceaccount.com
- Gmail DWD: OAuth client 108550589402351078214, scope gmail.send only
- Dev machine: Windows, PowerShell, repo at E:\gcp-audit

## Frozen files - do not edit without asking first
src/senders/gmail_sender.py, src/email_template.py, src/models.py,
src/rules/engine.py, src/enrichment/asset_inventory.py, src/analysis/gemini.py,
src/persistence/bigquery.py, main.py

## Non-negotiable constraints
- NEVER read, write, or reference a service account JSON key file. Auth is
  keyless: IAM Credentials signJwt + JWT-bearer grant. No from_service_account_*,
  no with_subject, no GOOGLE_APPLICATION_CREDENTIALS pointing at a key.
- NEVER use SendGrid, Mailgun, SES, or smtplib. Gmail API only.
- The only OAuth scope in this repo is https://www.googleapis.com/auth/gmail.send
- Every audit-log-derived value passes through html.escape() before templating.
- Email HTML: inline CSS and <table> layout only. No <style>, flexbox, or grid,
  except one approved exception in `_wrap_html_document` (src/email_template.py):
  a `<style>` block containing only Gmail's proprietary `[data-ogsc]`/`[data-ogsb]`
  dark-mode override selectors -- inert on every other client, since only Gmail
  ever injects those attributes. No layout rules (flexbox/grid/positioning) may
  go in it; background-color/color overrides only.
- Rules, routing, severity styling live in config/*.yaml. No logic in Python.
- No eval() or exec() on config content.
- logging with structured extra fields. No print() in deployed code
  (scripts/probe_dwd.py is an interactive CLI and may print).
- Never log an access token, signed JWT, or full email body.
- pathlib.Path for all paths (Windows dev, Linux runtime).
- GCP clients are module-level lazy singletons, never per-invocation.
- CAI, BigQuery, and Gemini failures must never block the email.
- Gemini runs only when the matched rule sets ai_analysis: true.
- Permanent Gmail 4xx -> DLQ and ack. Transient/5xx/429 -> exponential backoff.
- Never re-raise GmailSendError from main.py (causes a Pub/Sub hot loop).

## Terraform constraints
- No SA keys. Provider uses impersonate_service_account. CI uses Workload
  Identity Federation, never a key in a repo secret.
- Modular: root composes modules, modules take variables, no hardcoded IDs.
- deployment_mode gates org-level resources ("project_only" | "full").
- Least privilege: never grant owner, editor, *.admin, or organizationAdmin.
- All subscriptions have dead-letter and retry policies.

## Conventions
- Every shell command in docs is labeled with target project + gcloud account.
- PowerShell alongside bash for every script.
- Full type hints, docstrings on public callables, frozen dataclasses between
  pipeline stages (never raw dicts).
- Tests mock all GCP clients. Zero network calls in the suite.

## Commands
- Lint:   ruff check src tests scripts main.py
- Types:  mypy src
- Test:   pytest -q
- Deploy: .\scripts\deploy.ps1

## Do not execute
gcloud, bq, terraform apply, git push, gcloud iam service-accounts keys create.
Generate the commands; the operator runs them.
