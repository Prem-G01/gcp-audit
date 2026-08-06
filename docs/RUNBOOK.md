# Operational Runbook

One section per alert policy (`terraform/modules/monitoring/main.tf`), plus
general pipeline operations. Every alert links back to a specific pipeline
stage -- see the architecture diagram in `README.md` if you need the full
picture.

## Before you rely on any of this

Log-based metrics here filter on **`textPayload`**, not `jsonPayload`. The
frozen application code (`main.py`, `src/`) configures plain
`logging.basicConfig(level=logging.INFO)` with no JSON formatter, so
`logger.error("gmail_alert_send_failed", extra={...})` lands in Cloud
Logging as an unstructured text line -- the `extra` fields are **not**
queryable as structured jsonPayload fields today. The alert policies below
work (they match on the literal message substring), but you cannot filter
Logs Explorer on e.g. `jsonPayload.rule_id="public_iam_grant"` -- only on
`textPayload:"public_iam_grant"` (substring, unstructured). If a future
change adds a JSON log formatter to `src/`, revisit
`terraform/modules/monitoring/main.tf`'s filters to use `jsonPayload.*`
instead, which would make every filter below exact rather than
substring-based.

---

## Alert: audit-platform: Cloud Function execution errors

**Fires when**: any Cloud Function execution has a non-`"ok"` status.

**Pivot into Logs Explorer**:
```
resource.type="cloud_function"
resource.labels.function_name="process-audit-log-gmail-alerts"
severity>=ERROR
```

**Likely causes, by what the traceback mentions**:
- `functions_framework`/`cloudevents` import or decode errors ->
  malformed Pub/Sub message shape (should be rare -- `_decode_message`
  catches base64/JSON errors and acks instead of raising; a genuine
  exception here means something upstream changed the message shape).
- `RuntimeError` from `evaluate_rules`/`enrich` -> a real bug, not a
  config issue (both are constraint-guaranteed not to raise under normal
  operation; check the traceback for which one).
- Timeout (execution exceeded `function_timeout_seconds`) -> check whether
  a specific finding's Gemini/CAI/BigQuery call is hanging past its own
  configured timeout; the app's own timeouts (`GEMINI_TIMEOUT`,
  `CAI_TIMEOUT_SECONDS`) should prevent this, so a function-level timeout
  suggests unusually high finding volume in one message instead.

**Remediation**: read the actual stack trace in Logs Explorer first --
this alert is intentionally coarse (any non-ok execution), the traceback
tells you which pipeline stage actually broke.

---

## Alert: audit-platform: DLQ has undelivered messages

**Fires when**: the DLQ drain subscription's backlog is > 0 for 15
sustained minutes.

**Pivot into Logs Explorer** (find the actual failure reason before
touching Pub/Sub):
```
resource.type="cloud_run_revision"
textPayload:"gmail_alert_send_failed"
```

**Likely causes** (matches `README.md`'s Gmail troubleshooting table):
DWD scope mismatch, sender mailbox lost its Gmail license, `GMAIL_SENDER`
drifted from the `sub` claim, or a sustained Gmail API outage.

**Remediation**:
1. `gcloud pubsub subscriptions pull audit-platform-dlq-drain --project=prj-dg-devops-test --auto-ack --limit=5` to inspect a few messages -- each has a `reason` field with the exact `GmailSendError` text and the full serialized `finding`.
2. Fix the underlying cause (see the Gmail troubleshooting table in `README.md`).
3. Undeliverable findings are NOT automatically retried once dead-lettered -- if they still matter, republish them to the main topic manually, or accept the loss (they're also persisted to BigQuery with `delivery_status="failed"`, so nothing is silently lost).
4. If the backlog is old enough to have hit 5 delivery attempts, it will have moved to `audit-platform-dlq-exhausted` -- check there too (`gcloud pubsub subscriptions pull` after creating an ad-hoc subscription on it, or query the BigQuery `delivery_status="failed"` rows instead, which is usually easier).

---

## Alert: audit-platform: no function executions in 1h

**Fires when**: zero executions for a full hour -- the canary for "the
pipeline went silently dark," which nothing else here catches (no
exception is raised anywhere for "no events arrived").

**Likely causes**:
- The org-wide log sink stopped exporting (check `deployment_mode`;
  if it's `"project_only"`, this is expected in an environment with no
  local audit activity -- tune or disable this alert accordingly).
- The Eventarc trigger broke (check `gcloud eventarc triggers describe`
  for the trigger's status).
- No qualifying audit events actually occurred (genuinely quiet period --
  raise the 1h duration in `terraform/modules/monitoring/main.tf` if this
  fires too often in a low-traffic project).

**Remediation**: `gcloud eventarc triggers list --project=prj-dg-devops-test --location=asia-south1` to confirm the trigger is `ACTIVE`; `gcloud logging sinks describe <sink-name> --organization=<org-id>` (if `deployment_mode = "full"`) to confirm the org sink's `writerIdentity` still has publish rights (a manual IAM change outside Terraform could have removed it).

---

## Alert: audit-platform: caught pipeline failures

**Fires when**: any of the five failure-class log-based metrics is > 0 in
a 5-minute window (Gmail send, DLQ write, BigQuery persist, malformed
payload, unexpected per-finding failure). These are all failures the app
deliberately *catches* rather than raises (constraint: CAI/BigQuery/Gemini
failures must never block the email) -- which is exactly why they need
external alerting instead of the coarse execution-error policy above.

**Pivot into Logs Explorer** by the specific message name (`gmail_alert_
send_failed`, `dlq_write_failed`, `bigquery_persist_failed`/`bigquery_
insert_errors`, `payload_decode_failed`, `finding_processing_failed`) --
see `README.md`'s troubleshooting table for the full cause/fix mapping per
message name.

**Remediation**: identify which of the five conditions fired (Cloud
Monitoring's incident detail names the specific condition), then follow
the matching row in `README.md`'s troubleshooting table.

---

## Building a dashboard

Not Terraform-managed (deliberately -- see `terraform/modules/monitoring/
main.tf`'s header comment for why). Build one manually in Cloud Monitoring
from these widgets: the five `logging.googleapis.com/user/audit_platform_*`
metrics as a stacked chart, `cloudfunctions.googleapis.com/function/
execution_count` split by `status`, and `pubsub.googleapis.com/
subscription/num_undelivered_messages` for the DLQ drain subscription.

## Re-running the Eventarc DLQ configuration

`scripts/configure_eventarc_dlq.ps1`/`.sh` must be re-run any time the
Cloud Function or its trigger is destroyed and recreated (a Terraform
`taint`/replace, a manual `gcloud functions delete`, etc.) -- the
Eventarc-managed subscription's dead-letter policy does not survive
recreation because the subscription itself doesn't. See the script's
header comment and `terraform/modules/pubsub/main.tf`'s header comment for
why this can't be fully Terraform-managed today.

## Rotating the WIF bootstrap identities

See `terraform/bootstrap/README.md`. Rotating is a `terraform apply` in
that directory with new variable values; nothing in the main stack needs
to change (it only references the deploy SA by email via a variable).
