"""Cloud Function entrypoint: Pub/Sub audit log message -> Gmail alert email.

Pipeline: decode Pub/Sub message -> enrich (Cloud Asset Inventory) ->
evaluate_rules (config/rules.yaml) -> [per finding] conditional Gemini
analysis -> render + send via the existing Gmail client -> persist to
BigQuery -> dead-letter on permanent Gmail failure.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any
from urllib.parse import urlencode

import functions_framework
from cloudevents.http import CloudEvent

from src import muting
from src.analysis.gemini import analyze
from src.email_template import load_routing_config, render_alert
from src.enrichment.asset_inventory import enrich
from src.enrichment.data_volume import enrich_data_volume
from src.models import EnrichedEvent, Finding
from src.persistence.bigquery import Delivery, persist
from src.rules.engine import evaluate_rules, requires_ai_analysis, write_to_dlq
from src.rules.project_overrides import is_rule_muted_for_service_accounts, is_rule_suppressed_for_project
from src.senders.gmail_sender import GmailSendError, get_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _resolve_recipients(severity: str, principal_email: str | None) -> list[str]:
    routing_config = load_routing_config()
    if principal_email and principal_email.endswith(".iam.gserviceaccount.com"):
        sa_recipients = routing_config.get("service_account_notification_recipients")
        if sa_recipients:
            return list(sa_recipients)
    recipients_config = routing_config.get("recipients", {})
    recipients = recipients_config.get(severity) or recipients_config.get("default") or []
    return list(recipients)


def _mute_url(
    rule_id: str,
    project_id: str | None,
    *,
    principal_email: str | None = None,
    resource_name: str | None = None,
) -> str | None:
    """Build the "Mute this alert" link from the real rule_id/project_id and
    the deployed mute-web service's URL (MUTE_SERVICE_URL, set by Terraform
    -- see terraform/modules/mute_web). None when unset, so email_template.py
    simply omits the button rather than rendering a dead link.

    principal_email/resource_name (from the matched Finding, when known)
    let mute-web offer muting narrower than "this whole project" -- only
    included when project_id is also known, since neither means anything
    without it (see src/muting.py's module docstring).
    """
    base_url = os.environ.get("MUTE_SERVICE_URL")
    if not base_url:
        return None
    params = {"rule_id": rule_id}
    if project_id:
        params["project_id"] = project_id
        if principal_email:
            params["principal_email"] = principal_email
        if resource_name:
            params["resource_name"] = resource_name
    return f"{base_url.rstrip('/')}/mute?{urlencode(params)}"


def _decode_message(cloud_event: CloudEvent) -> dict[str, Any]:
    message = cloud_event.data["message"]
    raw = base64.b64decode(message["data"])
    payload: dict[str, Any] = json.loads(raw)
    return payload


def _handle_finding(finding: Finding, event: EnrichedEvent) -> None:
    log_context = {"rule_id": finding.rule_id, "raw_log_id": finding.raw_log_id}

    if muting.is_muted(
        finding.rule_id,
        event.project_id,
        principal_email=finding.principal_email,
        resource_name=finding.resource_name,
    ):
        # Muting hides the email, never the record that this matched --
        # still persisted, just with no recipients/message id. Checked
        # before the Gemini call too, so a muted finding doesn't spend
        # money on an analysis nobody will see.
        logger.info("alert_muted", extra=log_context)
        persist(
            finding,
            event,
            Delivery(
                recipients=[],
                gmail_message_id=None,
                delivery_status="muted",
                delivery_error=None,
            ),
        )
        return

    if is_rule_suppressed_for_project(finding.rule_id, event.project_id, event.asset_ancestors):
        # Same shape as the mute check above, but permanent and config-driven
        # (config/project_rules.yaml) rather than self-service/time-limited --
        # a distinct delivery_status ("suppressed") so BigQuery can tell the
        # two apart. Checked before Gemini for the same reason muting is.
        logger.info("alert_suppressed_by_project_rule", extra=log_context)
        persist(
            finding,
            event,
            Delivery(
                recipients=[],
                gmail_message_id=None,
                delivery_status="suppressed",
                delivery_error=None,
            ),
        )
        return

    if (
        finding.principal_email
        and finding.principal_email.endswith(".iam.gserviceaccount.com")
        and is_rule_muted_for_service_accounts(finding.rule_id)
    ):
        # Org-wide, rule-specific mute for service-account-triggered
        # findings only (config/project_rules.yaml's
        # service_account_muted_rules) -- a human triggering this same
        # rule still alerts normally, and an SA triggering any OTHER rule
        # still routes to the minimal SA notification list below. Built
        # for a high-frequency automated SA source overwhelming a rule
        # with no volume threshold. Checked before Gemini for the same
        # reason the checks above are.
        logger.info("alert_muted_for_service_account", extra=log_context)
        persist(
            finding,
            event,
            Delivery(
                recipients=[],
                gmail_message_id=None,
                delivery_status="suppressed_service_account",
                delivery_error=None,
            ),
        )
        return

    if requires_ai_analysis(finding.rule_id):
        finding = analyze(finding, event)

    recipients = _resolve_recipients(finding.severity, finding.principal_email)
    subject, html_body, text_body = render_alert(
        rule_id=finding.rule_id,
        severity=finding.severity,
        title=finding.title,
        fields=finding.fields,
        ai_analysis=finding.ai_analysis,
        console_url=finding.console_url,
        mute_url=_mute_url(
            finding.rule_id,
            event.project_id,
            principal_email=finding.principal_email,
            resource_name=finding.resource_name,
        ),
    )

    try:
        message_id = get_client().send(
            to=recipients,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            headers={
                "X-Audit-Rule-Id": finding.rule_id,
                "X-Audit-Severity": finding.severity,
                "Auto-Submitted": "auto-generated",
            },
        )
    except GmailSendError as exc:
        # Permanent configuration/delivery error: log, dead-letter, persist
        # the failed outcome, and return normally. Re-raising here would
        # hot-loop the Pub/Sub subscription against a misconfiguration that
        # a retry cannot fix.
        logger.error("gmail_alert_send_failed", extra={**log_context, "error": str(exc)})
        write_to_dlq(finding, reason=str(exc))
        persist(
            finding,
            event,
            Delivery(
                recipients=recipients,
                gmail_message_id=None,
                delivery_status="failed",
                delivery_error=str(exc),
            ),
        )
        return

    logger.info("gmail_alert_sent", extra={**log_context, "message_id": message_id})
    persist(
        finding,
        event,
        Delivery(
            recipients=recipients,
            gmail_message_id=message_id,
            delivery_status="sent",
            delivery_error=None,
        ),
    )


@functions_framework.cloud_event
def process_audit_log(cloud_event: CloudEvent) -> None:
    """Entry point: process one Pub/Sub-delivered audit log entry."""
    try:
        log_entry = _decode_message(cloud_event)
    except Exception as exc:
        # A malformed payload will never parse on retry either -- ack it.
        logger.error("payload_decode_failed", extra={"error": str(exc)})
        return

    # enrich(), enrich_data_volume(), and evaluate_rules() are all guaranteed
    # not to raise under normal operation (constraint 6 / the rules engine's
    # own per-rule guard); if any does, it's an unforeseen bug and should
    # propagate so Pub/Sub retries.
    event = enrich(log_entry)
    event = enrich_data_volume(event)
    findings = evaluate_rules(event)

    logger.info(
        "findings_evaluated", extra={"raw_log_id": event.raw_log_id, "finding_count": len(findings)}
    )

    succeeded = 0
    failed = 0
    for finding in findings:
        try:
            _handle_finding(finding, event)
            succeeded += 1
        except Exception:
            failed += 1
            logger.exception(
                "finding_processing_failed",
                extra={"rule_id": finding.rule_id, "raw_log_id": finding.raw_log_id},
            )

    logger.info(
        "audit_log_processed",
        extra={
            "raw_log_id": event.raw_log_id,
            "finding_count": len(findings),
            "succeeded": succeeded,
            "failed": failed,
        },
    )
