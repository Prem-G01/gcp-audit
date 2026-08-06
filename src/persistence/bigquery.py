"""BigQuery persistence for delivered (and failed-to-deliver) alert findings.

Every insert is via `insert_rows_json` against a fixed schema -- never
string-built SQL. Persistence runs *after* the Gmail send has already been
attempted, so a BigQuery failure here must never surface as a pipeline
failure: it's logged at ERROR and swallowed.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import UTC, datetime
from typing import Any, TypedDict

from google.cloud import bigquery

from src.models import EnrichedEvent, Finding

logger = logging.getLogger(__name__)

_DEFAULT_DATASET = "audit_platform"
_DEFAULT_TABLE = "alert_events"

# Kept as a Python constant for reference / for provisioning the table via
# the client library if ever needed; the authoritative provisioning path is
# terraform/bigquery.tf.
SCHEMA: list[bigquery.SchemaField] = [
    bigquery.SchemaField("event_timestamp", "TIMESTAMP", mode="NULLABLE"),
    bigquery.SchemaField("ingest_timestamp", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("rule_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("title", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("project_id", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("resource_name", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("resource_type", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("principal_email", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("method_name", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("caller_ip", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("ai_analysis", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("enrichment_ok", "BOOL", mode="REQUIRED"),
    bigquery.SchemaField("recipients", "STRING", mode="REPEATED"),
    bigquery.SchemaField("gmail_message_id", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("delivery_status", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("delivery_error", "STRING", mode="NULLABLE"),
    bigquery.SchemaField("raw_log_id", "STRING", mode="NULLABLE"),
]


class Delivery(TypedDict):
    recipients: list[str]
    gmail_message_id: str | None
    delivery_status: str
    delivery_error: str | None


_client_lock = threading.Lock()
_client: bigquery.Client | None = None


def _get_client() -> bigquery.Client:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = bigquery.Client(project=os.environ.get("BQ_PROJECT") or None)
    return _client


def _table_id() -> str:
    client = _get_client()
    project = client.project
    dataset = os.environ.get("BQ_DATASET", _DEFAULT_DATASET)
    table = os.environ.get("BQ_TABLE", _DEFAULT_TABLE)
    return f"{project}.{dataset}.{table}"


def _build_row(finding: Finding, event: EnrichedEvent, delivery: Delivery) -> dict[str, Any]:
    return {
        "event_timestamp": finding.event_timestamp.isoformat() if finding.event_timestamp else None,
        "ingest_timestamp": datetime.now(UTC).isoformat(),
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "project_id": event.project_id,
        "resource_name": finding.resource_name,
        "resource_type": event.resource_type,
        "principal_email": finding.principal_email,
        "method_name": finding.method_name,
        "caller_ip": event.request_metadata.get("caller_ip"),
        "ai_analysis": finding.ai_analysis,
        "enrichment_ok": event.enrichment_ok,
        "recipients": list(delivery["recipients"]),
        "gmail_message_id": delivery["gmail_message_id"],
        "delivery_status": delivery["delivery_status"],
        "delivery_error": delivery["delivery_error"],
        "raw_log_id": finding.raw_log_id,
    }


def persist(finding: Finding, event: EnrichedEvent, delivery: Delivery) -> None:
    """Insert one alert-event row into BigQuery. Never raises."""
    try:
        table_id = _table_id()
        row = _build_row(finding, event, delivery)
        errors = _get_client().insert_rows_json(table_id, [row])
        if errors:
            logger.error(
                "bigquery_insert_errors",
                extra={"rule_id": finding.rule_id, "raw_log_id": finding.raw_log_id, "errors": errors},
            )
    except Exception as exc:  # external I/O boundary -- must never block the alert (constraint 6)
        logger.error(
            "bigquery_persist_failed",
            extra={"rule_id": finding.rule_id, "raw_log_id": finding.raw_log_id, "error": str(exc)},
        )


__all__ = ["Delivery", "SCHEMA", "persist"]
