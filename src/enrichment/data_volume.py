"""Best-effort data-volume enrichment for the bulk_data_export_or_download rule.

Cloud Audit Logs never carry a bytes-transferred figure on the log entries
this rule matches: a GCS `storage.objects.get` entry fires on the API call,
not the data plane, and can't reflect a partial/range read; a BigQuery
`JobService.InsertJob` entry fires at job *submission*, before any byte count
exists. This module makes one best-effort external lookup per matching event
-- the object's current size (GCS) or the completed job's processed-bytes
statistic (BigQuery) -- and formats it for display. Every failure mode
(permission, timeout, not found, cross-project) degrades to leaving the size
fields unset rather than raising, exactly like
src/enrichment/asset_inventory.py's CAI lookup.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import replace

from google.cloud import bigquery, storage  # type: ignore[attr-defined]

from src.models import EnrichedEvent

logger = logging.getLogger(__name__)

_GCS_RESOURCE_RE = re.compile(r"^projects/[^/]+/buckets/([^/]+)/objects/(.+)$")
_BQ_JOB_RESOURCE_RE = re.compile(r"^projects/([^/]+)/jobs/([^/]+)$")

_storage_client: storage.Client | None = None
_storage_client_lock = threading.Lock()

_bigquery_client: bigquery.Client | None = None
_bigquery_client_lock = threading.Lock()


def _get_storage_client() -> storage.Client:
    global _storage_client
    if _storage_client is None:
        with _storage_client_lock:
            if _storage_client is None:
                _storage_client = storage.Client()
    return _storage_client


def _get_bigquery_client() -> bigquery.Client:
    global _bigquery_client
    if _bigquery_client is None:
        with _bigquery_client_lock:
            if _bigquery_client is None:
                _bigquery_client = bigquery.Client()
    return _bigquery_client


def _format_bytes(n: int) -> str:
    """Format a byte count as a human-readable string, e.g. 134_669_926 -> '128.4 MB'."""
    for unit, threshold in (("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if n >= threshold:
            return f"{n / threshold:.1f} {unit}"
    return f"{n} B"


def _lookup_gcs_object_size(bucket: str, object_name: str) -> int | None:
    """Current size of a GCS object in bytes, or None if unknown. Only raises
    on a genuine bug -- callers must catch external I/O errors themselves.
    """
    blob = _get_storage_client().bucket(bucket).blob(object_name)
    blob.reload()
    size = blob.size
    return int(size) if size is not None else None


def _lookup_bq_job_bytes(project_id: str, job_id: str) -> int | None:
    """Processed-bytes statistic for a completed BigQuery job, or None if
    unavailable. Only raises on a genuine bug -- callers must catch external
    I/O errors themselves.
    """
    job = _get_bigquery_client().get_job(job_id, project=project_id)
    total = getattr(job, "total_bytes_processed", None)
    if isinstance(total, int):
        return total
    # Fallback for job types/API versions where the client library doesn't
    # expose total_bytes_processed as an attribute -- read the raw job
    # resource directly rather than fabricating a number.
    stats = getattr(job, "_properties", {}).get("statistics", {})
    raw_total = stats.get("totalBytesProcessed") or stats.get("query", {}).get("totalBytesProcessed")
    return int(raw_total) if raw_total is not None else None


def _is_gcs_download(event: EnrichedEvent) -> bool:
    return event.method_name == "storage.objects.get"


def _is_bq_extract(event: EnrichedEvent) -> bool:
    if not event.method_name or "JobService" not in event.method_name:
        return False
    return "EXTRACT" in str(event.raw.get("protoPayload", {}).get("metadata", {}))


def enrich_data_volume(event: EnrichedEvent) -> EnrichedEvent:
    """Best-effort augment `event` with data_size_bytes/data_size_display. Never raises."""
    size: int | None = None

    if _is_gcs_download(event):
        match = _GCS_RESOURCE_RE.match(event.resource_name or "")
        if match:
            bucket, object_name = match.group(1), match.group(2)
            try:
                size = _lookup_gcs_object_size(bucket, object_name)
            except Exception as exc:  # external I/O boundary -- must never block the alert
                logger.warning(
                    "data_volume_lookup_failed",
                    extra={"resource_name": event.resource_name, "raw_log_id": event.raw_log_id, "error": str(exc)},
                )
    elif _is_bq_extract(event):
        match = _BQ_JOB_RESOURCE_RE.match(event.resource_name or "")
        if match:
            project_id, job_id = match.group(1), match.group(2)
            try:
                size = _lookup_bq_job_bytes(project_id, job_id)
            except Exception as exc:  # external I/O boundary -- must never block the alert
                logger.warning(
                    "data_volume_lookup_failed",
                    extra={"resource_name": event.resource_name, "raw_log_id": event.raw_log_id, "error": str(exc)},
                )
    else:
        return event

    if size is None:
        return event

    return replace(event, data_size_bytes=size, data_size_display=_format_bytes(size))


__all__ = ["enrich_data_volume"]
