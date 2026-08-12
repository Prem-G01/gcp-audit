"""Temporary, self-service alert muting, backed by Firestore.

A mute suppresses a rule's alert email (org-wide, or scoped to one
project) until it expires -- created via scripts/mute_alert.py, checked
by main.py before every Gmail send. Muted findings are still evaluated
and persisted to BigQuery with delivery_status="muted" -- muting hides
the email, never the record that something matched.

Firestore's own TTL policy (configured on the `expire_at` field via
Terraform) eventually deletes expired documents, but that deletion is a
best-effort background process that can lag by up to ~24 hours per GCP's
own documentation -- so correctness here never depends on document
existence. `is_muted` always compares `expire_at` against the current
time itself; TTL is purely a cleanup optimization for the collection,
never the source of truth for "is this currently muted".
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

_COLLECTION = "audit_platform_mutes"

_client_lock = threading.Lock()
_client: Any = None


def _get_client() -> Any:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                from google.cloud import firestore  # type: ignore[attr-defined]

                project = os.environ.get("FIRESTORE_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
                _client = firestore.Client(project=project) if project else firestore.Client()
    return _client


def _doc_id(rule_id: str, project_id: str | None) -> str:
    return f"rule_project::{rule_id}::{project_id}" if project_id else f"rule::{rule_id}"


def is_muted(rule_id: str, project_id: str | None) -> bool:
    """True iff an active (non-expired) mute covers this rule -- either
    org-wide, or scoped to this specific project. Never raises: a
    Firestore failure must never block an alert, matching this pipeline's
    resilience constraint for every other external dependency (CAI,
    BigQuery, Gemini).
    """
    try:
        client = _get_client()
        now = datetime.now(UTC)
        for doc_id in filter(None, [_doc_id(rule_id, None), _doc_id(rule_id, project_id) if project_id else None]):
            snapshot = client.collection(_COLLECTION).document(doc_id).get()
            if not snapshot.exists:
                continue
            data = snapshot.to_dict() or {}
            expire_at = data.get("expire_at")
            if isinstance(expire_at, datetime) and expire_at > now:
                return True
        return False
    except Exception as exc:  # external I/O boundary -- must never block the alert
        logger.warning("mute_check_failed", extra={"rule_id": rule_id, "project_id": project_id, "error": str(exc)})
        return False


@dataclass(frozen=True)
class MuteRecord:
    rule_id: str
    project_id: str | None
    reason: str
    muted_by: str
    created_at: datetime
    expire_at: datetime


def create_mute(
    *, rule_id: str, project_id: str | None, duration_hours: float, reason: str, muted_by: str
) -> MuteRecord:
    """Create (or replace) a mute. Raises on Firestore failure -- unlike
    `is_muted`, this is an explicit operator action (run via
    scripts/mute_alert.py), so a failure should surface loudly rather than
    be silently swallowed.
    """
    now = datetime.now(UTC)
    expire_at = now + timedelta(hours=duration_hours)
    record = MuteRecord(
        rule_id=rule_id, project_id=project_id, reason=reason, muted_by=muted_by, created_at=now, expire_at=expire_at
    )
    client = _get_client()
    client.collection(_COLLECTION).document(_doc_id(rule_id, project_id)).set(
        {
            "rule_id": record.rule_id,
            "project_id": record.project_id,
            "reason": record.reason,
            "muted_by": record.muted_by,
            "created_at": record.created_at,
            "expire_at": record.expire_at,
        }
    )
    return record


def clear_mute(*, rule_id: str, project_id: str | None) -> bool:
    """Delete a mute immediately (don't wait for it to expire). Returns
    False if no such mute existed.
    """
    client = _get_client()
    doc_ref = client.collection(_COLLECTION).document(_doc_id(rule_id, project_id))
    if not doc_ref.get().exists:
        return False
    doc_ref.delete()
    return True


def list_mutes() -> list[MuteRecord]:
    """All mute documents currently in Firestore, including ones that are
    logically expired but not yet TTL-deleted (list actual state; callers
    that only want active mutes should filter on `expire_at`).
    """
    client = _get_client()
    records = []
    for snapshot in client.collection(_COLLECTION).stream():
        data = snapshot.to_dict() or {}
        try:
            records.append(
                MuteRecord(
                    rule_id=data["rule_id"],
                    project_id=data.get("project_id"),
                    reason=data.get("reason", ""),
                    muted_by=data.get("muted_by", ""),
                    created_at=data["created_at"],
                    expire_at=data["expire_at"],
                )
            )
        except KeyError:
            logger.warning("mute_record_malformed", extra={"doc_id": snapshot.id})
    return records


__all__ = ["MuteRecord", "clear_mute", "create_mute", "is_muted", "list_mutes"]
