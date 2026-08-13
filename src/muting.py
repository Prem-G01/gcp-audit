"""Temporary, self-service alert muting, backed by Firestore.

A mute suppresses a rule's alert email -- org-wide, scoped to one
project, or scoped further to one principal or one resource within that
project -- until it expires. Created via scripts/mute_alert.py or the
mute-web button, checked by main.py before every Gmail send. Muted
findings are still evaluated and persisted to BigQuery with
delivery_status="muted" -- muting hides the email, never the record that
something matched.

Narrowing is strictly one level at a time: a mute is either org-wide,
project-wide, or project+principal, or project+resource -- never
project+principal+resource together (create_mute takes both keyword-only
so a caller can pass either, but is_muted checks each independently
against the finding's own principal_email/resource_name, so an active
mute at ANY of the four levels suppresses the email).

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
                from google.cloud import firestore

                project = os.environ.get("FIRESTORE_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
                _client = firestore.Client(project=project) if project else firestore.Client()
    return _client


def _doc_id(
    rule_id: str,
    project_id: str | None,
    *,
    principal_email: str | None = None,
    resource_name: str | None = None,
) -> str:
    """principal_email/resource_name only narrow the id when project_id is
    also known -- without a project there's no meaningful "this principal
    within this project" scope, so both are silently ignored in that case
    (falls through to the project/org-wide id, same as omitting them).
    """
    if project_id and principal_email:
        return f"rule_project_principal::{rule_id}::{project_id}::{principal_email}"
    if project_id and resource_name:
        return f"rule_project_resource::{rule_id}::{project_id}::{resource_name}"
    if project_id:
        return f"rule_project::{rule_id}::{project_id}"
    return f"rule::{rule_id}"


def is_muted(
    rule_id: str,
    project_id: str | None,
    *,
    principal_email: str | None = None,
    resource_name: str | None = None,
) -> bool:
    """True iff an active (non-expired) mute covers this rule -- org-wide,
    project-wide, or scoped to this specific principal or resource within
    the project. Checks every applicable level and returns True on the
    first active match. Never raises: a Firestore failure must never block
    an alert, matching this pipeline's resilience constraint for every
    other external dependency (CAI, BigQuery, Gemini).
    """
    try:
        client = _get_client()
        now = datetime.now(UTC)
        doc_ids = [_doc_id(rule_id, None)]
        if project_id:
            doc_ids.append(_doc_id(rule_id, project_id))
            if principal_email:
                doc_ids.append(_doc_id(rule_id, project_id, principal_email=principal_email))
            if resource_name:
                doc_ids.append(_doc_id(rule_id, project_id, resource_name=resource_name))
        for doc_id in doc_ids:
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
    principal_email: str | None = None
    resource_name: str | None = None


def create_mute(
    *,
    rule_id: str,
    project_id: str | None,
    duration_hours: float,
    reason: str,
    muted_by: str,
    principal_email: str | None = None,
    resource_name: str | None = None,
) -> MuteRecord:
    """Create (or replace) a mute. Raises on Firestore failure -- unlike
    `is_muted`, this is an explicit operator action (run via
    scripts/mute_alert.py or the mute-web button), so a failure should
    surface loudly rather than be silently swallowed.

    Pass at most one of principal_email/resource_name -- see the module
    docstring. If both are given, _doc_id prioritizes principal_email;
    callers (mute_web/app.py) never offer both as simultaneous choices, so
    this ambiguity is unreachable in practice, not something worth a
    ValueError over.
    """
    now = datetime.now(UTC)
    expire_at = now + timedelta(hours=duration_hours)
    record = MuteRecord(
        rule_id=rule_id,
        project_id=project_id,
        reason=reason,
        muted_by=muted_by,
        created_at=now,
        expire_at=expire_at,
        principal_email=principal_email if project_id else None,
        resource_name=resource_name if project_id else None,
    )
    client = _get_client()
    doc_id = _doc_id(rule_id, project_id, principal_email=principal_email, resource_name=resource_name)
    client.collection(_COLLECTION).document(doc_id).set(
        {
            "rule_id": record.rule_id,
            "project_id": record.project_id,
            "reason": record.reason,
            "muted_by": record.muted_by,
            "created_at": record.created_at,
            "expire_at": record.expire_at,
            "principal_email": record.principal_email,
            "resource_name": record.resource_name,
        }
    )
    return record


def clear_mute(
    *,
    rule_id: str,
    project_id: str | None,
    principal_email: str | None = None,
    resource_name: str | None = None,
) -> bool:
    """Delete a mute immediately (don't wait for it to expire). Returns
    False if no such mute existed.
    """
    client = _get_client()
    doc_id = _doc_id(rule_id, project_id, principal_email=principal_email, resource_name=resource_name)
    doc_ref = client.collection(_COLLECTION).document(doc_id)
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
                    principal_email=data.get("principal_email"),
                    resource_name=data.get("resource_name"),
                )
            )
        except KeyError:
            logger.warning("mute_record_malformed", extra={"doc_id": snapshot.id})
    return records


__all__ = ["MuteRecord", "clear_mute", "create_mute", "is_muted", "list_mutes"]
