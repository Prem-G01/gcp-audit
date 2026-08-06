"""Cloud Asset Inventory enrichment for parsed audit log entries.

Looks up the resource named in the audit log entry to attach its current
asset type, labels, and ancestor chain (folders/organization). This is a
best-effort augmentation: any Cloud Asset Inventory failure (permission,
timeout, resource not found, transient error) must not prevent the alert
email from being sent, so every failure mode here degrades to
`enrichment_ok=False` on the un-augmented event rather than raising.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, replace
from typing import Any

from google.cloud import asset_v1

from src.models import EnrichedEvent

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_TTL_SECONDS = 300.0
_DEFAULT_TIMEOUT_SECONDS = 10.0


def _cache_ttl_seconds() -> float:
    return float(os.environ.get("CAI_CACHE_TTL_SECONDS", _DEFAULT_CACHE_TTL_SECONDS))


def _timeout_seconds() -> float:
    return float(os.environ.get("CAI_TIMEOUT_SECONDS", _DEFAULT_TIMEOUT_SECONDS))


@dataclass(frozen=True)
class _CacheEntry:
    labels: dict[str, str]
    ancestors: list[str]
    expires_at: float


_cache: dict[str, _CacheEntry] = {}
_cache_lock = threading.Lock()

_asset_client: asset_v1.AssetServiceClient | None = None
_asset_client_lock = threading.Lock()


def _get_asset_client() -> asset_v1.AssetServiceClient:
    global _asset_client
    if _asset_client is None:
        with _asset_client_lock:
            if _asset_client is None:
                _asset_client = asset_v1.AssetServiceClient()
    return _asset_client


def _cache_get(resource_name: str) -> _CacheEntry | None:
    with _cache_lock:
        entry = _cache.get(resource_name)
        if entry is None:
            return None
        if entry.expires_at <= time.time():
            del _cache[resource_name]
            return None
        return entry


def _cache_put(resource_name: str, labels: dict[str, str], ancestors: list[str]) -> None:
    with _cache_lock:
        _cache[resource_name] = _CacheEntry(
            labels=labels, ancestors=ancestors, expires_at=time.time() + _cache_ttl_seconds()
        )


def _search_resource(project_id: str, resource_name: str) -> Any | None:
    """Look up a single resource's current state via CAI search. Returns the first match, if any."""
    client = _get_asset_client()
    request = {
        "scope": f"projects/{project_id}",
        "query": f'name="{resource_name}"',
        "page_size": 1,
    }
    for result in client.search_all_resources(request=request, timeout=_timeout_seconds()):
        return result
    return None


def enrich(log_entry: dict[str, Any]) -> EnrichedEvent:
    """Parse a raw audit log entry and best-effort augment it with CAI data. Never raises."""
    event = EnrichedEvent.from_log_entry(log_entry)

    if not event.resource_name or not event.project_id:
        return event

    cached = _cache_get(event.resource_name)
    if cached is not None:
        return replace(event, asset_labels=cached.labels, asset_ancestors=cached.ancestors, enrichment_ok=True)

    try:
        result = _search_resource(event.project_id, event.resource_name)
    except Exception as exc:  # external I/O boundary -- must never block the alert (constraint 6)
        logger.warning(
            "cai_enrichment_failed",
            extra={"resource_name": event.resource_name, "raw_log_id": event.raw_log_id, "error": str(exc)},
        )
        return replace(event, enrichment_ok=False)

    if result is None:
        logger.info(
            "cai_resource_not_found",
            extra={"resource_name": event.resource_name, "raw_log_id": event.raw_log_id},
        )
        return event

    labels = dict(result.labels) if result.labels else {}
    ancestors = list(result.folders) + ([result.organization] if result.organization else [])
    _cache_put(event.resource_name, labels, ancestors)

    return replace(event, asset_labels=labels, asset_ancestors=ancestors, enrichment_ok=True)


__all__ = ["enrich"]
