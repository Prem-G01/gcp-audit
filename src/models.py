"""Shared data contracts for the audit pipeline.

Every pipeline stage (enrichment, rule evaluation, analysis, persistence,
delivery) passes these frozen dataclasses between stages -- never raw dicts.
`EnrichedEvent.from_log_entry` is deliberately tolerant of missing/malformed
keys: real Cloud Audit Log entries have inconsistent shapes across services,
and a KeyError here would kill the whole Pub/Sub message.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["EnrichedEvent", "Finding", "replace"]

_FRACTIONAL_SECONDS_RE = re.compile(r"^(.*?)(\.\d+)?([+-]\d{2}:\d{2})$")


def _dig(source: Any, *keys: str, default: Any = None) -> Any:
    """Tolerant nested-mapping lookup: `_dig(d, "a", "b")` == `d.get("a", {}).get("b")`."""
    current = source
    for key in keys:
        if not isinstance(current, Mapping):
            return default
        current = current.get(key, default)
    return current


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse a Cloud Logging RFC3339 timestamp, tolerating >6 fractional-second digits."""
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    if "+" not in text[10:] and "-" not in text[10:]:
        text += "+00:00"
    match = _FRACTIONAL_SECONDS_RE.match(text)
    if match and match.group(2):
        fractional = match.group(2)[1:][:6].ljust(6, "0")
        text = f"{match.group(1)}.{fractional}{match.group(3)}"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        logger.warning("timestamp_parse_failed", extra={"value": value})
        return None


@dataclass(frozen=True)
class EnrichedEvent:
    """A parsed audit log entry, optionally augmented with Cloud Asset Inventory data."""

    method_name: str | None = None
    principal_email: str | None = None
    resource_name: str | None = None
    resource_type: str | None = None
    project_id: str | None = None
    severity: str | None = None
    event_timestamp: datetime | None = None
    raw_log_id: str | None = None
    request_metadata: dict[str, Any] = field(default_factory=dict)
    asset_labels: dict[str, str] = field(default_factory=dict)
    asset_ancestors: list[str] = field(default_factory=list)
    enrichment_ok: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_log_entry(cls, payload: Mapping[str, Any]) -> EnrichedEvent:
        """Parse a raw Cloud Logging audit-log-entry dict. Never raises."""
        if not isinstance(payload, Mapping):
            logger.warning("log_entry_not_a_mapping", extra={"type": type(payload).__name__})
            return cls(raw={})

        proto_payload = _dig(payload, "protoPayload", default={}) or {}
        resource = _dig(payload, "resource", default={}) or {}
        resource_labels = _dig(resource, "labels", default={}) or {}
        auth_info = _dig(proto_payload, "authenticationInfo", default={}) or {}
        request_metadata_raw = _dig(proto_payload, "requestMetadata", default={}) or {}

        return cls(
            method_name=proto_payload.get("methodName"),
            principal_email=auth_info.get("principalEmail"),
            resource_name=proto_payload.get("resourceName"),
            resource_type=resource.get("type"),
            project_id=resource_labels.get("project_id") or resource_labels.get("project"),
            severity=payload.get("severity"),
            event_timestamp=_parse_timestamp(payload.get("timestamp")),
            raw_log_id=payload.get("insertId"),
            request_metadata={
                "caller_ip": request_metadata_raw.get("callerIp"),
                "user_agent": request_metadata_raw.get("callerSuppliedUserAgent"),
            },
            raw=dict(payload),
        )


@dataclass(frozen=True)
class Finding:
    """A single matched rule against a single event, ready for analysis/delivery/persistence."""

    rule_id: str
    severity: str
    title: str
    fields: Mapping[str, Any]
    ai_analysis: str | None
    console_url: str | None
    resource_name: str | None
    principal_email: str | None
    method_name: str | None
    event_timestamp: datetime | None
    raw_log_id: str | None
