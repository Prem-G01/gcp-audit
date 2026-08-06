"""Declarative rule loading, validation, and evaluation, plus the DLQ sink.

Rules live entirely in config/rules.yaml -- this module contains the fixed
condition-tree grammar and closed operator set that YAML rules are matched
against, but zero rule-specific logic. The rule file is loaded and validated
once, at import time, so a malformed file fails loudly at Cloud Function cold
start rather than silently at match time.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

from src.email_template import load_routing_config
from src.models import EnrichedEvent, Finding

logger = logging.getLogger(__name__)

RULES_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "rules.yaml"

STRUCTURAL_KEYS = {"all_of", "any_of", "not"}
LEAF_KEYS = {"field", "op", "value"}
ALLOWED_RULE_KEYS = {
    "id",
    "title",
    "description",
    "severity",
    "enabled",
    "ai_analysis",
    "console_url_template",
    "match",
    "fields",
}
ALLOWED_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "in",
    "not_in",
    "regex",
    "exists",
    "not_exists",
}
NO_VALUE_OPERATORS = {"exists", "not_exists"}
LIST_VALUE_OPERATORS = {"in", "not_in"}
ALLOWED_URL_PLACEHOLDERS = {"project_id", "resource_name"}
MAX_CONTAINS_DEPTH = 25
MAX_REGEX_INPUT_LENGTH = 4096

_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class RuleConfigError(ValueError):
    """Raised when config/rules.yaml is structurally or semantically invalid."""


@dataclass(frozen=True)
class _Condition:
    kind: str  # "all_of" | "any_of" | "not" | "leaf"
    children: tuple[_Condition, ...] = ()
    field_path: str | None = None
    op: str | None = None
    value: Any = None
    compiled_regex: re.Pattern[str] | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: str
    enabled: bool
    ai_analysis: bool
    console_url_template: str | None
    match: _Condition
    fields: Mapping[str, str]


def _compile_leaf(node: dict[str, Any], rule_id: str) -> _Condition:
    unknown = set(node) - LEAF_KEYS
    if unknown:
        raise RuleConfigError(f"rule {rule_id}: unknown condition key(s) {sorted(unknown)}")

    field_path = node.get("field")
    if not field_path or not isinstance(field_path, str):
        raise RuleConfigError(f"rule {rule_id}: leaf condition missing required 'field'")

    op = node.get("op")
    if op not in ALLOWED_OPERATORS:
        raise RuleConfigError(
            f"rule {rule_id}: unknown operator {op!r} (allowed: {sorted(ALLOWED_OPERATORS)})"
        )

    if op in NO_VALUE_OPERATORS:
        return _Condition(kind="leaf", field_path=field_path, op=op)

    if "value" not in node:
        raise RuleConfigError(f"rule {rule_id}: operator {op!r} requires a 'value'")
    value = node["value"]

    if op in LIST_VALUE_OPERATORS and not isinstance(value, list):
        raise RuleConfigError(f"rule {rule_id}: operator {op!r} requires a list 'value'")

    compiled_regex = None
    if op == "regex":
        if not isinstance(value, str):
            raise RuleConfigError(f"rule {rule_id}: operator 'regex' requires a string 'value'")
        try:
            compiled_regex = re.compile(value)
        except re.error as exc:
            raise RuleConfigError(f"rule {rule_id}: invalid regex {value!r}: {exc}") from exc

    return _Condition(kind="leaf", field_path=field_path, op=op, value=value, compiled_regex=compiled_regex)


def _compile_condition(node: Any, rule_id: str) -> _Condition:
    if not isinstance(node, dict):
        raise RuleConfigError(f"rule {rule_id}: condition must be a mapping, got {type(node).__name__}")

    keys = set(node)
    structural = keys & STRUCTURAL_KEYS
    if len(structural) > 1:
        raise RuleConfigError(f"rule {rule_id}: condition has multiple structural keys {sorted(structural)}")

    if structural:
        if keys - structural:
            raise RuleConfigError(
                f"rule {rule_id}: condition mixes structural key with other keys {sorted(keys)}"
            )
        kind = next(iter(structural))
        if kind == "not":
            return _Condition(kind="not", children=(_compile_condition(node["not"], rule_id),))
        children_raw = node[kind]
        if not isinstance(children_raw, list) or not children_raw:
            raise RuleConfigError(f"rule {rule_id}: '{kind}' must be a non-empty list")
        children = tuple(_compile_condition(child, rule_id) for child in children_raw)
        return _Condition(kind=kind, children=children)

    return _compile_leaf(node, rule_id)


def _validate_console_url_template(template: str, rule_id: str) -> None:
    for match in _PLACEHOLDER_RE.finditer(template):
        name = match.group(1)
        if name not in ALLOWED_URL_PLACEHOLDERS:
            raise RuleConfigError(
                f"rule {rule_id}: console_url_template has unknown placeholder '{{{name}}}' "
                f"(allowed: {sorted(ALLOWED_URL_PLACEHOLDERS)})"
            )


def _compile_rule(raw_rule: Any, index: int, defaults: dict[str, Any], allowed_severities: set[str]) -> Rule:
    label = raw_rule.get("id") if isinstance(raw_rule, dict) else None
    label = label if isinstance(label, str) and label else f"<rule at index {index}>"

    if not isinstance(raw_rule, dict):
        raise RuleConfigError(f"rule {label}: must be a mapping")

    unknown_keys = set(raw_rule) - ALLOWED_RULE_KEYS
    if unknown_keys:
        raise RuleConfigError(f"rule {label}: unknown key(s) {sorted(unknown_keys)}")

    rule_id = raw_rule.get("id")
    if not rule_id or not isinstance(rule_id, str):
        raise RuleConfigError(f"rule {label}: missing required field 'id'")

    title = raw_rule.get("title")
    if not title or not isinstance(title, str):
        raise RuleConfigError(f"rule {rule_id}: missing required field 'title'")

    severity = raw_rule.get("severity", defaults.get("severity"))
    if severity not in allowed_severities:
        raise RuleConfigError(
            f"rule {rule_id}: invalid severity {severity!r} (must be one of {sorted(allowed_severities)})"
        )

    match_raw = raw_rule.get("match")
    if match_raw is None:
        raise RuleConfigError(f"rule {rule_id}: missing required field 'match'")
    condition = _compile_condition(match_raw, rule_id)

    fields_raw = raw_rule.get("fields") or {}
    if not isinstance(fields_raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in fields_raw.items()
    ):
        raise RuleConfigError(f"rule {rule_id}: 'fields' must be a mapping of string -> string")

    console_url_template = raw_rule.get("console_url_template")
    if console_url_template is not None:
        if not isinstance(console_url_template, str):
            raise RuleConfigError(f"rule {rule_id}: 'console_url_template' must be a string")
        _validate_console_url_template(console_url_template, rule_id)

    return Rule(
        id=rule_id,
        title=title,
        description=str(raw_rule.get("description", "")),
        severity=severity,
        enabled=bool(raw_rule.get("enabled", defaults.get("enabled", True))),
        ai_analysis=bool(raw_rule.get("ai_analysis", defaults.get("ai_analysis", False))),
        console_url_template=console_url_template,
        match=condition,
        fields=fields_raw,
    )


def load_rules(path: Path | None = None) -> list[Rule]:
    """Load, validate, and compile config/rules.yaml. Raises RuleConfigError on any problem."""
    target = path if path is not None else RULES_CONFIG_PATH
    with target.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, dict):
        raise RuleConfigError("rules.yaml: top-level document must be a mapping")

    if raw.get("version") != 1:
        raise RuleConfigError(f"rules.yaml: unsupported or missing 'version' (expected 1, got {raw.get('version')!r})")

    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise RuleConfigError("rules.yaml: 'defaults' must be a mapping")

    raw_rules = raw.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleConfigError("rules.yaml: 'rules' must be a non-empty list")

    allowed_severities = set(load_routing_config().get("severity_styles", {}))
    if not allowed_severities:
        raise RuleConfigError("rules.yaml: no severities found in config/routing.yaml's severity_styles")

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        rule = _compile_rule(raw_rule, index, defaults, allowed_severities)
        if rule.id in seen_ids:
            raise RuleConfigError(f"rule {rule.id}: duplicate rule id")
        seen_ids.add(rule.id)
        rules.append(rule)

    return rules


# Fail loudly at cold start on a malformed shipped config, per the platform's
# operational requirement -- not a silent runtime surprise at match time.
_RULES: list[Rule] = load_rules()
_RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in _RULES}


def requires_ai_analysis(rule_id: str) -> bool:
    """Whether the rule that produced this finding requested Gemini analysis."""
    rule = _RULES_BY_ID.get(rule_id)
    return bool(rule and rule.ai_analysis)


def _resolve_path(event: EnrichedEvent, path: str) -> tuple[Any, bool]:
    """Resolve a dotted path against an EnrichedEvent. Returns (value, found)."""
    first, *rest = path.split(".")
    if not hasattr(event, first):
        return None, False
    value: Any = getattr(event, first)
    for part in rest:
        if isinstance(value, Mapping):
            if part not in value:
                return None, False
            value = value[part]
        elif isinstance(value, list | tuple) and part.lstrip("-").isdigit():
            index = int(part)
            if -len(value) <= index < len(value):
                value = value[index]
            else:
                return None, False
        else:
            return None, False
    return value, True


def _contains_value(haystack: Any, needle: str, depth: int = 0) -> bool:
    """Recursively search VALUES (never dict keys) for a substring match."""
    if depth > MAX_CONTAINS_DEPTH:
        return False
    if isinstance(haystack, str):
        return needle in haystack
    if isinstance(haystack, Mapping):
        return any(_contains_value(v, needle, depth + 1) for v in haystack.values())
    if isinstance(haystack, list | tuple):
        return any(_contains_value(v, needle, depth + 1) for v in haystack)
    if haystack is None:
        return False
    return needle in str(haystack)


def _values_equal(value: Any, expected: Any) -> bool:
    """Direct equality, plus a narrow numeric-string and bool-string coercion fallback."""
    if value == expected:
        return True
    if value is None or expected is None:
        return False
    if isinstance(value, dict | list) or isinstance(expected, dict | list):
        return False
    if isinstance(value, bool) or isinstance(expected, bool):
        bool_side, other = (value, expected) if isinstance(value, bool) else (expected, value)
        if isinstance(other, str) and other.lower() in ("true", "false"):
            return bool_side == (other.lower() == "true")
        return False
    try:
        if isinstance(value, str) != isinstance(expected, str):
            return float(value) == float(expected)
    except (TypeError, ValueError):
        return False
    return False


def _match_leaf(event: EnrichedEvent, cond: _Condition) -> bool:
    assert cond.field_path is not None and cond.op is not None
    value, found = _resolve_path(event, cond.field_path)

    if cond.op == "exists":
        return found
    if cond.op == "not_exists":
        return not found
    if not found:
        return False

    if cond.op == "equals":
        return _values_equal(value, cond.value)
    if cond.op == "not_equals":
        return not _values_equal(value, cond.value)
    if cond.op == "contains":
        return _contains_value(value, str(cond.value))
    if cond.op == "not_contains":
        return not _contains_value(value, str(cond.value))
    if cond.op == "starts_with":
        return str(value).startswith(str(cond.value))
    if cond.op == "ends_with":
        return str(value).endswith(str(cond.value))
    if cond.op in ("in", "not_in"):
        matched = any(_values_equal(value, candidate) for candidate in cond.value)
        return matched if cond.op == "in" else not matched
    if cond.op == "regex":
        assert cond.compiled_regex is not None
        text = str(value)[:MAX_REGEX_INPUT_LENGTH]
        return bool(cond.compiled_regex.search(text))

    raise AssertionError(f"unhandled operator {cond.op!r}")  # unreachable: load-time validation covers this


def _match(event: EnrichedEvent, cond: _Condition) -> bool:
    if cond.kind == "all_of":
        return all(_match(event, child) for child in cond.children)
    if cond.kind == "any_of":
        return any(_match(event, child) for child in cond.children)
    if cond.kind == "not":
        return not _match(event, cond.children[0])
    return _match_leaf(event, cond)


def _render_console_url(template: str, event: EnrichedEvent) -> str:
    rendered = template.replace("{project_id}", quote(str(event.project_id or ""), safe=""))
    return rendered.replace("{resource_name}", quote(str(event.resource_name or ""), safe=""))


def evaluate_rules(event: EnrichedEvent) -> list[Finding]:
    """Evaluate every enabled rule against `event`. Pure, never raises."""
    findings: list[Finding] = []

    for rule in _RULES:
        if not rule.enabled:
            continue
        try:
            matched = _match(event, rule.match)
        except Exception:
            logger.exception(
                "rule_evaluation_error", extra={"rule_id": rule.id, "raw_log_id": event.raw_log_id}
            )
            continue
        if not matched:
            continue

        fields: dict[str, Any] = {}
        for label, path in rule.fields.items():
            value, found = _resolve_path(event, path)
            if found:
                fields[label] = value

        console_url = _render_console_url(rule.console_url_template, event) if rule.console_url_template else None

        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                fields=fields,
                ai_analysis=None,
                console_url=console_url,
                resource_name=event.resource_name,
                principal_email=event.principal_email,
                method_name=event.method_name,
                event_timestamp=event.event_timestamp,
                raw_log_id=event.raw_log_id,
            )
        )
        logger.info(
            "rule_matched", extra={"rule_id": rule.id, "raw_log_id": event.raw_log_id, "severity": rule.severity}
        )

    return findings


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    payload = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "fields": dict(finding.fields),
        "ai_analysis": finding.ai_analysis,
        "console_url": finding.console_url,
        "resource_name": finding.resource_name,
        "principal_email": finding.principal_email,
        "method_name": finding.method_name,
        "event_timestamp": finding.event_timestamp.isoformat() if finding.event_timestamp else None,
        "raw_log_id": finding.raw_log_id,
    }
    result: dict[str, Any] = json.loads(json.dumps(payload, default=str))
    return result


_publisher_lock = threading.Lock()
_publisher_client: Any = None


def _get_publisher() -> Any:
    global _publisher_client
    if _publisher_client is None:
        with _publisher_lock:
            if _publisher_client is None:
                from google.cloud import pubsub_v1  # type: ignore[attr-defined]

                _publisher_client = pubsub_v1.PublisherClient()
    return _publisher_client


def write_to_dlq(finding: Finding, reason: str) -> None:
    """Publish an undeliverable finding to the dead-letter Pub/Sub topic. Never raises.

    Falls back to an ERROR-level structured log (recoverable from Cloud
    Logging) if DLQ_TOPIC is unset or the publish itself fails.
    """
    serialized = _serialize_finding(finding)
    dlq_topic = os.environ.get("DLQ_TOPIC")
    if not dlq_topic:
        logger.error("dlq_topic_not_configured", extra={"reason": reason, "finding": serialized})
        return

    try:
        project = os.environ.get("DLQ_PROJECT") or os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not project:
            raise RuntimeError(
                "no GCP project resolvable for DLQ publish (set DLQ_PROJECT or GOOGLE_CLOUD_PROJECT)"
            )
        publisher = _get_publisher()
        topic_path = publisher.topic_path(project, dlq_topic)
        payload = {
            "reason": reason,
            "dead_lettered_at": datetime.now(UTC).isoformat(),
            "finding": serialized,
        }
        future = publisher.publish(topic_path, json.dumps(payload).encode("utf-8"))
        future.result(timeout=10)
    except Exception as exc:  # external I/O boundary -- must never raise (constraint 6)
        logger.error(
            "dlq_write_failed", extra={"reason": reason, "error": str(exc), "finding": serialized}
        )
        return

    logger.info("dlq_write_succeeded", extra={"rule_id": finding.rule_id, "raw_log_id": finding.raw_log_id})


__all__ = [
    "Rule",
    "RuleConfigError",
    "evaluate_rules",
    "load_rules",
    "requires_ai_analysis",
    "write_to_dlq",
]
