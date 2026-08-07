"""Renders Gmail alert emails (subject, HTML body, plain-text body) for findings.

All layout uses inline CSS and <table> markup only (no <style> blocks, no
flexbox/grid) for Outlook/Gmail rendering compatibility. Every value that
originates from an audit log entry is attacker-influenced and is passed
through html.escape() before reaching the HTML template.
"""

from __future__ import annotations

import html
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "routing.yaml"

_FALLBACK_ACCENT = "#6b7280"
_FALLBACK_TINT = "#f3f4f6"


@lru_cache(maxsize=8)
def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data: dict[str, Any] = yaml.safe_load(handle) or {}
    return data


def load_routing_config(path: Path | None = None) -> dict[str, Any]:
    """Load config/routing.yaml (severity_styles + recipients), cached by path."""
    return _load_yaml(path if path is not None else CONFIG_PATH)


def _severity_style(severity: str, routing_config: Mapping[str, Any]) -> tuple[str, str]:
    """Look up (accent_hex, tint_hex) for a severity, falling back to neutral grey.

    Never raises -- an unknown or malformed severity entry always yields a
    usable style pair.
    """
    styles = routing_config.get("severity_styles")
    style = styles.get(severity) if isinstance(styles, dict) else None
    if not isinstance(style, dict):
        logger.warning("unknown_severity_style", extra={"severity": severity})
        return _FALLBACK_ACCENT, _FALLBACK_TINT
    accent = style.get("accent")
    tint = style.get("tint")
    return (
        str(accent) if accent else _FALLBACK_ACCENT,
        str(tint) if tint else _FALLBACK_TINT,
    )


def _strip_header_injection(value: Any) -> str:
    """Collapse CR/LF in a value destined for an email header (Subject)."""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def _visible_fields(fields: Mapping[str, Any]) -> list[tuple[str, Any]]:
    return [(key, value) for key, value in fields.items() if value not in (None, "", [])]


def _is_safe_url(url: str) -> bool:
    return url.startswith("https://") or url.startswith("http://")


def render_alert(
    *,
    rule_id: str,
    severity: str,
    title: str,
    fields: Mapping[str, Any],
    ai_analysis: str | None = None,
    console_url: str | None = None,
) -> tuple[str, str, str]:
    """Render (subject, html_body, text_body) for a finding.

    `fields` entries whose value is None, "", or [] are omitted. Every
    interpolated value is html.escape()'d before it reaches the HTML output.
    """
    routing_config = load_routing_config()
    accent, tint = _severity_style(severity, routing_config)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    visible = _visible_fields(fields)

    subject = (
        f"[{_strip_header_injection(severity)}] "
        f"{_strip_header_injection(title)} - {_strip_header_injection(rule_id)}"
    )
    html_body = _render_html(
        severity=severity,
        accent=accent,
        tint=tint,
        title=title,
        rule_id=rule_id,
        fields=visible,
        ai_analysis=ai_analysis,
        console_url=console_url,
        generated_at=generated_at,
    )
    text_body = _render_text(
        severity=severity,
        title=title,
        rule_id=rule_id,
        fields=visible,
        ai_analysis=ai_analysis,
        console_url=console_url,
        generated_at=generated_at,
    )
    return subject, html_body, text_body


_MAX_NESTED_RENDER_DEPTH = 6


def _render_nested_value(value: Any, depth: int = 0) -> str:
    """Render a dict/list field value (e.g. a delegation chain or IAM binding
    delta) as a nested HTML table/list instead of a Python repr string.

    Depth-capped like the rule engine's own `_contains_value` -- these values
    originate from audit log entries, which are attacker-influenced. Every
    leaf still passes through html.escape().
    """
    if depth > _MAX_NESTED_RENDER_DEPTH:
        return html.escape(str(value))
    if isinstance(value, Mapping):
        if not value:
            return '<span style="color:#6b7280;">(empty)</span>'
        rows = "".join(
            "<tr>"
            '<td style="padding:2px 8px 2px 0;font-family:Arial,sans-serif;font-size:12px;'
            'font-weight:bold;color:#374151;vertical-align:top;white-space:nowrap;">'
            f"{html.escape(str(k))}</td>"
            '<td style="padding:2px 0;font-family:Arial,sans-serif;font-size:12px;'
            f'color:#111827;vertical-align:top;">{_render_nested_value(v, depth + 1)}</td>'
            "</tr>"
            for k, v in value.items()
        )
        return (
            '<table role="presentation" cellpadding="0" cellspacing="0" '
            f'style="border-left:2px solid #d1d5db;padding-left:6px;margin:2px 0;">{rows}</table>'
        )
    if isinstance(value, list | tuple):
        if not value:
            return '<span style="color:#6b7280;">(empty)</span>'
        return "".join(
            '<div style="padding:2px 0;border-bottom:1px dashed #e5e7eb;">'
            f"&bull; {_render_nested_value(item, depth + 1)}</div>"
            for item in value
        )
    return html.escape(str(value))


def _render_field_rows(fields: list[tuple[str, Any]], tint: str) -> str:
    rows = []
    for key, value in fields:
        value_html = (
            _render_nested_value(value) if isinstance(value, Mapping | list | tuple) else html.escape(str(value))
        )
        rows.append(
            "<tr>"
            f'<td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;'
            f'background-color:{tint};font-family:Arial,sans-serif;font-size:13px;'
            'font-weight:bold;color:#111827;vertical-align:top;width:35%;">'
            f"{html.escape(str(key))}</td>"
            '<td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;'
            'font-family:Arial,sans-serif;font-size:13px;color:#111827;'
            f'vertical-align:top;">{value_html}</td>'
            "</tr>"
        )
    return "".join(rows)


# Fixed label -> section lookup so the email groups related facts together
# (who did it / when / what / where the call came from / what actually
# changed) instead of one long flat table. A rule's `fields:` mapping in
# config/rules.yaml is still just {label: dotted path} -- no schema change
# there -- this grouping is purely a rendering concern, keyed on the exact
# label text the shipped rules use.
_FIELD_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Who",
        (
            "Principal",
            "Principal Subject",
            "Principal Subject (Federated Identity)",
            "Principal Email (if mapped)",
            "Service Account Key Used",
            "Impersonation/Delegation Chain",
        ),
    ),
    ("When", ("Event Time (UTC)",)),
    ("What", ("Method", "Resource", "Service Account", "Firewall Rule", "Project")),
    ("Where From", ("Caller IP", "User Agent")),
    (
        "Change Detail",
        (
            "IAM Binding Changes (Delta)",
            "Requested Policy",
            "Requested Firewall Config",
            "Requested Audit Config",
            "Requested Change",
        ),
    ),
)


def _group_fields_into_sections(fields: list[tuple[str, Any]]) -> list[tuple[str, list[tuple[str, Any]]]]:
    """Group (label, value) pairs by `_FIELD_SECTIONS`, preserving each field's
    original position within its section. A label absent from that lookup
    (a future or custom rule field) still renders -- it lands in a trailing
    "Details" section rather than being silently dropped.
    """
    by_label = dict(fields)
    used: set[str] = set()
    sections: list[tuple[str, list[tuple[str, Any]]]] = []
    for name, labels in _FIELD_SECTIONS:
        rows = [(label, by_label[label]) for label in labels if label in by_label]
        if rows:
            sections.append((name, rows))
            used.update(label for label, _ in rows)
    leftover = [(label, value) for label, value in fields if label not in used]
    if leftover:
        sections.append(("Details", leftover))
    return sections


def _render_section(name: str, rows: list[tuple[str, Any]], tint: str) -> str:
    header = (
        '<tr><td colspan="2" style="padding:14px 12px 4px 12px;font-family:Arial,sans-serif;'
        'font-size:11px;font-weight:bold;letter-spacing:0.6px;color:#6b7280;'
        f'text-transform:uppercase;">{html.escape(name)}</td></tr>'
    )
    return header + _render_field_rows(rows, tint)


def _render_sections(fields: list[tuple[str, Any]], tint: str) -> str:
    sections = _group_fields_into_sections(fields)
    if not sections:
        return (
            '<tr><td style="padding:8px 12px;font-family:Arial,sans-serif;'
            'font-size:13px;color:#6b7280;">No additional fields.</td></tr>'
        )
    return "".join(_render_section(name, rows, tint) for name, rows in sections)


def _render_ai_block(ai_analysis: str | None, accent: str, tint: str) -> str:
    if not ai_analysis:
        return ""
    ai_text = html.escape(str(ai_analysis)).replace("\n", "<br>")
    return (
        '<tr><td colspan="2" style="padding:16px;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-left:4px solid {accent};background-color:{tint};">'
        '<tr><td style="padding:12px 16px;font-family:Arial,sans-serif;font-size:13px;'
        'color:#111827;line-height:1.5;">'
        '<strong style="display:block;margin-bottom:4px;">AI Analysis</strong>'
        f"{ai_text}</td></tr></table></td></tr>"
    )


def _render_console_button(console_url: str | None, accent: str) -> str:
    if not console_url or not _is_safe_url(console_url):
        return ""
    url_escaped = html.escape(console_url)
    return (
        '<tr><td style="padding:16px;text-align:left;">'
        f'<a href="{url_escaped}" style="display:inline-block;padding:10px 20px;'
        f'background-color:{accent};color:#ffffff;font-family:Arial,sans-serif;'
        'font-size:13px;font-weight:bold;text-decoration:none;border-radius:4px;">'
        "Open in Cloud Console</a></td></tr>"
    )


def _render_html(
    *,
    severity: str,
    accent: str,
    tint: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    generated_at: str,
) -> str:
    severity_escaped = html.escape(str(severity))
    title_escaped = html.escape(str(title))
    rule_id_escaped = html.escape(str(rule_id))
    generated_at_escaped = html.escape(generated_at)

    fields_html = _render_sections(fields, tint)
    ai_block = _render_ai_block(ai_analysis, accent, tint)
    button_block = _render_console_button(console_url, accent)

    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="max-width:640px;font-family:Arial,sans-serif;border:1px solid #e5e7eb;">'
        "<tr><td "
        f'style="background-color:{accent};padding:16px 20px;">'
        '<span style="color:#ffffff;font-family:Arial,sans-serif;font-size:12px;'
        f'font-weight:bold;letter-spacing:1px;">{severity_escaped}</span>'
        '<div style="color:#ffffff;font-family:Arial,sans-serif;font-size:18px;'
        f'font-weight:bold;margin-top:4px;">{title_escaped}</div>'
        "</td></tr>"
        '<tr><td style="padding:0;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
        f"{fields_html}</table></td></tr>"
        f"{ai_block}{button_block}"
        '<tr><td style="padding:16px 20px;border-top:1px solid #e5e7eb;'
        'background-color:#f9fafb;">'
        '<div style="font-family:Arial,sans-serif;font-size:11px;color:#6b7280;">'
        f"Rule: {rule_id_escaped}</div>"
        '<div style="font-family:Arial,sans-serif;font-size:11px;color:#6b7280;">'
        f"Generated: {generated_at_escaped}</div>"
        '<div style="font-family:Arial,sans-serif;font-size:11px;color:#6b7280;'
        'margin-top:4px;">This is an automated message, do not reply.</div>'
        "</td></tr></table>"
    )


def _render_text(
    *,
    severity: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    generated_at: str,
) -> str:
    lines = [f"[{severity}] {title}", f"Rule: {rule_id}", ""]
    sections = _group_fields_into_sections(fields)
    if sections:
        for name, rows in sections:
            lines.append(f"-- {name} --")
            lines.extend(f"  {key}: {value}" for key, value in rows)
            lines.append("")
    else:
        lines.append("No additional fields.")
        lines.append("")
    if ai_analysis:
        lines.append("AI Analysis:")
        lines.append(str(ai_analysis))
        lines.append("")
    if console_url and _is_safe_url(console_url):
        lines.append(f"Open in Cloud Console: {console_url}")
        lines.append("")
    lines.append(f"Generated: {generated_at}")
    lines.append("This is an automated message, do not reply.")
    return "\n".join(lines)
