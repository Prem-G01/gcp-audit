"""Renders Gmail alert emails (subject, HTML body, plain-text body) for findings.

Five visually distinct HTML layouts are selected per finding (see
`_select_template`, keyed on the real rule ids in config/rules.yaml):
"A" (Executive Dark, clean HIGH default), "B" (Security Operations, IOC-
focused), "C" (Clean Enterprise, default), "D" (Executive Summary, plain-
English framing for public_iam_grant/billing_account_changed), and "E"
(Engineer Detail, technical breakdown + remediation commands for
firewall_open_to_internet/service_account_key_created). All layouts use
inline CSS and <table> markup only (no flexbox/grid) -- CLAUDE.md forbids
general <style> blocks here for Outlook/Gmail rendering compatibility.
One narrow, explicitly-approved exception exists (see
_wrap_html_document): a <style> block containing only Gmail's
proprietary [data-ogsc]/[data-ogsb] dark-mode override selectors, inert
on every other client since only Gmail ever injects those attributes.
`@media (prefers-color-scheme: dark)` is still not used -- most clients
that matter here, Outlook desktop included, ignore it. Every value that
originates from an audit log entry is attacker-influenced and is passed
through html.escape() before reaching the HTML template.

Severity colours are NOT hardcoded here -- they come from
config/routing.yaml's severity_styles, per this repo's "no logic in Python"
rule for styling. Anything this module can't honestly derive from real
finding/field data (a fabricated risk score, a fake compliance-framework
PASS/FAIL badge, a guessed AI model name, a "revoke access" button with
nothing behind it) is deliberately omitted rather than invented.
Remediation commands (Template E) are built only from this finding's own
resource name/project fields -- never a placeholder value that wasn't
actually present.
"""

from __future__ import annotations

import html
import ipaddress
import logging
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

import yaml

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "routing.yaml"

_FALLBACK_ACCENT = "#6b7280"
_FALLBACK_TINT = "#f3f4f6"
_MAX_NESTED_RENDER_DEPTH = 6
_MAX_SCALAR_LENGTH = 500
_MAX_LIST_ITEMS = 20
# Cycled by nesting depth in _render_nested_value so each level of a deeply
# nested object is visually distinguishable from its parent, not just
# indented by the same flat gray line at every depth. Darker -> lighter
# reads as "more deeply nested" without needing a legend.
_NESTING_BORDER_COLORS = ("#94a3b8", "#cbd5e1", "#e2e8f0")


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


def _severity_colors(severity: str) -> dict[str, str]:
    """Same lookup as `_severity_style`, shaped as a dict. Colours still come
    from config/routing.yaml -- this is a rendering-convenience wrapper, not
    a second source of truth.
    """
    accent, tint = _severity_style(severity, load_routing_config())
    return {"accent": accent, "tint": tint}


def _strip_header_injection(value: Any) -> str:
    """Collapse CR/LF in a value destined for an email header (Subject)."""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def _visible_fields(fields: Mapping[str, Any]) -> list[tuple[str, Any]]:
    return [(key, value) for key, value in fields.items() if value not in (None, "", [])]


def _is_safe_url(url: str | None) -> bool:
    return isinstance(url, str) and (url.startswith("https://") or url.startswith("http://"))


def _field_value(fields: list[tuple[str, Any]], label: str) -> Any | None:
    for key, value in fields:
        if key == label:
            return value
    return None


# -----------------------------------------------------------------------
# Nested value rendering (delegation chains, IAM binding deltas, requested
# policies) -- real HTML sub-tables instead of a Python repr string.
# -----------------------------------------------------------------------

# Splits a camelCase/PascalCase run at each lowercase->uppercase boundary
# and at the end of an acronym run (e.g. "IPProtocol" -> "IP Protocol",
# not "I P Protocol") -- used only to relabel raw GCP API field names for
# display; never changes the underlying data.
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


_SIMPLE_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _prettify_key(key: str) -> str:
    """Turn a raw GCP API field name into a readable label for nested-value
    rendering, e.g. "principalSubject" -> "Principal Subject",
    "sourceRanges" -> "Source Ranges". Purely cosmetic relabeling -- only
    capitalizes each token's first letter if it's lowercase, so existing
    acronym casing (IP, TTL, ...) is preserved rather than mangled.

    Keys that aren't a plain camelCase/snake_case identifier (Kubernetes-
    style annotation keys like "autoscaling.knative.dev/maxScale", which
    Cloud Run's request objects carry) are returned verbatim instead of
    prettified -- the word-splitting logic below only understands "_" and
    camelCase boundaries, so running it on a dotted/slashed key produces
    mangled output ("Autoscaling.knative.dev/max Scale") that's less
    readable than the original, not more.
    """
    if not _SIMPLE_KEY_RE.match(key):
        return key
    spaced = _CAMEL_BOUNDARY_RE.sub(" ", key.replace("_", " "))
    words = spaced.split()
    if not words:
        return key
    return " ".join(w[:1].upper() + w[1:] if w[:1].islower() else w for w in words)


def _escape_scalar(value: Any) -> str:
    """str() + truncate + html.escape() a scalar field value, in that order.

    Truncating BEFORE escaping (not after) matters -- truncating the
    escaped string could cut an entity reference in half (e.g. "&amp;"
    -> "&am"), producing broken/mojibake output in the email.

    These values originate from audit log entries -- attacker-influenced,
    and with no inherent size limit (a single request field can legitimately
    be a multi-KB blob). Without this cap, one oversized value blows up the
    whole email into something unreadable, the same failure mode a huge
    nested dict/list has -- see _MAX_NESTED_RENDER_DEPTH and
    _MAX_LIST_ITEMS.

    A raw `datetime` (event_timestamp, always UTC-aware -- see
    src/models.py) is rendered in IST rather than via str()'s default
    ISO-with-microseconds form -- this platform's operators work in IST,
    and that default form needs manual mental math plus a timezone lookup
    to be useful at a glance.
    """
    if isinstance(value, datetime):
        value = _format_event_time_ist(value)
    text = str(value)
    if len(text) > _MAX_SCALAR_LENGTH:
        text = f"{text[:_MAX_SCALAR_LENGTH]}… ({len(text)} chars total)"
    return html.escape(text)


def _render_nested_value(value: Any, depth: int = 0) -> str:
    """Render a dict/list field value as a nested HTML table/list.

    Depth-capped -- these values originate from audit log entries, which are
    attacker-influenced. Every leaf still passes through _escape_scalar()
    (html.escape() plus a length cap -- see its docstring).
    """
    if depth > _MAX_NESTED_RENDER_DEPTH:
        return _escape_scalar(value)
    if isinstance(value, Mapping):
        if not value:
            return '<span style="color:#6b7280;">(empty)</span>'
        rows = "".join(
            "<tr>"
            '<td class="ea-key" style="padding:3px 8px 3px 0;font-family:Arial,sans-serif;font-size:13px;'
            'font-weight:bold;color:#374151;vertical-align:top;white-space:nowrap;'
            'background-color:#ffffff;">'
            f"{html.escape(_prettify_key(str(k)))}</td>"
            '<td class="ea-val" style="padding:3px 0;font-family:Arial,sans-serif;font-size:13px;'
            f'color:#111827;vertical-align:top;background-color:#ffffff;">'
            f"{_render_nested_value(v, depth + 1)}</td>"
            "</tr>"
            for k, v in value.items()
        )
        # 14px indent per level (not the previous 6px) so 3-4 levels of real
        # GCP request nesting (Spec > Template > Containers > Resources, a
        # very ordinary shape) actually reads as a staircase instead of one
        # visually flat wall of key/value pairs -- the original 6px was
        # imperceptible past 2 levels deep, which was the actual "not
        # clear" problem, not information density. Explicit background-color
        # on every cell (not just the outer wrapper) -- a client's dark-mode
        # engine can repaint an individual node's background even when its
        # ancestor already declared one, so nothing here is left transparent
        # to inherit; that gap (not the color-scheme meta tags' absence) was
        # the actual cause of "readable in light mode, not in dark mode."
        border_color = _NESTING_BORDER_COLORS[depth % len(_NESTING_BORDER_COLORS)]
        return (
            '<table role="presentation" cellpadding="0" cellspacing="0" '
            f'style="border-left:3px solid {border_color};padding-left:14px;margin:4px 0;'
            f'background-color:#ffffff;">{rows}</table>'
        )
    if isinstance(value, list | tuple):
        if not value:
            return '<span style="color:#6b7280;">(empty)</span>'
        shown, remaining = value[:_MAX_LIST_ITEMS], len(value) - _MAX_LIST_ITEMS
        rendered = "".join(
            '<div style="padding:2px 0;border-bottom:1px dashed #e5e7eb;">'
            f"&bull; {_render_nested_value(item, depth + 1)}</div>"
            for item in shown
        )
        if remaining > 0:
            rendered += (
                '<div style="padding:2px 0;color:#6b7280;font-style:italic;">'
                f"&hellip; and {remaining} more</div>"
            )
        return rendered
    return _escape_scalar(value)


def _contains_text(value: Any, needle: str, depth: int = 0) -> bool:
    """Recursively search VALUES (never dict keys) for a case-insensitive substring."""
    if depth > _MAX_NESTED_RENDER_DEPTH:
        return False
    if isinstance(value, str):
        return needle.lower() in value.lower()
    if isinstance(value, Mapping):
        return any(_contains_text(v, needle, depth + 1) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_text(item, needle, depth + 1) for item in value)
    return False


def _has_nested_key(value: Any, key: str, depth: int = 0) -> bool:
    if depth > _MAX_NESTED_RENDER_DEPTH:
        return False
    if isinstance(value, Mapping):
        if key in value:
            return True
        return any(_has_nested_key(v, key, depth + 1) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_has_nested_key(item, key, depth + 1) for item in value)
    return False


def _render_field_rows(fields: list[tuple[str, Any]], row_bg: str) -> str:
    rows = []
    for key, value in fields:
        value_html = (
            _render_nested_value(value) if isinstance(value, Mapping | list | tuple) else _escape_scalar(value)
        )
        # class="ea-key"/"ea-val" carry no visual meaning by themselves --
        # they exist only so the [data-ogsc]/[data-ogsb] rules in <head>
        # (see _wrap_html_document) can target this exact label/value
        # pattern when Gmail applies its own dark mode, which otherwise
        # converts some structurally-identical tables in an email and
        # leaves others untouched -- confirmed live, two emails for the
        # SAME rule/template, one fully dark-and-legible, one with this
        # exact row pattern stuck white inside an otherwise-dark shell.
        rows.append(
            "<tr>"
            f'<td class="ea-key" style="padding:6px 12px;border-bottom:1px solid #e5e7eb;'
            f'background-color:{row_bg};font-family:Arial,sans-serif;font-size:14px;'
            'font-weight:bold;color:#111827;vertical-align:top;width:35%;">'
            f"{html.escape(str(key))}</td>"
            f'<td class="ea-val" style="padding:6px 12px;border-bottom:1px solid #e5e7eb;'
            f'background-color:{row_bg};font-family:Arial,sans-serif;font-size:14px;color:#111827;'
            f'vertical-align:top;">{value_html}</td>'
            "</tr>"
        )
    return "".join(rows)


# -----------------------------------------------------------------------
# Field grouping -- Who / When / What / Where From / Change Detail, keyed
# on the exact field labels the shipped config/rules.yaml rules use. A
# label not in this lookup (a future/custom rule field) still renders --
# it lands in a trailing "Details" section rather than being dropped.
# -----------------------------------------------------------------------

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
    ("When", ("Event Time (IST)",)),
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


def _render_info_card(title: str, rows: list[tuple[str, Any]], *, accent: str | None = None) -> str:
    """A bordered, rounded info card: optional small title, then label/value rows."""
    if not rows:
        return ""
    border_left = f"border-left:3px solid {accent};" if accent else "border-left:1px solid #e2e8f0;"
    title_html = (
        '<tr><td colspan="2" style="padding:8px 12px 2px 12px;font-family:Arial,sans-serif;'
        'font-size:11px;font-weight:bold;letter-spacing:0.08em;color:#94a3b8;'
        f'text-transform:uppercase;">{html.escape(title)}</td></tr>'
        if title
        else ""
    )
    rows_html = _render_field_rows(rows, "#f8fafc")
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="{border_left}border-top:1px solid #e2e8f0;border-right:1px solid #e2e8f0;'
        'border-bottom:1px solid #e2e8f0;border-radius:6px;background-color:#f8fafc;margin-bottom:8px;">'
        f"{title_html}{rows_html}</table>"
    )


def _render_severity_badge(severity: str, accent: str) -> str:
    return (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:10px;'
        f'background-color:{accent};color:#ffffff;font-family:Arial,sans-serif;'
        'font-size:12px;font-weight:bold;letter-spacing:0.5px;">'
        f"{html.escape(str(severity))}</span>"
    )


def _render_cta_row(buttons: list[tuple[str, str | None, str, str, str]]) -> str:
    """buttons: (label, url, bg_color, text_color, border_color). Skips any
    button whose url is missing or not http(s) -- never renders a dead link.
    """
    cells = []
    for label, url, bg_color, text_color, border_color in buttons:
        if not _is_safe_url(url):
            continue
        url_escaped = html.escape(str(url))
        cells.append(
            '<td style="padding:0 8px 0 0;">'
            f'<a href="{url_escaped}" style="display:inline-block;padding:10px 18px;'
            f'background-color:{bg_color};color:{text_color};font-family:Arial,sans-serif;'
            f'font-size:13px;font-weight:bold;text-decoration:none;border-radius:4px;'
            f'border:1px solid {border_color};">{html.escape(label)}</a></td>'
        )
    if not cells:
        return ""
    return (
        '<tr><td style="padding:16px 20px;">'
        '<table role="presentation" cellpadding="0" cellspacing="0"><tr>' + "".join(cells) + "</tr></table>"
        "</td></tr>"
    )


# -----------------------------------------------------------------------
# Markdown-lite: Gemini returns **bold** emphasis in plain text. Convert it
# to real <strong> tags -- but only AFTER html.escape(), so this only ever
# wraps already-neutralized text in tags this function controls. It can
# never introduce attacker-controlled markup.
# -----------------------------------------------------------------------

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def _render_markdown_bold(escaped_text: str) -> str:
    return _BOLD_RE.sub(r"<strong>\1</strong>", escaped_text)


def _render_ai_text(ai_analysis: str) -> str:
    escaped = html.escape(str(ai_analysis))
    bolded = _render_markdown_bold(escaped)
    return bolded.replace("\n", "<br>")


# -----------------------------------------------------------------------
# Real, derived helpers -- no fabricated data.
# -----------------------------------------------------------------------

_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_rfc1918(ip: str) -> bool:
    """True iff `ip` is a valid RFC1918 private IPv4 address. Never raises."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and any(addr in net for net in _RFC1918_NETWORKS)


_IST = ZoneInfo("Asia/Kolkata")


def _format_event_time_ist(dt: datetime) -> str:
    """Render a datetime in IST (UTC+5:30) as 'YYYY-MM-DD HH:MM:SS IST' --
    this platform's operators work in IST, and a bare UTC timestamp needs
    manual mental math to be useful at a glance. Naive datetimes are
    assumed UTC (matches src/models.py's EnrichedEvent.event_timestamp,
    always parsed from a Cloud Audit Log's UTC timestamp). Returns the raw
    (unescaped) string -- callers (_escape_scalar) escape it same as any
    other value.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(_IST).strftime("%Y-%m-%d %H:%M:%S IST")


def _extract_utc_hour(value: Any) -> int | None:
    if isinstance(value, datetime):
        return value.hour
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).hour
        except ValueError:
            return None
    return None


def _alert_id(rule_id: str, now: datetime) -> str:
    suffix = re.sub(r"[^A-Z0-9]", "", (rule_id or "").upper())[:4] or "RULE"
    return f"AUD-{now.strftime('%Y%m%d')}-{suffix}"


def _iam_console_url(fields: list[tuple[str, Any]]) -> str | None:
    project_id = _field_value(fields, "Project")
    if not isinstance(project_id, str) or not project_id:
        return None
    return f"https://console.cloud.google.com/iam-admin/iam?project={quote(project_id, safe='')}"


# Real rule ids from config/rules.yaml (all 10 shipped rules). Rule-specific
# overrides win over the severity-based fallback -- e.g. public_iam_grant
# always renders as "D" even though it happens to also be CRITICAL.
_TEMPLATE_D_RULE_IDS = frozenset({"public_iam_grant", "billing_account_changed"})
_TEMPLATE_E_RULE_IDS = frozenset({"firewall_open_to_internet", "service_account_key_created"})
_TEMPLATE_B_RULE_IDS = frozenset(
    {"iam_policy_change", "audit_config_changed", "org_policy_modified", "federated_identity_action"}
)
_TEMPLATE_A_RULE_IDS = frozenset({"project_created"})


def _select_template(severity: str, rule_id: str) -> str:
    """Pick which of the five layouts to render.

    D = executive summary (public grants, billing changes -- board-relevant).
    E = engineer detail + remediation commands (firewall, SA keys -- rules
        with a concrete, derivable fix).
    B = security-operations IOC view (policy/config/identity changes).
    A = clean HIGH-severity default (project_created and any future HIGH
        rule not otherwise mapped).
    C = clean default for everything else (LOW/MEDIUM, unclassified,
        and any future CRITICAL rule not otherwise mapped -- unlike a
        severity-only fallback, this never silently drops a CRITICAL
        finding into the plainest template; it only reaches C if nothing
        more specific, including the CRITICAL check below, applies).
    """
    if rule_id in _TEMPLATE_D_RULE_IDS:
        return "D"
    if rule_id in _TEMPLATE_E_RULE_IDS:
        return "E"
    if rule_id in _TEMPLATE_B_RULE_IDS:
        return "B"
    if rule_id in _TEMPLATE_A_RULE_IDS:
        return "A"
    if severity == "CRITICAL":
        return "D"
    if severity == "HIGH":
        return "A"
    return "C"


# -----------------------------------------------------------------------
# Honest, fixed lookups for executive-facing copy -- human-friendly
# rewording of a KNOWN rule's real title/nature, never a computed score
# or invented category. Any rule not in these maps falls back to the
# finding's own real `title`/a generic label, rather than guessing.
# -----------------------------------------------------------------------

_PLAIN_ENGLISH_TITLES: dict[str, str] = {
    "public_iam_grant": "Public internet access granted to a cloud resource",
    "billing_account_changed": "Billing account linked or modified",
    "org_policy_modified": "Organization-wide security policy modified",
    "firewall_open_to_internet": "Network firewall opened to the internet",
    "service_account_key_created": "Service account credentials created",
    "iam_policy_change": "Access permissions changed",
    "audit_config_changed": "Audit logging configuration changed",
    "federated_identity_action": "External identity performed a privileged action",
    "project_created": "New GCP project created",
    "unclassified_admin_activity": "Administrative activity detected",
    "resource_created": "A cloud resource was created",
    "resource_deleted": "A cloud resource was deleted",
}


def _plain_english_title(rule_id: str, title: str) -> str:
    return _PLAIN_ENGLISH_TITLES.get(rule_id, title)


def _plain_english_summary(fields: list[tuple[str, Any]]) -> str:
    """A one-sentence, jargon-free summary of what happened -- "who did what
    to what, where" -- derived only from real field data (Principal/
    Resource/Project), never fabricated. Shown at the top of every
    template (not just D) so a non-technical reader gets the gist without
    needing to parse the structured/technical sections below; a technical
    reader still has all of those sections unchanged.

    Returns the raw (unescaped) sentence -- HTML call sites must
    html.escape() it themselves, same as every other interpolated value in
    this module; _render_text (plain text) uses it as-is.
    """
    principal = (
        _field_value(fields, "Principal")
        or _field_value(fields, "Principal Subject")
        or _field_value(fields, "Principal Subject (Federated Identity)")
    )
    resource = (
        _field_value(fields, "Resource")
        or _field_value(fields, "Firewall Rule")
        or _field_value(fields, "Service Account")
        or _field_value(fields, "New Project Resource")
    )
    project = _field_value(fields, "Project")
    parts = [f"{principal} made a change" if principal else "A change was made"]
    if resource:
        parts.append(f"to {resource}")
    if project:
        parts.append(f"in project {project}")
    return " ".join(parts) + "."


_BUSINESS_IMPACT: dict[str, tuple[str, str, str]] = {
    "public_iam_grant": (
        "Data may be publicly exposed",
        "Possible compliance violation",
        "Review access immediately",
    ),
    "billing_account_changed": (
        "Billing destination changed",
        "Possible unexpected charges",
        "Verify this was authorized",
    ),
}
_DEFAULT_BUSINESS_IMPACT: tuple[str, str, str] = (
    "Security-relevant change",
    "May affect compliance posture",
    "Review recommended",
)


def _business_impact(rule_id: str) -> tuple[str, str, str]:
    return _BUSINESS_IMPACT.get(rule_id, _DEFAULT_BUSINESS_IMPACT)


# -----------------------------------------------------------------------
# Remediation commands -- built ONLY from this finding's own real field
# values (the resource's actual name/project). If the expected value
# isn't present, no command is fabricated -- the section just omits that
# step rather than showing a placeholder.
# -----------------------------------------------------------------------


def _resource_name_segment(resource_name: Any, marker: str) -> str | None:
    """Pull the path segment right after `marker` out of a GCP resource
    name, e.g. 'projects/P/global/firewalls/NAME' with marker="firewalls"
    -> "NAME". None if the marker isn't present.
    """
    if not isinstance(resource_name, str):
        return None
    parts = resource_name.split("/")
    if marker in parts:
        idx = parts.index(marker)
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _firewall_remediation_commands(fields: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    resource_name = _field_value(fields, "Firewall Rule") or _field_value(fields, "Resource")
    project_id = _field_value(fields, "Project")
    firewall_name = _resource_name_segment(resource_name, "firewalls")
    if not firewall_name or not isinstance(project_id, str):
        return []
    flag = f" --project={project_id}"
    return [
        ("Disable the rule immediately", f"gcloud compute firewall-rules update {firewall_name}{flag} --disabled"),
        ("Review its full configuration", f"gcloud compute firewall-rules describe {firewall_name}{flag}"),
        ("Delete it once confirmed unneeded", f"gcloud compute firewall-rules delete {firewall_name}{flag}"),
    ]


def _sa_key_remediation_commands(fields: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    resource_name = _field_value(fields, "Service Account") or _field_value(fields, "Resource")
    project_id = _field_value(fields, "Project")
    sa_email = _resource_name_segment(resource_name, "serviceAccounts")
    key_id = _resource_name_segment(resource_name, "keys")
    if not sa_email:
        return []
    flag = f" --project={project_id}" if isinstance(project_id, str) else ""
    list_cmd = f"gcloud iam service-accounts keys list --iam-account={sa_email}{flag}"
    commands = [("List all keys on this service account", list_cmd)]
    if key_id:
        delete_cmd = f"gcloud iam service-accounts keys delete {key_id} --iam-account={sa_email}{flag}"
        commands.append(("Delete this specific key", delete_cmd))
    return commands


def _firewall_config_detail(fields: list[tuple[str, Any]]) -> dict[str, Any] | None:
    """Real source ranges / allowed ports / target tags from the requested
    firewall config, when present and shaped as a dict. None otherwise --
    never fabricates a value that wasn't actually in the audit log entry.
    """
    value = _field_value(fields, "Requested Firewall Config")
    if not isinstance(value, Mapping):
        return None
    return {
        "source_ranges": value.get("sourceRanges"),
        "allowed": value.get("allowed"),
        "target_tags": value.get("targetTags"),
    }


def _sa_key_risk_notes(fields: list[tuple[str, Any]]) -> list[str]:
    notes = [
        "User-managed keys are long-lived credentials -- prefer Workload Identity "
        "or short-lived tokens where possible."
    ]
    caller_ip = _field_value(fields, "Caller IP")
    if isinstance(caller_ip, str) and caller_ip and not _is_rfc1918(caller_ip):
        notes.append(f"Created from a non-private IP ({caller_ip}) -- confirm this was an expected origin.")
    return notes


def _render_code_block(label: str, command: str) -> str:
    return (
        '<tr><td style="padding:4px 0;">'
        f'<div style="font-family:Arial,sans-serif;font-size:12px;color:#94a3b8;margin-bottom:3px;">'
        f"{html.escape(label)}</div>"
        '<div style="font-family:monospace;font-size:14px;color:#93c5fd;background-color:#0f172a;'
        f'padding:8px 12px;border-radius:5px;overflow-wrap:break-word;">{html.escape(command)}</div>'
        "</td></tr>"
    )


def _detect_indicators(fields: list[tuple[str, Any]]) -> list[tuple[str, str]]:
    """Best-effort indicators of concern, derived only from field values
    already present in this finding -- never fabricated. Each entry is
    (severity_tag, description).
    """
    indicators: list[tuple[str, str]] = []

    change_values = [
        value
        for label in (
            "Requested Policy",
            "IAM Binding Changes (Delta)",
            "Requested Change",
            "Requested Firewall Config",
            "Requested Audit Config",
        )
        if (value := _field_value(fields, label)) is not None
    ]
    if any(_contains_text(v, "allUsers") or _contains_text(v, "allAuthenticatedUsers") for v in change_values):
        indicators.append(("CRITICAL", "Grants access to allUsers or allAuthenticatedUsers (public)"))

    caller_ip = _field_value(fields, "Caller IP")
    if isinstance(caller_ip, str) and caller_ip and not _is_rfc1918(caller_ip):
        indicators.append(("HIGH", f"Caller IP {caller_ip} is not in a private (RFC1918) range"))

    # Reads the raw datetime object from `fields` (never mutated -- only
    # _escape_scalar's rendering step converts it to an IST string), so
    # this still correctly extracts the UTC hour regardless of the field's
    # renamed "(IST)" label and its display formatting elsewhere.
    hour = _extract_utc_hour(_field_value(fields, "Event Time (IST)"))
    if hour is not None and not (6 <= hour < 20):
        indicators.append(("MEDIUM", f"Occurred outside typical business hours ({hour:02d}:00 UTC)"))

    method = _field_value(fields, "Method")
    if isinstance(method, str) and re.search(r"(?i)(delete|disable)", method):
        indicators.append(("HIGH", f"Method '{method}' is destructive/disabling"))

    if change_values and not any(_has_nested_key(v, "condition") for v in change_values):
        indicators.append(("HIGH", "No IAM condition present on this binding change"))

    return indicators


_SUBJECT_IDENTIFIER_LABELS = ("Resource", "Firewall Rule", "Service Account", "New Project Resource")


def _subject_identifier(fields: list[tuple[str, Any]]) -> str | None:
    """A short, human-recognizable identifier for the subject line, so two
    different real-world events (e.g. two different VMs created) never
    produce an identical subject. Prefers the actual resource's own name
    (the last path segment of its resource name) over the full path;
    falls back to the project id when no resource-shaped field is present.
    Real data only -- returns None rather than fabricating a placeholder.
    """
    for label in _SUBJECT_IDENTIFIER_LABELS:
        value = _field_value(fields, label)
        if isinstance(value, str) and value:
            return value.rstrip("/").split("/")[-1]
    project = _field_value(fields, "Project")
    return project if isinstance(project, str) and project else None


def _wrap_html_document(*, subject: str, severity: str, title: str, body_html: str) -> str:
    """Wrap a template's inner <table> markup in a full HTML document --
    <!doctype>/<html>/<head> with charset + viewport meta tags, plus a
    hidden preheader (the inbox-list preview snippet most clients show
    next to the subject, read before any visible body content).

    Contains ONE deliberate, narrow exception to CLAUDE.md's "inline CSS
    and <table> layout only, no <style> blocks" rule: a <style> block
    containing ONLY Gmail's proprietary [data-ogsc]/[data-ogsb] dark-mode
    override selectors (see below). That rule exists to keep Outlook's
    Word rendering engine predictable -- this block poses no risk to that,
    because [data-ogsc]/[data-ogsb] are attributes GMAIL ITSELF injects
    into the DOM when its automatic dark-mode conversion engages; no other
    client (Outlook included) ever adds them, so on every other client
    these selectors simply never match anything and the block is inert.
    It contains no layout rules (no flexbox/grid/positioning) -- only
    background-color/color overrides for the two classes below. Approved
    explicitly for this narrow case, not a general reopening of <style>.

    subject/severity/title are already attacker-influenced (from the
    finding) by the time they reach here -- html.escape()'d same as every
    other interpolated value in this module.
    """
    preheader = html.escape(_strip_header_injection(f"{severity}: {title}")[:150])
    return (
        "<!doctype html>"
        '<html lang="en">'
        "<head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        # Every color in every template is hardcoded per-severity (from
        # config/routing.yaml), never theme-aware -- a client's automatic
        # dark-mode inversion would selectively flip some of those colors
        # (e.g. the deliberately-dark navy header) and not others, breaking
        # contrast in ways this module never designed for. These two tags
        # are the standard opt-out signal (Apple Mail, Outlook.com, and
        # others honor them): render exactly as authored, don't invert.
        '<meta name="color-scheme" content="light">'
        '<meta name="supported-color-schemes" content="light">'
        f"<title>{html.escape(subject)}</title>"
        # Gmail's own dark-mode conversion applies inconsistently across
        # structurally identical content within the same email -- confirmed
        # live: two emails for the same rule/template, one fully converted
        # and legible, one with this exact label/value row pattern
        # (class="ea-key"/"ea-val", used by _render_field_rows and the
        # Template C/E zebra rows) left white inside an otherwise-dark
        # shell. Forces a consistent, deliberately-chosen dark rendering
        # instead of leaving it to that inconsistent heuristic.
        "<style>"
        "[data-ogsc] .ea-key,[data-ogsb] .ea-key,"
        "[data-ogsc] .ea-val,[data-ogsb] .ea-val{"
        "background-color:#1e293b !important;color:#e2e8f0 !important;"
        "}"
        "</style>"
        "</head>"
        '<body style="margin:0;padding:0;background-color:#f3f4f6;">'
        '<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;'
        'opacity:0;overflow:hidden;mso-hide:all;">'
        f"{preheader}&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;"
        "</div>"
        f"{body_html}"
        "</body>"
        "</html>"
    )


def render_alert(
    *,
    rule_id: str,
    severity: str,
    title: str,
    fields: Mapping[str, Any],
    ai_analysis: str | None = None,
    console_url: str | None = None,
    mute_url: str | None = None,
) -> tuple[str, str, str]:
    """Render (subject, html_body, text_body) for a finding.

    `fields` entries whose value is None, "", or [] are omitted. Every
    interpolated value is html.escape()'d before it reaches the HTML output.
    `mute_url` is built by the caller (main.py, from MUTE_SERVICE_URL + this
    finding's real rule_id/project_id) -- omitted entirely (no button
    rendered) when None, exactly like console_url.
    """
    routing_config = load_routing_config()
    accent, tint = _severity_style(severity, routing_config)
    now = datetime.now(UTC)
    generated_at = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    alert_id = _alert_id(rule_id, now)
    visible = _visible_fields(fields)
    template = _select_template(severity, rule_id)

    identifier = _subject_identifier(visible)
    subject = (
        f"[{_strip_header_injection(severity)}] "
        f"{_strip_header_injection(title)}"
        + (f" — {_strip_header_injection(identifier)}" if identifier else "")
        + f" ({_strip_header_injection(rule_id)})"
    )

    renderer = {
        "A": _render_template_a,
        "B": _render_template_b,
        "C": _render_template_c,
        "D": _render_template_d,
        "E": _render_template_e,
    }[template]
    html_body = renderer(
        severity=severity,
        accent=accent,
        tint=tint,
        title=title,
        rule_id=rule_id,
        fields=visible,
        ai_analysis=ai_analysis,
        console_url=console_url,
        mute_url=mute_url,
        generated_at=generated_at,
        alert_id=alert_id,
    )
    html_body = _wrap_html_document(subject=subject, severity=severity, title=title, body_html=html_body)
    text_body = _render_text(
        severity=severity,
        title=title,
        rule_id=rule_id,
        fields=visible,
        ai_analysis=ai_analysis,
        console_url=console_url,
        mute_url=mute_url,
        generated_at=generated_at,
        alert_id=alert_id,
    )
    return subject, html_body, text_body


# -----------------------------------------------------------------------
# Template A -- Executive Dark. Internal security leads / eng managers.
# -----------------------------------------------------------------------


def _render_template_a(
    *,
    severity: str,
    accent: str,
    tint: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    mute_url: str | None,
    generated_at: str,
    alert_id: str,
) -> str:
    del tint  # Template A deliberately keeps info cards neutral, not severity-tinted.
    title_e = html.escape(str(title))
    rule_id_e = html.escape(str(rule_id))
    project = _field_value(fields, "Project")
    project_e = html.escape(str(project)) if project else ""
    method = _field_value(fields, "Method") or "-"
    caller_ip = _field_value(fields, "Caller IP") or "-"

    kpi_row = (
        "<tr>"
        '<td width="34%" style="padding:12px;border-bottom:1px solid #e2e8f0;border-right:1px solid #e2e8f0;'
        'background-color:#ffffff;">'
        '<div style="font-family:Arial,sans-serif;font-size:11px;color:#64748b;text-transform:uppercase;">'
        "Severity</div>"
        f'<div style="font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:{accent};">'
        f"{html.escape(str(severity))}</div></td>"
        '<td width="33%" style="padding:12px;border-bottom:1px solid #e2e8f0;border-right:1px solid #e2e8f0;'
        'background-color:#ffffff;">'
        '<div style="font-family:Arial,sans-serif;font-size:11px;color:#64748b;text-transform:uppercase;">'
        "Method</div>"
        '<div style="font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#0f172a;">'
        f"{html.escape(str(method))}</div></td>"
        '<td width="33%" style="padding:12px;border-bottom:1px solid #e2e8f0;background-color:#ffffff;">'
        '<div style="font-family:Arial,sans-serif;font-size:11px;color:#64748b;text-transform:uppercase;">'
        "Caller IP</div>"
        '<div style="font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#0f172a;">'
        f"{html.escape(str(caller_ip))}</div></td>"
        "</tr>"
    )

    sections = _group_fields_into_sections(fields)
    cards = "".join(_render_info_card(name, rows, accent=accent) for name, rows in sections if name != "Change Detail")
    cards_html = f'<tr><td style="padding:16px 20px 0 20px;">{cards}</td></tr>' if cards else ""

    change_rows = next((rows for name, rows in sections if name == "Change Detail"), None)
    change_html = ""
    if change_rows:
        change_html = (
            '<tr><td style="padding:0 20px 16px 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #fed7aa;border-radius:6px;background-color:#fff7ed;">'
            '<tr><td colspan="2" style="padding:10px 12px 2px 12px;font-family:Arial,sans-serif;'
            "font-size:11px;font-weight:bold;letter-spacing:0.08em;color:#c2410c;"
            'text-transform:uppercase;">Change Detail</td></tr>'
            f'{_render_field_rows(change_rows, "#ffedd5")}</table></td></tr>'
        )

    ai_html = ""
    if ai_analysis:
        ai_html = (
            '<tr><td style="padding:0 20px 16px 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #bfdbfe;border-radius:6px;background-color:#eff6ff;">'
            '<tr><td style="padding:12px 16px;font-family:Arial,sans-serif;font-size:14px;'
            'color:#0f172a;line-height:1.6;">'
            '<strong style="display:block;margin-bottom:6px;color:#1e40af;">&#10022; Gemini AI Analysis</strong>'
            f"{_render_ai_text(ai_analysis)}</td></tr></table></td></tr>"
        )

    buttons_html = _render_cta_row(
        [
            ("Open Cloud Console", console_url, "#0f172a", "#ffffff", "#0f172a"),
            ("IAM Policy", _iam_console_url(fields), "#ffffff", "#3b82f6", "#3b82f6"),
            ("Mute this alert", mute_url, "#ffffff", "#b45309", "#fbbf24"),
        ]
    )

    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="max-width:620px;font-family:Arial,sans-serif;border:1px solid #e2e8f0;'
        'background-color:#ffffff;">'
        f'<tr><td style="background-color:{accent};height:4px;line-height:4px;font-size:0;">&nbsp;</td></tr>'
        '<tr><td style="background-color:#0f172a;padding:20px 20px 16px 20px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;letter-spacing:1px;'
        'color:#e2e8f0;">GCP AUDIT PLATFORM</td>'
        f'<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;color:#94a3b8;">'
        f"{project_e}</td></tr></table>"
        f'<div style="font-family:Arial,sans-serif;font-size:12px;color:#64748b;margin-top:2px;">'
        f"{html.escape(generated_at)}</div>"
        f'<div style="margin-top:12px;">{_render_severity_badge(severity, accent)}</div>'
        f'<div style="color:#ffffff;font-family:Arial,sans-serif;font-size:24px;font-weight:bold;'
        f'margin-top:8px;">{title_e}</div>'
        f'<div style="color:#94a3b8;font-family:Arial,sans-serif;font-size:13px;margin-top:4px;">'
        f"Rule: {rule_id_e} &middot; Alert: {html.escape(alert_id)}</div>"
        f'<div style="color:#e2e8f0;font-family:Arial,sans-serif;font-size:14px;margin-top:10px;'
        f'line-height:1.5;">{html.escape(_plain_english_summary(fields))}</div>'
        "</td></tr>"
        f'<tr><td><table role="presentation" width="100%" cellpadding="0" cellspacing="0">{kpi_row}'
        "</table></td></tr>"
        f"{cards_html}{change_html}{ai_html}{buttons_html}"
        '<tr><td style="padding:14px 20px;border-top:1px solid #e2e8f0;background-color:#f8fafc;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;color:#64748b;">'
        "GCP Audit Platform &middot; Automated &middot; Do not reply</td>"
        '<td style="text-align:right;"><span style="display:inline-block;padding:2px 8px;'
        'border-radius:8px;background-color:#eff6ff;color:#3b82f6;font-family:Arial,sans-serif;'
        f'font-size:11px;font-weight:bold;">{rule_id_e}</span></td>'
        "</tr></table></td></tr>"
        "</table>"
    )


# -----------------------------------------------------------------------
# Template B -- Security Operations. SOC analysts / incident responders.
# -----------------------------------------------------------------------


def _render_template_b(
    *,
    severity: str,
    accent: str,
    tint: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    mute_url: str | None,
    generated_at: str,
    alert_id: str,
) -> str:
    del tint
    title_e = html.escape(str(title))
    rule_id_e = html.escape(str(rule_id))

    sections = dict(_group_fields_into_sections(fields))
    who_when = sections.get("Who", []) + sections.get("When", [])
    what_where = sections.get("What", []) + sections.get("Where From", [])
    change_rows = sections.get("Change Detail", [])
    leftover_rows = sections.get("Details", [])

    left_card = _render_info_card("Who & When", who_when) if who_when else ""
    right_card = _render_info_card("What & Where", what_where) if what_where else ""
    two_col = ""
    if left_card or right_card:
        two_col = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
            f'<td width="50%" style="padding-right:8px;vertical-align:top;">{left_card}</td>'
            f'<td width="50%" style="padding-left:8px;vertical-align:top;">{right_card}</td>'
            "</tr></table></td></tr>"
        )

    # "Most detailed" per this template's brief -- change detail and any
    # unmapped/future field label must still show up, never be silently
    # dropped just because they don't fit the two-column Who/What layout.
    change_html = ""
    if change_rows:
        change_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #fed7aa;border-radius:6px;background-color:#fff7ed;">'
            '<tr><td colspan="2" style="padding:10px 12px 2px 12px;font-family:Arial,sans-serif;'
            "font-size:11px;font-weight:bold;letter-spacing:0.08em;color:#c2410c;"
            'text-transform:uppercase;">Change Detail</td></tr>'
            f'{_render_field_rows(change_rows, "#ffedd5")}</table></td></tr>'
        )
    leftover_html = ""
    if leftover_rows:
        leftover_card = _render_info_card("Details", leftover_rows)
        leftover_html = f'<tr><td style="padding:16px 20px 0 20px;">{leftover_card}</td></tr>'

    tag_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#3b82f6"}
    indicators = _detect_indicators(fields)
    ioc_html = ""
    if indicators:
        rows = "".join(
            '<tr><td style="padding:6px 0;border-bottom:1px dashed #fde68a;">'
            f'<span style="display:inline-block;padding:2px 8px;border-radius:8px;'
            f'background-color:{tag_colors.get(tag, "#64748b")};color:#ffffff;'
            f'font-family:Arial,sans-serif;font-size:11px;font-weight:bold;margin-right:8px;">'
            f"{html.escape(tag)}</span>"
            f'<span style="font-family:Arial,sans-serif;font-size:13px;color:#78350f;">'
            f"{html.escape(desc)}</span></td></tr>"
            for tag, desc in indicators
        )
        ioc_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #fde68a;border-radius:6px;background-color:#fffbeb;">'
            '<tr><td style="padding:10px 14px 4px 14px;font-family:Arial,sans-serif;font-size:12px;'
            'font-weight:bold;letter-spacing:0.06em;color:#92400e;text-transform:uppercase;">'
            "Indicators of Concern</td></tr>"
            '<tr><td style="padding:0 14px 8px 14px;"><table role="presentation" width="100%" '
            f'cellpadding="0" cellspacing="0">{rows}</table></td></tr>'
            "</table></td></tr>"
        )

    ai_html = ""
    if ai_analysis:
        ai_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #bbf7d0;border-radius:6px;background-color:#f0fdf4;">'
            '<tr><td style="padding:12px 16px;font-family:Arial,sans-serif;font-size:14px;'
            'color:#14532d;line-height:1.6;">'
            '<strong style="display:block;margin-bottom:6px;">&#10022; Gemini AI Analysis</strong>'
            f"{_render_ai_text(ai_analysis)}</td></tr></table></td></tr>"
        )

    buttons_html = _render_cta_row(
        [
            ("Open Cloud Console", console_url, "#1e293b", "#ffffff", "#1e293b"),
            ("IAM Policy", _iam_console_url(fields), "#ffffff", "#dc2626", "#dc2626"),
            ("Mute this alert", mute_url, "#ffffff", "#b45309", "#fbbf24"),
        ]
    )

    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="max-width:620px;font-family:Arial,sans-serif;border:1px solid #e5e7eb;'
        'background-color:#ffffff;">'
        '<tr><td style="background-color:#1e293b;padding:10px 20px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;color:#ffffff;">'
        "&#128274; GCP AUDIT PLATFORM</td>"
        f'<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;color:#94a3b8;">'
        f"{html.escape(alert_id)}</td></tr></table></td></tr>"
        '<tr><td style="padding:16px 20px 0 20px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="border:1px solid #fecaca;border-radius:8px;background-color:#fef2f2;">'
        '<tr><td style="padding:14px 16px;">'
        f"{_render_severity_badge(severity, accent)}"
        f'<div style="font-family:Arial,sans-serif;font-size:18px;font-weight:bold;color:#7f1d1d;'
        f'margin-top:8px;">{title_e}</div>'
        f'<div style="font-family:Arial,sans-serif;font-size:13px;color:#991b1b;margin-top:2px;">'
        f"Rule: {rule_id_e} &middot; {html.escape(generated_at)}</div>"
        f'<div style="font-family:Arial,sans-serif;font-size:14px;color:#7f1d1d;margin-top:10px;'
        f'line-height:1.5;">{html.escape(_plain_english_summary(fields))}</div>'
        "</td></tr></table></td></tr>"
        f"{two_col}{change_html}{leftover_html}{ioc_html}{ai_html}{buttons_html}"
        '<tr><td style="padding:14px 20px;border-top:1px solid #e5e7eb;background-color:#f8fafc;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;color:#6b7280;">'
        f"GCP Audit Platform &middot; Alert #{html.escape(alert_id)} &middot; Automated &middot; "
        "Do not reply</td>"
        f'<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;font-weight:bold;'
        f'color:{accent};">{html.escape(str(severity))}</td>'
        "</tr></table></td></tr>"
        "</table>"
    )


# -----------------------------------------------------------------------
# Template C -- Clean Enterprise. Client presentations / exec reporting.
# -----------------------------------------------------------------------


def _render_template_c(
    *,
    severity: str,
    accent: str,
    tint: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    mute_url: str | None,
    generated_at: str,
    alert_id: str,
) -> str:
    title_e = html.escape(str(title))
    rule_id_e = html.escape(str(rule_id))
    project = _field_value(fields, "Project")
    project_e = html.escape(str(project)) if project else ""

    tags = [str(severity)]
    if ai_analysis:
        tags.append("AI-analysed")
    tags_html = "".join(
        '<span style="display:inline-block;padding:2px 8px;border-radius:8px;'
        f"background-color:{tint};color:{accent};font-family:Arial,sans-serif;font-size:11px;"
        f'font-weight:bold;margin-right:6px;">{html.escape(tag)}</span>'
        for tag in tags
    )

    sections = _group_fields_into_sections(fields)
    detail_rows = [row for name, rows in sections if name != "Change Detail" for row in rows]
    zebra_rows = []
    for idx, (key, value) in enumerate(detail_rows):
        bg = "#ffffff" if idx % 2 == 0 else "#f8fafc"
        value_html = (
            _render_nested_value(value) if isinstance(value, Mapping | list | tuple) else _escape_scalar(value)
        )
        zebra_rows.append(
            "<tr>"
            f'<td class="ea-key" style="padding:8px 12px;background-color:{bg};border-bottom:1px solid #e2e8f0;'
            'font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#0f172a;width:35%;">'
            f"{html.escape(str(key))}</td>"
            f'<td class="ea-val" style="padding:8px 12px;background-color:{bg};border-bottom:1px solid #e2e8f0;'
            f'font-family:Arial,sans-serif;font-size:14px;color:#0f172a;">{value_html}</td>'
            "</tr>"
        )
    zebra_html = ""
    if zebra_rows:
        zebra_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #e2e8f0;">' + "".join(zebra_rows) + "</table></td></tr>"
        )

    change_rows = next((rows for name, rows in sections if name == "Change Detail"), [])
    change_html = ""
    if change_rows:
        rows_html = []
        for key, value in change_rows:
            badge = ""
            if _contains_text(value, "allUsers") or _contains_text(value, "allAuthenticatedUsers"):
                badge = (
                    '<span style="display:inline-block;margin-left:6px;padding:1px 6px;'
                    'border-radius:6px;background-color:#ef4444;color:#ffffff;'
                    'font-family:Arial,sans-serif;font-size:10px;font-weight:bold;">PUBLIC</span>'
                )
            value_html = (
                _render_nested_value(value) if isinstance(value, Mapping | list | tuple) else _escape_scalar(value)
            )
            rows_html.append(
                "<tr>"
                '<td style="padding:8px 12px;border-bottom:1px solid #fed7aa;font-family:Arial,sans-serif;'
                'font-size:14px;font-weight:bold;color:#7c2d12;width:35%;">'
                f"{html.escape(str(key))}{badge}</td>"
                '<td style="padding:8px 12px;border-bottom:1px solid #fed7aa;font-family:Arial,sans-serif;'
                f'font-size:14px;color:#0f172a;">{value_html}</td>'
                "</tr>"
            )
        change_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #fed7aa;">'
            '<tr><td colspan="2" style="padding:8px 12px;background-color:#fff7ed;'
            'font-family:Arial,sans-serif;font-size:12px;font-weight:bold;letter-spacing:0.06em;'
            'color:#9a3412;text-transform:uppercase;">Change Detail</td></tr>'
            f'{"".join(rows_html)}</table></td></tr>'
        )

    ai_html = ""
    if ai_analysis:
        ai_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #c7d2fe;">'
            '<tr><td style="padding:8px 12px;background-color:#eef2ff;font-family:Arial,sans-serif;'
            'font-size:13px;font-weight:bold;color:#3730a3;">&#10022; Gemini AI Analysis</td></tr>'
            '<tr><td style="padding:12px 16px;background-color:#e0e7ff;font-family:Arial,sans-serif;'
            f'font-size:14px;color:#1e1b4b;line-height:1.6;">{_render_ai_text(ai_analysis)}</td></tr>'
            "</table></td></tr>"
        )

    buttons_html = _render_cta_row(
        [
            ("Open Cloud Console", console_url, accent, "#ffffff", accent),
            ("IAM Policy", _iam_console_url(fields), "#ffffff", "#1e293b", "#cbd5e1"),
            ("Mute this alert", mute_url, "#ffffff", "#b45309", "#fbbf24"),
        ]
    )

    subtitle = html.escape(generated_at) + (f" &middot; {project_e}" if project_e else "")

    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="max-width:620px;font-family:Arial,sans-serif;border:1px solid #e2e8f0;'
        'background-color:#ffffff;">'
        '<tr><td style="background-color:#1e293b;padding:8px 20px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;color:#ffffff;">'
        "&#9679; GCP Audit Platform</td>"
        f'<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;color:#94a3b8;">'
        f"{html.escape(alert_id)}</td></tr></table></td></tr>"
        f'<tr><td style="padding:18px 20px 12px 20px;border-bottom:3px solid {accent};">'
        f"<div>{tags_html}</div>"
        f'<div style="font-family:Arial,sans-serif;font-size:22px;font-weight:bold;color:#0f172a;'
        f'margin-top:8px;">{title_e}</div>'
        f'<div style="font-family:Arial,sans-serif;font-size:13px;color:#64748b;margin-top:4px;">'
        f"{subtitle}</div>"
        f'<div style="font-family:Arial,sans-serif;font-size:14px;color:#334155;margin-top:10px;'
        f'line-height:1.5;">{html.escape(_plain_english_summary(fields))}</div>'
        "</td></tr>"
        f"{zebra_html}{change_html}{ai_html}{buttons_html}"
        '<tr><td style="padding:14px 20px;border-top:1px solid #e2e8f0;background-color:#f8fafc;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;color:#64748b;">'
        "GCP Audit Platform &middot; Automated security alert<br>Do not reply</td>"
        '<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;color:#64748b;">'
        f"Alert: {html.escape(alert_id)}<br>Rule: {rule_id_e}</td>"
        "</tr></table></td></tr>"
        "</table>"
    )


# -----------------------------------------------------------------------
# Template D -- Executive Summary. public_iam_grant, billing_account_changed.
# Plain-English framing for a non-technical, board-relevant audience.
# -----------------------------------------------------------------------


def _render_template_d(
    *,
    severity: str,
    accent: str,
    tint: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    mute_url: str | None,
    generated_at: str,
    alert_id: str,
) -> str:
    del tint
    plain_title = html.escape(_plain_english_title(rule_id, title))
    rule_id_e = html.escape(str(rule_id))

    summary_e = html.escape(_plain_english_summary(fields))

    impact_html = "".join(
        '<td width="33%" style="padding:12px;vertical-align:top;">'
        f'<div style="width:8px;height:8px;border-radius:50%;background-color:{accent};margin-bottom:6px;"></div>'
        '<div style="font-family:Arial,sans-serif;font-size:13px;color:#334155;line-height:1.4;">'
        f"{html.escape(item)}</div>"
        "</td>"
        for item in _business_impact(rule_id)
    )

    sections = _group_fields_into_sections(fields)
    cards = "".join(_render_info_card(name, rows, accent=accent) for name, rows in sections if name != "Change Detail")
    cards_html = f'<tr><td style="padding:16px 20px 0 20px;">{cards}</td></tr>' if cards else ""

    change_rows = next((rows for name, rows in sections if name == "Change Detail"), None)
    change_html = ""
    if change_rows:
        change_html = (
            '<tr><td style="padding:0 20px 16px 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #fed7aa;border-radius:6px;background-color:#fff7ed;">'
            '<tr><td colspan="2" style="padding:10px 12px 2px 12px;font-family:Arial,sans-serif;'
            "font-size:11px;font-weight:bold;letter-spacing:0.08em;color:#c2410c;"
            'text-transform:uppercase;">Change Detail</td></tr>'
            f'{_render_field_rows(change_rows, "#ffedd5")}</table></td></tr>'
        )

    ai_html = ""
    if ai_analysis:
        ai_html = (
            '<tr><td style="padding:0 20px 16px 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #bfdbfe;border-radius:6px;background-color:#eff6ff;">'
            '<tr><td style="padding:12px 16px;font-family:Arial,sans-serif;font-size:14px;'
            'color:#0f172a;line-height:1.75;">'
            '<strong style="display:block;margin-bottom:6px;color:#1e40af;">&#10022; Gemini AI Analysis</strong>'
            f"{_render_ai_text(ai_analysis)}</td></tr></table></td></tr>"
        )

    buttons_html = _render_cta_row(
        [
            ("Open Cloud Console", console_url, "#0f172a", "#ffffff", "#0f172a"),
            ("View Audit Log", _iam_console_url(fields), "#ffffff", "#3b82f6", "#3b82f6"),
            ("Mute this alert", mute_url, "#ffffff", "#b45309", "#fbbf24"),
        ]
    )

    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="max-width:620px;font-family:Arial,sans-serif;border:1px solid #e2e8f0;border-radius:10px;'
        'overflow:hidden;background-color:#ffffff;">'
        f'<tr><td style="background-color:{accent};height:4px;line-height:4px;font-size:0;">&nbsp;</td></tr>'
        '<tr><td style="background-color:#0f172a;padding:16px 20px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;letter-spacing:1px;'
        'color:#e2e8f0;">GCP AUDIT PLATFORM</td>'
        f'<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;color:#64748b;">'
        f"Alert: {html.escape(alert_id)} &middot; {html.escape(generated_at)}</td></tr></table></td></tr>"
        '<tr><td style="padding:24px 20px 20px 20px;">'
        f"{_render_severity_badge(severity, accent)}"
        f'<div style="font-family:Arial,sans-serif;font-size:22px;font-weight:bold;color:#0f172a;'
        f'margin-top:10px;">{plain_title}</div>'
        '<div style="font-family:Arial,sans-serif;font-size:12px;color:#94a3b8;margin-top:4px;">'
        f"Rule: {rule_id_e}</div>"
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:14px;'
        f'border-left:3px solid {accent};background-color:#f8fafc;">'
        '<tr><td style="padding:12px 16px;font-family:Arial,sans-serif;font-size:14px;color:#334155;'
        f'line-height:1.6;">{summary_e}</td></tr></table>'
        "</td></tr>"
        '<tr><td style="padding:0 20px 16px 20px;">'
        '<div style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;letter-spacing:0.08em;'
        'color:#94a3b8;text-transform:uppercase;margin-bottom:8px;">Business Impact</div>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>{impact_html}'
        "</tr></table></td></tr>"
        f"{cards_html}{change_html}{ai_html}{buttons_html}"
        '<tr><td style="padding:14px 20px;border-top:1px solid #e2e8f0;background-color:#f8fafc;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;color:#64748b;">'
        "GCP Audit Platform &middot; Automated &middot; Do not reply</td>"
        f'<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;color:{accent};'
        f'font-weight:bold;">{html.escape(str(severity))}</td>'
        "</tr></table></td></tr>"
        "</table>"
    )


# -----------------------------------------------------------------------
# Template E -- Engineer Detail. firewall_open_to_internet,
# service_account_key_created. Technical detail + copy-pasteable
# remediation commands derived from this finding's own real fields.
# -----------------------------------------------------------------------


def _render_template_e(
    *,
    severity: str,
    accent: str,
    tint: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    mute_url: str | None,
    generated_at: str,
    alert_id: str,
) -> str:
    title_e = html.escape(str(title))
    rule_id_e = html.escape(str(rule_id))

    sections = _group_fields_into_sections(fields)
    detail_rows = [row for name, rows in sections if name != "Change Detail" for row in rows]
    zebra_rows = []
    for idx, (key, value) in enumerate(detail_rows):
        bg = "#ffffff" if idx % 2 == 0 else "#f8fafc"
        value_html = (
            _render_nested_value(value) if isinstance(value, Mapping | list | tuple) else _escape_scalar(value)
        )
        zebra_rows.append(
            "<tr>"
            f'<td class="ea-key" style="padding:8px 12px;background-color:{bg};border-bottom:1px solid #e2e8f0;'
            'font-family:Arial,sans-serif;font-size:14px;font-weight:bold;color:#0f172a;width:35%;">'
            f"{html.escape(str(key))}</td>"
            f'<td class="ea-val" style="padding:8px 12px;background-color:{bg};border-bottom:1px solid #e2e8f0;'
            f'font-family:monospace;font-size:13px;color:#0f172a;">{value_html}</td>'
            "</tr>"
        )
    zebra_html = ""
    if zebra_rows:
        zebra_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #e2e8f0;">' + "".join(zebra_rows) + "</table></td></tr>"
        )

    firewall_html = ""
    if rule_id == "firewall_open_to_internet":
        detail = _firewall_config_detail(fields)
        if detail:
            firewall_rows: list[tuple[str, Any]] = []
            if detail["source_ranges"]:
                firewall_rows.append(("Source ranges", detail["source_ranges"]))
            if detail["allowed"]:
                firewall_rows.append(("Allowed", detail["allowed"]))
            if detail["target_tags"]:
                firewall_rows.append(("Target tags", detail["target_tags"]))
            if firewall_rows:
                firewall_html = (
                    '<tr><td style="padding:16px 20px 0 20px;">'
                    '<div style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;'
                    'letter-spacing:0.08em;color:#94a3b8;text-transform:uppercase;margin-bottom:8px;">'
                    "Firewall Configuration</div>"
                    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                    f'style="border:1px solid #e2e8f0;">{_render_field_rows(firewall_rows, "#f8fafc")}</table>'
                    "</td></tr>"
                )

    sa_key_html = ""
    if rule_id == "service_account_key_created":
        notes = _sa_key_risk_notes(fields)
        if notes:
            notes_rows = "".join(
                f'<div style="padding:4px 0;font-family:Arial,sans-serif;font-size:13px;color:#334155;'
                f'line-height:1.5;">&bull; {html.escape(n)}</div>'
                for n in notes
            )
            sa_key_html = (
                '<tr><td style="padding:16px 20px 0 20px;">'
                '<div style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;'
                'letter-spacing:0.08em;color:#94a3b8;text-transform:uppercase;margin-bottom:8px;">'
                "Key Risk Notes</div>"
                f"{notes_rows}</td></tr>"
            )

    tag_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#3b82f6"}
    indicators = _detect_indicators(fields)
    ioc_html = ""
    if indicators:
        rows = "".join(
            '<tr><td style="padding:6px 0;border-bottom:1px dashed #fde68a;">'
            f'<span style="display:inline-block;padding:2px 8px;border-radius:8px;'
            f'background-color:{tag_colors.get(tag, "#64748b")};color:#ffffff;'
            f'font-family:Arial,sans-serif;font-size:11px;font-weight:bold;margin-right:8px;">'
            f"{html.escape(tag)}</span>"
            f'<span style="font-family:Arial,sans-serif;font-size:13px;color:#78350f;">'
            f"{html.escape(desc)}</span></td></tr>"
            for tag, desc in indicators
        )
        ioc_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #fde68a;border-radius:6px;background-color:#fffbeb;">'
            '<tr><td style="padding:10px 14px 4px 14px;font-family:Arial,sans-serif;font-size:12px;'
            'font-weight:bold;letter-spacing:0.06em;color:#92400e;text-transform:uppercase;">'
            "Risk Indicators</td></tr>"
            '<tr><td style="padding:0 14px 8px 14px;"><table role="presentation" width="100%" '
            f'cellpadding="0" cellspacing="0">{rows}</table></td></tr>'
            "</table></td></tr>"
        )

    ai_html = ""
    if ai_analysis:
        ai_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="border:1px solid #bbf7d0;border-radius:6px;background-color:#f0fdf4;">'
            '<tr><td style="padding:12px 16px;font-family:Arial,sans-serif;font-size:14px;'
            'color:#14532d;line-height:1.75;">'
            '<strong style="display:block;margin-bottom:6px;">&#10022; Gemini AI Analysis</strong>'
            f"{_render_ai_text(ai_analysis)}</td></tr></table></td></tr>"
        )

    commands = (
        _firewall_remediation_commands(fields)
        if rule_id == "firewall_open_to_internet"
        else _sa_key_remediation_commands(fields)
        if rule_id == "service_account_key_created"
        else []
    )
    remediation_html = ""
    if commands:
        command_rows = "".join(_render_code_block(label, cmd) for label, cmd in commands)
        remediation_html = (
            '<tr><td style="padding:16px 20px 0 20px;">'
            '<div style="font-family:Arial,sans-serif;font-size:11px;font-weight:bold;'
            'letter-spacing:0.08em;color:#94a3b8;text-transform:uppercase;margin-bottom:8px;">'
            "Remediation Commands</div>"
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{command_rows}</table>'
            "</td></tr>"
        )

    buttons_html = _render_cta_row(
        [
            ("Open Cloud Console", console_url, "#0f172a", "#ffffff", "#0f172a"),
            ("IAM Policy", _iam_console_url(fields), "#ffffff", accent, accent),
            ("Mute this alert", mute_url, "#ffffff", "#b45309", "#fbbf24"),
        ]
    )

    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="max-width:620px;font-family:Arial,sans-serif;border:1px solid #e2e8f0;border-radius:10px;'
        'overflow:hidden;background-color:#ffffff;">'
        '<tr><td style="background-color:#0f172a;padding:10px 20px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;font-weight:bold;color:#ffffff;">'
        "GCP AUDIT PLATFORM</td>"
        f'<td style="text-align:right;font-family:Arial,sans-serif;font-size:12px;color:#94a3b8;">'
        f"{html.escape(alert_id)}</td></tr></table></td></tr>"
        f'<tr><td style="padding:16px 20px;background-color:{tint};border-bottom:3px solid {accent};">'
        f"{_render_severity_badge(severity, accent)}"
        f'<div style="font-family:Arial,sans-serif;font-size:18px;font-weight:bold;color:#0f172a;'
        f'margin-top:8px;">{title_e}</div>'
        '<div style="font-family:Arial,sans-serif;font-size:13px;color:#475569;margin-top:2px;">'
        f"Rule: {rule_id_e} &middot; {html.escape(generated_at)}</div>"
        f'<div style="font-family:Arial,sans-serif;font-size:14px;color:#0f172a;margin-top:10px;'
        f'line-height:1.5;">{html.escape(_plain_english_summary(fields))}</div>'
        "</td></tr>"
        f"{zebra_html}{firewall_html}{sa_key_html}{ioc_html}{ai_html}{remediation_html}{buttons_html}"
        '<tr><td style="padding:14px 20px;border-top:1px solid #e2e8f0;background-color:#f8fafc;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        '<td style="font-family:Arial,sans-serif;font-size:12px;color:#64748b;">'
        "GCP Audit Platform &middot; Automated &middot; Do not reply</td>"
        '<td style="text-align:right;"><span style="display:inline-block;padding:2px 8px;'
        'border-radius:8px;background-color:#eff6ff;color:#3b82f6;font-family:Arial,sans-serif;'
        f'font-size:11px;font-weight:bold;">{rule_id_e}</span></td>'
        "</tr></table></td></tr>"
        "</table>"
    )


def _render_text(
    *,
    severity: str,
    title: str,
    rule_id: str,
    fields: list[tuple[str, Any]],
    ai_analysis: str | None,
    console_url: str | None,
    mute_url: str | None,
    generated_at: str,
    alert_id: str,
) -> str:
    lines = [
        f"[{severity}] {title}",
        f"Rule: {rule_id}",
        f"Alert ID: {alert_id}",
        "",
        _plain_english_summary(fields),
        "",
    ]
    sections = _group_fields_into_sections(fields)
    if sections:
        for name, rows in sections:
            lines.append(f"-- {name} --")
            # A raw datetime (event_timestamp) needs the same IST
            # conversion _escape_scalar applies for the HTML body --
            # otherwise the plain-text body falls back to str(datetime)'s
            # default UTC-with-microseconds form while the HTML body next
            # to it shows IST, an inconsistency between the two parts of
            # the same MIME message.
            lines.extend(
                f"  {key}: {_format_event_time_ist(value) if isinstance(value, datetime) else value}"
                for key, value in rows
            )
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
    if mute_url and _is_safe_url(mute_url):
        lines.append(f"Mute this alert (admin access required): {mute_url}")
        lines.append("")
    lines.append(f"Generated: {generated_at}")
    lines.append("This is an automated message, do not reply.")
    return "\n".join(lines)
