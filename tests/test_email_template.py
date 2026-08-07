from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src import email_template
from src.email_template import (
    _FALLBACK_ACCENT,
    _FALLBACK_TINT,
    _alert_id,
    _detect_indicators,
    _format_timestamp,
    _is_rfc1918,
    _select_template,
    _severity_colors,
    _severity_style,
    render_alert,
)


@pytest.fixture(autouse=True)
def _use_test_routing_config(monkeypatch: pytest.MonkeyPatch, routing_yaml_path) -> None:
    monkeypatch.setattr(email_template, "CONFIG_PATH", routing_yaml_path)


def test_severity_styling_lookup() -> None:
    config = email_template.load_routing_config()
    accent, tint = _severity_style("CRITICAL", config)
    assert accent == "#ef4444"
    assert tint == "#fef2f2"


def test_unknown_severity_falls_back_without_raising() -> None:
    config = email_template.load_routing_config()
    accent, tint = _severity_style("SOMETHING_MADE_UP", config)
    assert accent == _FALLBACK_ACCENT
    assert tint == _FALLBACK_TINT


def test_unknown_severity_in_routing_end_to_end() -> None:
    subject, html_body, text_body = render_alert(
        rule_id="R1", severity="NOT_A_REAL_SEVERITY", title="Title", fields={}
    )
    assert _FALLBACK_ACCENT in html_body
    assert "NOT_A_REAL_SEVERITY" in subject


def test_html_injection_in_field_value_is_escaped() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="CRITICAL",
        title="Title",
        fields={"actor": "<script>alert(1)</script>"},
    )
    assert "<script>alert(1)</script>" not in html_body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_body


def test_none_empty_and_empty_list_fields_are_omitted() -> None:
    _subject, html_body, text_body = render_alert(
        rule_id="R1",
        severity="CRITICAL",
        title="Title",
        fields={"skip_none": None, "skip_empty_str": "", "skip_empty_list": [], "keep_me": "value"},
    )
    for omitted in ("skip_none", "skip_empty_str", "skip_empty_list"):
        assert omitted not in html_body
        assert omitted not in text_body
    assert "keep_me" in html_body
    assert "value" in html_body


def test_subject_format() -> None:
    subject, _html_body, _text_body = render_alert(
        rule_id="RULE-42", severity="HIGH", title="Something Bad Happened", fields={}
    )
    assert subject == "[HIGH] Something Bad Happened - RULE-42"


def test_nested_list_of_dicts_renders_as_table_not_repr() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={
            "IAM Binding Changes (Delta)": [
                {"action": "ADD", "role": "roles/editor", "member": "user:alice@example.com"}
            ]
        },
    )
    # A raw Python repr would read "[{'action': 'ADD', ...". Confirm that's gone
    # and the value instead rendered as its own nested <table>.
    assert "[{'action'" not in html_body
    assert html_body.count("<table") >= 2
    assert "action" in html_body
    assert "ADD" in html_body
    assert "roles/editor" in html_body


def test_nested_dict_renders_as_table() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={"Requested Policy": {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}},
    )
    assert "{'bindings'" not in html_body
    assert "bindings" in html_body
    assert "allUsers" in html_body


def test_html_injection_in_nested_value_is_escaped() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={"Delegation Chain": [{"principalSubject": "<img src=x onerror=alert(1)>"}]},
    )
    assert "<img src=x onerror=alert(1)>" not in html_body
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_body


def test_fields_grouped_into_labeled_sections() -> None:
    _subject, html_body, text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={
            "Principal": "alice@example.com",
            "Event Time (UTC)": "2026-08-05T12:00:00+00:00",
            "Method": "SetIamPolicy",
            "Caller IP": "203.0.113.10",
            "Requested Policy": {"bindings": []},
        },
    )
    # text-transform:uppercase is CSS-only -- the underlying escaped text stays
    # title-case, so assert on that rather than the rendered-visual casing.
    for section in ("Who</td>", "When</td>", "What</td>", "Where From</td>", "Change Detail</td>"):
        assert section in html_body
    for section in ("-- Who --", "-- When --", "-- What --", "-- Where From --", "-- Change Detail --"):
        assert section in text_body


def test_unmapped_field_label_still_renders_in_details_section() -> None:
    _subject, html_body, text_body = render_alert(
        rule_id="R1", severity="HIGH", title="Title", fields={"Some Future Field": "value123"}
    )
    assert "Details</td>" in html_body
    assert "Some Future Field" in html_body
    assert "value123" in html_body
    assert "-- Details --" in text_body


def test_empty_nested_dict_and_list_render_without_raising() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={"Outer": {"empty_dict": {}, "empty_list": [], "scalar": "x"}},
    )
    assert "(empty)" in html_body
    assert "scalar" in html_body


# --- template selection -------------------------------------------------


def test_select_template_rule_id_overrides_beat_severity() -> None:
    assert _select_template("CRITICAL", "public_iam_grant") == "B"
    assert _select_template("MEDIUM", "public_iam_grant") == "B"  # override wins even at low severity
    assert _select_template("LOW", "firewall_open_to_internet") == "A"
    assert _select_template("LOW", "service_account_key_created") == "A"


def test_select_template_severity_fallback() -> None:
    assert _select_template("CRITICAL", "some_other_rule") == "B"
    assert _select_template("HIGH", "some_other_rule") == "A"
    assert _select_template("MEDIUM", "some_other_rule") == "C"
    assert _select_template("LOW", "some_other_rule") == "C"
    assert _select_template("INFO", "some_other_rule") == "C"


# --- real helpers, no fabricated data ------------------------------------


def test_is_rfc1918() -> None:
    assert _is_rfc1918("10.1.2.3") is True
    assert _is_rfc1918("172.16.0.5") is True
    assert _is_rfc1918("192.168.1.1") is True
    assert _is_rfc1918("203.0.113.10") is False  # public TEST-NET-3 range
    assert _is_rfc1918("not-an-ip") is False


def test_format_timestamp_from_datetime() -> None:
    dt = datetime(2026, 8, 7, 6, 19, 30, tzinfo=UTC)
    assert _format_timestamp(dt) == "2026-08-07 06:19:30 UTC"


def test_format_timestamp_from_iso_string() -> None:
    assert _format_timestamp("2026-08-07T06:19:30+00:00") == "2026-08-07 06:19:30 UTC"


def test_format_timestamp_never_raises_on_garbage() -> None:
    assert _format_timestamp("not a timestamp") == "not a timestamp"
    assert _format_timestamp(None) == "None"


def test_alert_id_format() -> None:
    now = datetime(2026, 8, 7, 6, 19, 30, tzinfo=UTC)
    assert _alert_id("public_iam_grant", now) == "AUD-20260807-PUBL"
    assert _alert_id("", now) == "AUD-20260807-RULE"


def test_severity_colors_reads_from_routing_config() -> None:
    colors = _severity_colors("CRITICAL")
    assert colors == {"accent": "#ef4444", "tint": "#fef2f2"}


# --- markdown-lite bold rendering (the bug seen in real emails) ---------


def test_ai_analysis_markdown_bold_renders_as_strong() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={},
        ai_analysis="This is bad. **Recommended action:** revoke it now.",
    )
    assert "**Recommended action:**" not in html_body
    assert "<strong>Recommended action:</strong>" in html_body


def test_ai_analysis_bold_conversion_does_not_reintroduce_html_injection() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={},
        ai_analysis="**<script>alert(1)</script>**",
    )
    assert "<script>alert(1)</script>" not in html_body
    assert "<strong>&lt;script&gt;alert(1)&lt;/script&gt;</strong>" in html_body


# --- indicators of concern (Template B), derived only from real fields --


def test_detect_indicators_public_grant() -> None:
    indicators = _detect_indicators([("Requested Policy", {"bindings": [{"members": ["allUsers"]}]})])
    tags = [tag for tag, _desc in indicators]
    assert "CRITICAL" in tags


def test_detect_indicators_non_private_ip() -> None:
    indicators = _detect_indicators([("Caller IP", "203.0.113.10")])
    assert any(tag == "HIGH" and "not in a private" in desc for tag, desc in indicators)


def test_detect_indicators_private_ip_not_flagged() -> None:
    indicators = _detect_indicators([("Caller IP", "10.0.0.5")])
    assert not any("not in a private" in desc for _tag, desc in indicators)


def test_detect_indicators_destructive_method() -> None:
    indicators = _detect_indicators([("Method", "google.iam.admin.v1.DeleteServiceAccount")])
    assert any("destructive" in desc for _tag, desc in indicators)


def test_detect_indicators_empty_for_no_fields() -> None:
    assert _detect_indicators([]) == []


# --- per-template rendering + the Template B completeness fix -----------


def test_template_a_renders_dark_executive_header() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="firewall_open_to_internet", severity="LOW", title="Title", fields={}
    )
    assert "#0f172a" in html_body
    assert "GCP AUDIT PLATFORM" in html_body


def test_template_b_renders_soc_header_and_ioc_box() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="public_iam_grant",
        severity="CRITICAL",
        title="Title",
        fields={"Requested Policy": {"bindings": [{"members": ["allUsers"]}]}},
    )
    assert "GCP AUDIT PLATFORM" in html_body
    assert "Indicators of Concern" in html_body


def test_template_b_does_not_drop_change_detail_or_unmapped_fields() -> None:
    """Regression test: Template B originally only rendered Who/When and
    What/Where From, silently dropping Change Detail and any unmapped field
    -- exactly the data a CRITICAL/public_iam_grant alert most needs.
    """
    _subject, html_body, _text_body = render_alert(
        rule_id="public_iam_grant",
        severity="CRITICAL",
        title="Title",
        fields={
            "Requested Policy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
            "Some Future Field": "must-not-vanish",
        },
    )
    assert "roles/storage.objectViewer" in html_body
    assert "must-not-vanish" in html_body


def test_template_c_renders_clean_enterprise_header() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="some_other_rule", severity="MEDIUM", title="Title", fields={}, ai_analysis="analysis text"
    )
    assert "GCP Audit Platform" in html_body
    assert "AI-analysed" in html_body


def test_iam_policy_button_only_appears_when_project_field_present() -> None:
    _subject, html_body_without, _text_body = render_alert(
        rule_id="r", severity="LOW", title="Title", fields={}
    )
    assert "IAM Policy" not in html_body_without

    _subject, html_body_with, _text_body = render_alert(
        rule_id="r", severity="LOW", title="Title", fields={"Project": "prj-dg-devops-test"}
    )
    assert "IAM Policy" in html_body_with
    assert "iam-admin/iam?project=prj-dg-devops-test" in html_body_with


def test_console_button_omitted_when_url_missing() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="r", severity="LOW", title="Title", fields={}, console_url=None
    )
    assert "Open Cloud Console" not in html_body


def test_all_three_templates_escape_html_injection() -> None:
    for severity, rule_id in (("HIGH", "firewall_open_to_internet"), ("CRITICAL", "public_iam_grant"), ("LOW", "x")):
        _subject, html_body, _text_body = render_alert(
            rule_id=rule_id,
            severity=severity,
            title="Title",
            fields={"Some Future Field": "<script>alert(1)</script>"},
            ai_analysis="**<img src=x onerror=alert(1)>**",
        )
        assert "<script>alert(1)</script>" not in html_body
        assert "<img src=x onerror=alert(1)>" not in html_body
