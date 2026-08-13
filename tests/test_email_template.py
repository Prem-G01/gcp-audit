from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src import email_template
from src.email_template import (
    _FALLBACK_ACCENT,
    _FALLBACK_TINT,
    _alert_id,
    _business_impact,
    _detect_indicators,
    _firewall_config_detail,
    _firewall_remediation_commands,
    _format_timestamp,
    _is_rfc1918,
    _plain_english_summary,
    _plain_english_title,
    _prettify_key,
    _resource_name_segment,
    _sa_key_remediation_commands,
    _sa_key_risk_notes,
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


def test_subject_format_without_identifier() -> None:
    subject, _html_body, _text_body = render_alert(
        rule_id="RULE-42", severity="HIGH", title="Something Bad Happened", fields={}
    )
    assert subject == "[HIGH] Something Bad Happened (RULE-42)"


def test_subject_format_includes_resource_identifier() -> None:
    subject, _html_body, _text_body = render_alert(
        rule_id="resource_created",
        severity="HIGH",
        title="Resource created",
        fields={"Resource": "projects/p/zones/z/instances/my-test-vm"},
    )
    assert subject == "[HIGH] Resource created — my-test-vm (resource_created)"


def test_subject_identifier_falls_back_to_project_when_no_resource_field() -> None:
    subject, _html_body, _text_body = render_alert(
        rule_id="project_created", severity="HIGH", title="New GCP project created", fields={"Project": "prj-abc"}
    )
    assert subject == "[HIGH] New GCP project created — prj-abc (project_created)"


def test_two_different_events_never_produce_identical_subjects() -> None:
    subject_a, _h, _t = render_alert(
        rule_id="resource_created",
        severity="HIGH",
        title="Resource created",
        fields={"Resource": "projects/p/zones/z/instances/vm-one"},
    )
    subject_b, _h, _t = render_alert(
        rule_id="resource_created",
        severity="HIGH",
        title="Resource created",
        fields={"Resource": "projects/p/zones/z/instances/vm-two"},
    )
    assert subject_a != subject_b


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
    # and the value instead rendered as its own nested <table>, with the raw
    # API key relabeled for readability ("action" -> "Action").
    assert "[{'action'" not in html_body
    assert html_body.count("<table") >= 2
    assert "Action" in html_body
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
    assert "Bindings" in html_body
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
    assert "Scalar" in html_body


def test_very_long_scalar_value_is_truncated() -> None:
    """A single oversized field value (a real audit log field can legitimately
    be a multi-KB blob) must not blow the whole email up -- truncated with a
    visible "chars total" marker instead of rendered in full.
    """
    huge_value = "x" * 5000
    _subject, html_body, _text_body = render_alert(
        rule_id="R1", severity="HIGH", title="Title", fields={"Some Field": huge_value}
    )
    assert "x" * 5000 not in html_body
    assert "(5000 chars total)" in html_body


def test_truncation_does_not_split_an_html_entity() -> None:
    """Truncating must happen on the raw string BEFORE html.escape() -- doing
    it after could cut an entity reference in half (e.g. "&amp;" -> "&am"),
    producing broken markup.
    """
    # Place a literal "&" right at the truncation boundary.
    value = ("y" * (500 - 1)) + "&" + ("z" * 100)
    _subject, html_body, _text_body = render_alert(
        rule_id="R1", severity="HIGH", title="Title", fields={"Some Field": value}
    )
    # A split entity would leave a bare "&am" or similar with no ";" -- confirm
    # the escaped ampersand is either whole ("&amp;") or was cut before it,
    # never mangled.
    assert "&am " not in html_body
    assert "&amz" not in html_body


def test_long_list_is_capped_with_a_remaining_count() -> None:
    """A list with more items than _MAX_LIST_ITEMS renders only the cap, plus
    a visible "and N more" marker -- not all of them.
    """
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="HIGH",
        title="Title",
        fields={"Tags": [f"tag-{i}" for i in range(30)]},
    )
    assert "tag-0" in html_body
    assert "tag-19" in html_body
    assert "tag-20" not in html_body
    assert "and 10 more" in html_body


def test_short_list_is_not_capped() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="R1", severity="HIGH", title="Title", fields={"Tags": ["a", "b", "c"]}
    )
    assert "more</div>" not in html_body


def test_html_body_is_a_full_document_with_charset_and_viewport() -> None:
    _subject, html_body, _text_body = render_alert(rule_id="R1", severity="HIGH", title="Title", fields={})
    assert html_body.startswith("<!doctype html>")
    assert '<meta charset="utf-8">' in html_body
    assert '<meta name="viewport" content="width=device-width, initial-scale=1.0">' in html_body
    assert html_body.rstrip().endswith("</html>")


def test_html_body_includes_hidden_preheader_matching_severity_and_title() -> None:
    """The preheader is the inbox-list preview snippet shown next to the
    subject, before the email is opened -- must be present and hidden
    (never visible in the rendered body itself).
    """
    _subject, html_body, _text_body = render_alert(
        rule_id="R1", severity="HIGH", title="Suspicious activity detected", fields={}
    )
    assert "display:none" in html_body
    assert "HIGH: Suspicious activity detected" in html_body


def test_html_document_declares_light_only_color_scheme() -> None:
    """Every color in every template is hardcoded per-severity, never
    theme-aware -- these meta tags stop a client's automatic dark-mode
    inversion from selectively flipping some hardcoded colors and not
    others, which would break contrast in ways the templates never designed
    for.
    """
    _subject, html_body, _text_body = render_alert(rule_id="R1", severity="HIGH", title="Title", fields={})
    assert '<meta name="color-scheme" content="light">' in html_body
    assert '<meta name="supported-color-schemes" content="light">' in html_body


def test_dotted_annotation_key_renders_verbatim_not_mangled() -> None:
    """Kubernetes-style annotation keys (which Cloud Run's request objects
    carry, e.g. from an UpdateService call) aren't camelCase/snake_case --
    running the word-splitting prettifier on them produced mangled output
    ("Autoscaling.knative.dev/max Scale") that was less readable than the
    original, not more. Must render verbatim instead.
    """
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="LOW",
        title="Title",
        fields={"Requested Change": {"autoscaling.knative.dev/maxScale": "2"}},
    )
    assert "autoscaling.knative.dev/maxScale" in html_body
    assert "Autoscaling.knative.dev/max Scale" not in html_body


def test_nested_object_indentation_increases_visibly_with_depth() -> None:
    """The original 6px-per-level indent was imperceptible past 2 levels
    deep -- real GCP request shapes (Spec > Template > Containers >
    Resources) commonly nest 3-4 levels, which read as one flat wall of
    key/value pairs rather than a traceable hierarchy. Confirm indentation
    now visibly compounds per level.
    """
    _subject, html_body, _text_body = render_alert(
        rule_id="R1",
        severity="LOW",
        title="Title",
        fields={"Requested Change": {"a": {"b": {"c": "deep value"}}}},
    )
    assert "padding-left:14px" in html_body
    assert "deep value" in html_body


def test_prettify_key_camel_case() -> None:
    assert _prettify_key("principalSubject") == "Principal Subject"
    assert _prettify_key("sourceRanges") == "Source Ranges"
    assert _prettify_key("role") == "Role"


def test_prettify_key_snake_case() -> None:
    assert _prettify_key("billing_account_name") == "Billing Account Name"


def test_prettify_key_preserves_acronym_casing() -> None:
    assert _prettify_key("IPProtocol") == "IP Protocol"


def test_prettify_key_empty_string_returns_unchanged() -> None:
    assert _prettify_key("") == ""


def test_prettify_key_returns_dotted_slashed_key_verbatim() -> None:
    assert _prettify_key("autoscaling.knative.dev/maxScale") == "autoscaling.knative.dev/maxScale"


# -----------------------------------------------------------------------
# Plain-English summary -- one jargon-free sentence, on every template
# (not just D), derived only from real field data, never fabricated.
# -----------------------------------------------------------------------


def test_plain_english_summary_with_principal_resource_and_project() -> None:
    fields = [("Principal", "alice@example.com"), ("Resource", "projects/p/disks/d1"), ("Project", "prj-a")]
    assert _plain_english_summary(fields) == (
        "alice@example.com made a change to projects/p/disks/d1 in project prj-a."
    )


def test_plain_english_summary_falls_back_when_principal_missing() -> None:
    fields = [("Resource", "projects/p/disks/d1")]
    assert _plain_english_summary(fields) == "A change was made to projects/p/disks/d1."


def test_plain_english_summary_with_no_matching_fields_at_all() -> None:
    assert _plain_english_summary([]) == "A change was made."


@pytest.mark.parametrize(
    ("rule_id", "severity", "expected_template"),
    [
        ("public_iam_grant", "CRITICAL", "D"),
        ("firewall_open_to_internet", "CRITICAL", "E"),
        ("iam_policy_change", "HIGH", "B"),
        ("project_created", "HIGH", "A"),
        ("unclassified_admin_activity", "LOW", "C"),
    ],
)
def test_plain_english_summary_appears_on_every_template(rule_id, severity, expected_template) -> None:
    """The summary line must render on all 5 layouts, not just D -- this
    parametrization forces each one via its real rule_id/severity mapping
    (see _select_template) so the assertion actually exercises each
    template's own header code, not just whichever one the default
    severity/rule_id in other tests happens to select.
    """
    assert _select_template(severity, rule_id) == expected_template
    _subject, html_body, text_body = render_alert(
        rule_id=rule_id,
        severity=severity,
        title="Title",
        fields={"Principal": "alice@example.com", "Resource": "some-resource", "Project": "prj-a"},
    )
    assert "alice@example.com made a change to some-resource in project prj-a." in html_body
    assert "alice@example.com made a change to some-resource in project prj-a." in text_body


# --- template selection -------------------------------------------------


def test_select_template_rule_id_overrides_beat_severity() -> None:
    # Overrides win even at a severity that would otherwise route elsewhere.
    assert _select_template("MEDIUM", "public_iam_grant") == "D"
    assert _select_template("MEDIUM", "billing_account_changed") == "D"
    assert _select_template("LOW", "firewall_open_to_internet") == "E"
    assert _select_template("LOW", "service_account_key_created") == "E"
    assert _select_template("LOW", "iam_policy_change") == "B"
    assert _select_template("LOW", "audit_config_changed") == "B"
    assert _select_template("LOW", "org_policy_modified") == "B"
    assert _select_template("LOW", "federated_identity_action") == "B"
    assert _select_template("LOW", "project_created") == "A"


def test_select_template_all_twelve_shipped_rules() -> None:
    """Every real rule id in config/rules.yaml maps to a real template --
    catches drift if a rule is renamed/added without updating this module.
    resource_created/resource_deleted have no rule-id-specific override,
    so they fall through to the HIGH severity default (A) -- confirming
    that fallback still applies correctly for rules added after the fact.
    """
    expected = {
        "iam_policy_change": "B",
        "service_account_key_created": "E",
        "org_policy_modified": "B",
        "firewall_open_to_internet": "E",
        "public_iam_grant": "D",
        "audit_config_changed": "B",
        "unclassified_admin_activity": "C",
        "federated_identity_action": "B",
        "project_created": "A",
        "billing_account_changed": "D",
        "resource_created": "A",
        "resource_deleted": "A",
    }
    severities = {
        "iam_policy_change": "HIGH",
        "service_account_key_created": "HIGH",
        "org_policy_modified": "HIGH",
        "firewall_open_to_internet": "CRITICAL",
        "public_iam_grant": "CRITICAL",
        "audit_config_changed": "HIGH",
        "unclassified_admin_activity": "LOW",
        "federated_identity_action": "HIGH",
        "project_created": "HIGH",
        "billing_account_changed": "CRITICAL",
        "resource_created": "HIGH",
        "resource_deleted": "HIGH",
    }
    for rule_id, template in expected.items():
        assert _select_template(severities[rule_id], rule_id) == template, rule_id


def test_select_template_severity_fallback() -> None:
    # Unmapped rule ids: CRITICAL never silently lands on the plainest
    # template (C) -- it always escalates to D, the executive layout.
    assert _select_template("CRITICAL", "some_other_rule") == "D"
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
        rule_id="project_created", severity="HIGH", title="Title", fields={}
    )
    assert "#0f172a" in html_body
    assert "GCP AUDIT PLATFORM" in html_body


def test_template_b_renders_soc_header_and_ioc_box() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="iam_policy_change",
        severity="HIGH",
        title="Title",
        fields={"Requested Policy": {"bindings": [{"members": ["allUsers"]}]}},
    )
    assert "GCP AUDIT PLATFORM" in html_body
    assert "Indicators of Concern" in html_body


def test_template_b_does_not_drop_change_detail_or_unmapped_fields() -> None:
    """Regression test: Template B originally only rendered Who/When and
    What/Where From, silently dropping Change Detail and any unmapped field.
    """
    _subject, html_body, _text_body = render_alert(
        rule_id="audit_config_changed",
        severity="HIGH",
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


def test_all_five_templates_escape_html_injection() -> None:
    cases = (
        ("HIGH", "project_created"),  # A
        ("HIGH", "iam_policy_change"),  # B
        ("LOW", "x"),  # C
        ("CRITICAL", "public_iam_grant"),  # D
        ("CRITICAL", "firewall_open_to_internet"),  # E
    )
    for severity, rule_id in cases:
        _subject, html_body, _text_body = render_alert(
            rule_id=rule_id,
            severity=severity,
            title="Title",
            fields={"Some Future Field": "<script>alert(1)</script>"},
            ai_analysis="**<img src=x onerror=alert(1)>**",
        )
        assert "<script>alert(1)</script>" not in html_body
        assert "<img src=x onerror=alert(1)>" not in html_body


# --- Template D: Executive Summary (public_iam_grant, billing_account_changed) --


def test_plain_english_title_known_rule() -> None:
    assert _plain_english_title("public_iam_grant", "raw title") == (
        "Public internet access granted to a cloud resource"
    )


def test_plain_english_title_falls_back_to_real_title_for_unknown_rule() -> None:
    assert _plain_english_title("some_future_rule", "The Real Title") == "The Real Title"


def test_business_impact_known_vs_default() -> None:
    assert _business_impact("public_iam_grant") == (
        "Data may be publicly exposed",
        "Possible compliance violation",
        "Review access immediately",
    )
    assert _business_impact("unmapped_rule") == (
        "Security-relevant change",
        "May affect compliance posture",
        "Review recommended",
    )


def test_template_d_renders_plain_english_title_and_business_impact() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="public_iam_grant",
        severity="CRITICAL",
        title="raw internal title",
        fields={"Principal": "alice@example.com", "Resource": "projects/_/buckets/x", "Project": "prj-1"},
    )
    assert "Public internet access granted to a cloud resource" in html_body
    assert "Data may be publicly exposed" in html_body
    assert "alice@example.com made a change to projects/_/buckets/x in project prj-1" in html_body


def test_template_d_used_for_billing_account_changed() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="billing_account_changed", severity="CRITICAL", title="Title", fields={}
    )
    assert "Billing account linked or modified" in html_body


# --- Template E: Engineer Detail (firewall_open_to_internet, service_account_key_created) --


def test_resource_name_segment() -> None:
    assert _resource_name_segment("projects/p/global/firewalls/allow-all", "firewalls") == "allow-all"
    assert _resource_name_segment("projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/abc123", "keys") == (
        "abc123"
    )
    resource = "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/abc123"
    assert _resource_name_segment(resource, "serviceAccounts") == "sa@p.iam.gserviceaccount.com"
    assert _resource_name_segment("no/marker/here", "firewalls") is None
    assert _resource_name_segment(None, "firewalls") is None


def test_firewall_remediation_commands_derived_from_real_fields() -> None:
    commands = _firewall_remediation_commands(
        [("Firewall Rule", "projects/prj-1/global/firewalls/allow-all-ingress"), ("Project", "prj-1")]
    )
    assert len(commands) == 3
    assert any("allow-all-ingress" in cmd and "--project=prj-1" in cmd for _label, cmd in commands)
    assert any(cmd.startswith("gcloud compute firewall-rules update") and "--disabled" in cmd for _l, cmd in commands)


def test_firewall_remediation_commands_empty_without_real_data() -> None:
    assert _firewall_remediation_commands([]) == []


def test_sa_key_remediation_commands_derived_from_real_fields() -> None:
    resource = "projects/prj-1/serviceAccounts/svc@prj-1.iam.gserviceaccount.com/keys/deadbeef"
    commands = _sa_key_remediation_commands([("Service Account", resource), ("Project", "prj-1")])
    assert any("deadbeef" in cmd for _label, cmd in commands)
    assert any("svc@prj-1.iam.gserviceaccount.com" in cmd for _label, cmd in commands)


def test_sa_key_remediation_commands_empty_without_sa_email() -> None:
    assert _sa_key_remediation_commands([]) == []


def test_firewall_config_detail_extracts_real_values() -> None:
    detail = _firewall_config_detail(
        [("Requested Firewall Config", {"sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp"}]})]
    )
    assert detail == {"source_ranges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp"}], "target_tags": None}


def test_firewall_config_detail_none_when_absent_or_wrong_shape() -> None:
    assert _firewall_config_detail([]) is None
    assert _firewall_config_detail([("Requested Firewall Config", "not a dict")]) is None


def test_sa_key_risk_notes_flags_non_private_ip() -> None:
    notes = _sa_key_risk_notes([("Caller IP", "203.0.113.10")])
    assert any("203.0.113.10" in n for n in notes)


def test_sa_key_risk_notes_always_has_baseline_note() -> None:
    notes = _sa_key_risk_notes([])
    assert len(notes) == 1
    assert "long-lived credentials" in notes[0]


def test_template_e_firewall_shows_remediation_commands() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="firewall_open_to_internet",
        severity="CRITICAL",
        title="Title",
        fields={
            "Firewall Rule": "projects/prj-1/global/firewalls/allow-all",
            "Project": "prj-1",
            "Requested Firewall Config": {"sourceRanges": ["0.0.0.0/0"]},
        },
    )
    assert "Remediation Commands" in html_body
    assert "gcloud compute firewall-rules" in html_body
    assert "Firewall Configuration" in html_body


def test_template_e_sa_key_shows_key_risk_notes() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="service_account_key_created",
        severity="HIGH",
        title="Title",
        fields={
            "Service Account": "projects/prj-1/serviceAccounts/svc@prj-1.iam.gserviceaccount.com/keys/abc",
            "Project": "prj-1",
        },
    )
    assert "Key Risk Notes" in html_body
    assert "gcloud iam service-accounts keys" in html_body


def test_template_e_never_shows_firewall_section_for_sa_key_rule() -> None:
    _subject, html_body, _text_body = render_alert(
        rule_id="service_account_key_created", severity="HIGH", title="Title", fields={}
    )
    assert "Firewall Configuration" not in html_body


@pytest.mark.parametrize(
    "rule_id,severity",
    [
        ("project_created", "HIGH"),  # Template A
        ("iam_policy_change", "HIGH"),  # Template B
        ("unclassified_admin_activity", "LOW"),  # Template C
        ("public_iam_grant", "CRITICAL"),  # Template D
        ("firewall_open_to_internet", "HIGH"),  # Template E
    ],
)
def test_mute_button_rendered_in_every_template_when_mute_url_given(rule_id: str, severity: str) -> None:
    mute_url = "https://mute-web-abc123-uc.a.run.app/mute?rule_id=" + rule_id
    _subject, html_body, text_body = render_alert(
        rule_id=rule_id, severity=severity, title="Title", fields={}, mute_url=mute_url
    )
    assert "Mute this alert" in html_body
    assert f'href="{mute_url}"' in html_body
    assert mute_url in text_body


def test_mute_button_omitted_when_mute_url_is_none() -> None:
    _subject, html_body, text_body = render_alert(
        rule_id="iam_policy_change", severity="HIGH", title="Title", fields={}, mute_url=None
    )
    assert "Mute this alert" not in html_body
    assert "Mute this alert" not in text_body


def test_mute_button_omitted_for_unsafe_url_scheme() -> None:
    _subject, html_body, text_body = render_alert(
        rule_id="iam_policy_change",
        severity="HIGH",
        title="Title",
        fields={},
        mute_url="javascript:alert(1)",
    )
    assert "Mute this alert" not in html_body
    assert "javascript:" not in html_body
    assert "javascript:" not in text_body
