from __future__ import annotations

import pytest

from src import email_template
from src.email_template import _FALLBACK_ACCENT, _FALLBACK_TINT, _severity_style, render_alert


@pytest.fixture(autouse=True)
def _use_test_routing_config(monkeypatch: pytest.MonkeyPatch, routing_yaml_path) -> None:
    monkeypatch.setattr(email_template, "CONFIG_PATH", routing_yaml_path)


def test_severity_styling_lookup() -> None:
    config = email_template.load_routing_config()
    accent, tint = _severity_style("CRITICAL", config)
    assert accent == "#b91c1c"
    assert tint == "#fee2e2"


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
