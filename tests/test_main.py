from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

import main
from src.models import EnrichedEvent, Finding
from src.senders.gmail_sender import GmailSendError


def _cloud_event(payload) -> SimpleNamespace:
    if isinstance(payload, dict):
        raw = json.dumps(payload).encode("utf-8")
    else:
        raw = payload
    return SimpleNamespace(data={"message": {"data": base64.b64encode(raw).decode("ascii")}})


def _finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="iam_policy_change",
        severity="HIGH",
        title="IAM policy changed",
        fields={"Principal": "a@b.com"},
        ai_analysis=None,
        console_url=None,
        resource_name="projects/p",
        principal_email="a@b.com",
        method_name="SetIamPolicy",
        event_timestamp=None,
        raw_log_id="log-1",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class _FakeGmailClient:
    def __init__(self, *, message_id: str = "msg-1", error: Exception | None = None):
        self.message_id = message_id
        self.error = error
        self.calls: list = []

    def send(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.message_id


@pytest.fixture(autouse=True)
def _no_real_persist_or_dlq(monkeypatch: pytest.MonkeyPatch):
    """Persistence/DLQ are exercised in their own test files; default them to no-ops here."""
    monkeypatch.setattr(main, "persist", lambda *a, **k: None)
    monkeypatch.setattr(main, "write_to_dlq", lambda *a, **k: None)
    monkeypatch.setattr(main, "requires_ai_analysis", lambda rule_id: False)
    monkeypatch.setattr(main.muting, "is_muted", lambda rule_id, project_id: False)


def test_happy_path_sends_and_persists(monkeypatch: pytest.MonkeyPatch) -> None:
    event = EnrichedEvent(raw_log_id="log-1")
    finding = _finding()
    monkeypatch.setattr(main, "enrich", lambda log_entry: event)
    monkeypatch.setattr(main, "evaluate_rules", lambda e: [finding])

    fake_client = _FakeGmailClient()
    monkeypatch.setattr(main, "get_client", lambda: fake_client)

    persisted = []
    monkeypatch.setattr(main, "persist", lambda f, e, delivery: persisted.append(delivery))

    main.process_audit_log(_cloud_event({"insertId": "log-1"}))

    assert len(fake_client.calls) == 1
    assert fake_client.calls[0]["headers"]["X-Audit-Rule-Id"] == "iam_policy_change"
    assert len(persisted) == 1
    assert persisted[0]["delivery_status"] == "sent"
    assert persisted[0]["gmail_message_id"] == "msg-1"


def test_zero_findings_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "enrich", lambda log_entry: EnrichedEvent())
    monkeypatch.setattr(main, "evaluate_rules", lambda e: [])

    fake_client = _FakeGmailClient()
    monkeypatch.setattr(main, "get_client", lambda: fake_client)

    main.process_audit_log(_cloud_event({"insertId": "log-1"}))

    assert fake_client.calls == []


def test_gmail_send_error_writes_dlq_persists_failed_and_acks(monkeypatch: pytest.MonkeyPatch) -> None:
    event = EnrichedEvent(raw_log_id="log-1")
    finding = _finding()
    monkeypatch.setattr(main, "enrich", lambda log_entry: event)
    monkeypatch.setattr(main, "evaluate_rules", lambda e: [finding])

    fake_client = _FakeGmailClient(error=GmailSendError("permanent failure"))
    monkeypatch.setattr(main, "get_client", lambda: fake_client)

    dlq_calls = []
    persisted = []
    monkeypatch.setattr(main, "write_to_dlq", lambda f, reason: dlq_calls.append((f, reason)))
    monkeypatch.setattr(main, "persist", lambda f, e, delivery: persisted.append(delivery))

    # Must not raise -- a GmailSendError is a permanent config error that
    # should ack the Pub/Sub message, not retry it.
    main.process_audit_log(_cloud_event({"insertId": "log-1"}))

    assert len(dlq_calls) == 1
    assert dlq_calls[0][0].rule_id == "iam_policy_change"
    assert "permanent failure" in dlq_calls[0][1]
    assert persisted[0]["delivery_status"] == "failed"
    assert persisted[0]["delivery_error"] == "permanent failure"


def test_one_finding_failing_does_not_block_the_others(monkeypatch: pytest.MonkeyPatch) -> None:
    event = EnrichedEvent(raw_log_id="log-1")
    boom_finding = _finding(rule_id="boom_rule", raw_log_id="log-1")
    ok_finding = _finding(rule_id="ok_rule", raw_log_id="log-1")
    monkeypatch.setattr(main, "enrich", lambda log_entry: event)
    monkeypatch.setattr(main, "evaluate_rules", lambda e: [boom_finding, ok_finding])

    def fake_requires_ai(rule_id: str) -> bool:
        return rule_id == "boom_rule"

    def fake_analyze(finding, event):
        raise RuntimeError("unexpected bug analyzing this finding")

    monkeypatch.setattr(main, "requires_ai_analysis", fake_requires_ai)
    monkeypatch.setattr(main, "analyze", fake_analyze)

    fake_client = _FakeGmailClient()
    monkeypatch.setattr(main, "get_client", lambda: fake_client)

    # Should not raise -- the per-finding loop isolates the failure.
    main.process_audit_log(_cloud_event({"insertId": "log-1"}))

    # Only the ok_finding made it to send(); boom_finding's failure was
    # caught, logged, and counted, without aborting the loop.
    assert len(fake_client.calls) == 1
    assert fake_client.calls[0]["headers"]["X-Audit-Rule-Id"] == "ok_rule"


def test_malformed_payload_acks_without_calling_downstream_stages(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(main, "enrich", lambda log_entry: calls.append(log_entry))
    monkeypatch.setattr(main, "evaluate_rules", lambda e: calls.append("evaluate_rules") or [])

    # Not valid base64 -> base64.b64decode raises -> caught -> ack, no raise.
    bad_event = SimpleNamespace(data={"message": {"data": "not-valid-base64!!!"}})

    main.process_audit_log(bad_event)  # must not raise

    assert calls == []


def test_malformed_json_payload_acks(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(main, "enrich", lambda log_entry: calls.append(log_entry))

    not_json = base64.b64encode(b"this is not json").decode("ascii")
    bad_event = SimpleNamespace(data={"message": {"data": not_json}})

    main.process_audit_log(bad_event)  # must not raise

    assert calls == []


def test_muted_finding_skips_send_but_still_persists(monkeypatch: pytest.MonkeyPatch) -> None:
    event = EnrichedEvent(raw_log_id="log-1", project_id="prj-dg-devops-test")
    finding = _finding()
    monkeypatch.setattr(main, "enrich", lambda log_entry: event)
    monkeypatch.setattr(main, "evaluate_rules", lambda e: [finding])
    monkeypatch.setattr(main.muting, "is_muted", lambda rule_id, project_id: True)

    fake_client = _FakeGmailClient()
    monkeypatch.setattr(main, "get_client", lambda: fake_client)

    persisted = []
    monkeypatch.setattr(main, "persist", lambda f, e, delivery: persisted.append(delivery))

    main.process_audit_log(_cloud_event({"insertId": "log-1"}))

    assert fake_client.calls == []  # muted -- never even attempted to send
    assert len(persisted) == 1
    assert persisted[0]["delivery_status"] == "muted"
    assert persisted[0]["recipients"] == []
    assert persisted[0]["gmail_message_id"] is None


def test_muted_finding_never_reaches_gemini(monkeypatch: pytest.MonkeyPatch) -> None:
    """Muting is checked before requires_ai_analysis()/analyze() -- a muted
    finding must never spend money on an AI analysis nobody will see.
    """
    event = EnrichedEvent(raw_log_id="log-1")
    finding = _finding(rule_id="org_policy_modified")
    monkeypatch.setattr(main, "enrich", lambda log_entry: event)
    monkeypatch.setattr(main, "evaluate_rules", lambda e: [finding])
    monkeypatch.setattr(main.muting, "is_muted", lambda rule_id, project_id: True)

    def boom_if_called(rule_id: str) -> bool:
        raise AssertionError("requires_ai_analysis must not be called for a muted finding")

    monkeypatch.setattr(main, "requires_ai_analysis", boom_if_called)

    main.process_audit_log(_cloud_event({"insertId": "log-1"}))  # must not raise


def test_only_muted_rule_id_and_project_are_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    """is_muted() receives the finding's rule_id and the event's project_id --
    confirms the two pieces of scoping data actually get threaded through.
    """
    event = EnrichedEvent(raw_log_id="log-1", project_id="prj-target")
    finding = _finding(rule_id="resource_created")
    monkeypatch.setattr(main, "enrich", lambda log_entry: event)
    monkeypatch.setattr(main, "evaluate_rules", lambda e: [finding])

    seen_args = []

    def fake_is_muted(rule_id: str, project_id: str | None) -> bool:
        seen_args.append((rule_id, project_id))
        return False

    monkeypatch.setattr(main.muting, "is_muted", fake_is_muted)

    fake_client = _FakeGmailClient()
    monkeypatch.setattr(main, "get_client", lambda: fake_client)

    main.process_audit_log(_cloud_event({"insertId": "log-1"}))

    assert seen_args == [("resource_created", "prj-target")]


def test_unexpected_exception_in_evaluate_rules_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "enrich", lambda log_entry: EnrichedEvent())

    def raise_bug(event):
        raise RuntimeError("genuine bug")

    monkeypatch.setattr(main, "evaluate_rules", raise_bug)

    with pytest.raises(RuntimeError, match="genuine bug"):
        main.process_audit_log(_cloud_event({"insertId": "log-1"}))
