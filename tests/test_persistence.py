from __future__ import annotations

import logging

import pytest

from src.models import EnrichedEvent, Finding
from src.persistence import bigquery as bq_module
from src.persistence.bigquery import Delivery


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


def _event(**overrides) -> EnrichedEvent:
    defaults: dict = {"project_id": "p", "resource_type": "project", "enrichment_ok": True}
    defaults.update(overrides)
    return EnrichedEvent(**defaults)


class _FakeBqClient:
    def __init__(self, project: str = "proj", insert_errors=None):
        self.project = project
        self.insert_errors = insert_errors or []
        self.inserted: list = []

    def insert_rows_json(self, table_id, rows):
        self.inserted.append((table_id, rows))
        return self.insert_errors


def test_persist_correct_row_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeBqClient()
    monkeypatch.setattr(bq_module, "_get_client", lambda: fake_client)
    monkeypatch.setenv("BQ_DATASET", "ds")
    monkeypatch.setenv("BQ_TABLE", "tbl")

    finding = _finding()
    event = _event()
    delivery = Delivery(recipients=["a@b.com"], gmail_message_id="msg1", delivery_status="sent", delivery_error=None)

    bq_module.persist(finding, event, delivery)

    assert len(fake_client.inserted) == 1
    table_id, rows = fake_client.inserted[0]
    assert table_id == "proj.ds.tbl"
    row = rows[0]
    assert row["rule_id"] == finding.rule_id
    assert row["severity"] == finding.severity
    assert row["title"] == finding.title
    assert row["project_id"] == event.project_id
    assert row["recipients"] == ["a@b.com"]
    assert row["gmail_message_id"] == "msg1"
    assert row["delivery_status"] == "sent"
    assert row["delivery_error"] is None
    assert row["enrichment_ok"] == event.enrichment_ok
    assert row["raw_log_id"] == finding.raw_log_id
    assert "ingest_timestamp" in row
    assert set(row) == {field.name for field in bq_module.SCHEMA}


def test_persist_insert_errors_logged_not_raised(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake_client = _FakeBqClient(insert_errors=[{"index": 0, "errors": ["bad row"]}])
    monkeypatch.setattr(bq_module, "_get_client", lambda: fake_client)

    delivery = Delivery(recipients=[], gmail_message_id=None, delivery_status="sent", delivery_error=None)
    with caplog.at_level(logging.ERROR):
        bq_module.persist(_finding(), _event(), delivery)

    assert any(
        record.getMessage() == "bigquery_insert_errors" and record.levelname == "ERROR"
        for record in caplog.records
    )


def test_persist_never_raises_on_client_construction_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error():
        raise RuntimeError("connection failed")

    monkeypatch.setattr(bq_module, "_get_client", raise_error)
    delivery = Delivery(recipients=[], gmail_message_id=None, delivery_status="failed", delivery_error="x")

    bq_module.persist(_finding(), _event(), delivery)  # must not raise


def test_persist_never_raises_when_insert_itself_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class _RaisingClient:
        project = "proj"

        def insert_rows_json(self, table_id, rows):
            raise RuntimeError("network blip")

    monkeypatch.setattr(bq_module, "_get_client", lambda: _RaisingClient())
    delivery = Delivery(recipients=[], gmail_message_id=None, delivery_status="sent", delivery_error=None)

    bq_module.persist(_finding(), _event(), delivery)  # must not raise
