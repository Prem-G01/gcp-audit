from __future__ import annotations

from datetime import datetime

from src.models import EnrichedEvent


def test_from_log_entry_set_iam_policy(load_fixture) -> None:
    event = EnrichedEvent.from_log_entry(load_fixture("set_iam_policy.json"))

    assert event.method_name == "SetIamPolicy"
    assert event.principal_email == "alice@example.com"
    assert event.resource_name == "projects/prj-dg-devops-test"
    assert event.resource_type == "project"
    assert event.project_id == "prj-dg-devops-test"
    assert event.raw_log_id == "fixture-set-iam-policy-001"
    assert event.request_metadata["caller_ip"] == "203.0.113.10"
    assert event.request_metadata["user_agent"] == "google-cloud-sdk"
    assert isinstance(event.event_timestamp, datetime)
    assert event.event_timestamp.year == 2026
    assert event.enrichment_ok is True
    assert event.raw["insertId"] == "fixture-set-iam-policy-001"


def test_from_log_entry_service_account_key_creation(load_fixture) -> None:
    event = EnrichedEvent.from_log_entry(load_fixture("service_account_key_creation.json"))

    assert event.method_name == "google.iam.admin.v1.CreateServiceAccountKey"
    assert event.principal_email == "bob@example.com"
    assert event.resource_type == "service_account"


def test_from_log_entry_firewall_change(load_fixture) -> None:
    event = EnrichedEvent.from_log_entry(load_fixture("firewall_open_internet.json"))

    assert event.method_name == "v1.compute.firewalls.insert"
    assert event.raw["protoPayload"]["request"]["sourceRanges"] == ["0.0.0.0/0"]


def test_from_log_entry_tolerates_missing_protopayload(load_fixture) -> None:
    event = EnrichedEvent.from_log_entry(load_fixture("malformed_missing_protopayload.json"))

    assert event.method_name is None
    assert event.principal_email is None
    assert event.resource_name is None
    assert event.project_id == "prj-dg-devops-test"
    assert event.raw_log_id == "fixture-malformed-007"


def test_from_log_entry_tolerates_completely_empty_dict() -> None:
    event = EnrichedEvent.from_log_entry({})

    assert event.method_name is None
    assert event.raw == {}
    assert event.request_metadata == {"caller_ip": None, "user_agent": None}


def test_from_log_entry_tolerates_non_mapping_payload() -> None:
    event = EnrichedEvent.from_log_entry("not a dict")  # type: ignore[arg-type]

    assert event.method_name is None
    assert event.raw == {}


def test_from_log_entry_tolerates_high_precision_timestamp() -> None:
    event = EnrichedEvent.from_log_entry({"timestamp": "2026-08-05T12:00:00.123456789Z"})

    assert event.event_timestamp is not None
    assert event.event_timestamp.year == 2026
    assert event.event_timestamp.month == 8


def test_from_log_entry_tolerates_garbage_timestamp() -> None:
    event = EnrichedEvent.from_log_entry({"timestamp": "not-a-timestamp"})

    assert event.event_timestamp is None
