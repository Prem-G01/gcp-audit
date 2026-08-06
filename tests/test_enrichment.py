from __future__ import annotations

from types import SimpleNamespace

import pytest
from google.api_core import exceptions as gax_exceptions

from src.enrichment import asset_inventory
from src.models import EnrichedEvent


@pytest.fixture(autouse=True)
def _clear_cai_cache():
    asset_inventory._cache.clear()
    yield
    asset_inventory._cache.clear()


def _fake_result(*, labels=None, folders=None, organization=""):
    return SimpleNamespace(labels=labels or {}, folders=folders or [], organization=organization)


def test_enrich_success(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _fake_result(labels={"env": "prod"}, folders=["folders/111"], organization="organizations/222")
    monkeypatch.setattr(asset_inventory, "_search_resource", lambda project_id, resource_name: result)

    event = asset_inventory.enrich(
        {
            "protoPayload": {"resourceName": "projects/p/x/y"},
            "resource": {"labels": {"project_id": "p"}},
        }
    )

    assert event.enrichment_ok is True
    assert event.asset_labels == {"env": "prod"}
    assert event.asset_ancestors == ["folders/111", "organizations/222"]


def test_enrich_cache_hit_avoids_second_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_search(project_id, resource_name):
        calls.append(1)
        return _fake_result(labels={"env": "prod"})

    monkeypatch.setattr(asset_inventory, "_search_resource", fake_search)

    log_entry = {
        "protoPayload": {"resourceName": "projects/p/x/y"},
        "resource": {"labels": {"project_id": "p"}},
    }
    asset_inventory.enrich(log_entry)
    asset_inventory.enrich(log_entry)

    assert len(calls) == 1


def test_enrich_cache_expires_after_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_search(project_id, resource_name):
        calls.append(1)
        return _fake_result(labels={"env": "prod"})

    monkeypatch.setattr(asset_inventory, "_search_resource", fake_search)
    monkeypatch.setenv("CAI_CACHE_TTL_SECONDS", "0")

    log_entry = {
        "protoPayload": {"resourceName": "projects/p/x/y"},
        "resource": {"labels": {"project_id": "p"}},
    }
    asset_inventory.enrich(log_entry)
    asset_inventory.enrich(log_entry)

    assert len(calls) == 2


def test_enrich_timeout_degrades_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_timeout(project_id, resource_name):
        raise gax_exceptions.DeadlineExceeded("timed out")

    monkeypatch.setattr(asset_inventory, "_search_resource", raise_timeout)

    event = asset_inventory.enrich(
        {
            "protoPayload": {"resourceName": "projects/p/x/y"},
            "resource": {"labels": {"project_id": "p"}},
        }
    )

    assert event.enrichment_ok is False
    assert event.asset_labels == {}


def test_enrich_exception_degrades_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error(project_id, resource_name):
        raise RuntimeError("boom")

    monkeypatch.setattr(asset_inventory, "_search_resource", raise_error)

    event = asset_inventory.enrich(
        {
            "protoPayload": {"resourceName": "projects/p/x/y"},
            "resource": {"labels": {"project_id": "p"}},
        }
    )

    assert event.enrichment_ok is False


def test_enrich_resource_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asset_inventory, "_search_resource", lambda project_id, resource_name: None)

    event = asset_inventory.enrich(
        {
            "protoPayload": {"resourceName": "projects/p/x/y"},
            "resource": {"labels": {"project_id": "p"}},
        }
    )

    assert event.enrichment_ok is True
    assert event.asset_labels == {}


def test_enrich_skips_lookup_without_resource_name_or_project(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(asset_inventory, "_search_resource", lambda *a: calls.append(1))

    event = asset_inventory.enrich({})

    assert calls == []
    assert isinstance(event, EnrichedEvent)
    assert event.enrichment_ok is True
