from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src import muting


class _FakeSnapshot:
    def __init__(self, exists: bool, data: dict | None, doc_id: str):
        self.exists = exists
        self._data = data or {}
        self.id = doc_id

    def to_dict(self):
        return self._data


class _FakeDocRef:
    def __init__(self, store: dict, doc_id: str):
        self._store = store
        self._doc_id = doc_id

    def get(self):
        data = self._store.get(self._doc_id)
        return _FakeSnapshot(exists=data is not None, data=data, doc_id=self._doc_id)

    def set(self, data: dict) -> None:
        self._store[self._doc_id] = data

    def delete(self) -> None:
        self._store.pop(self._doc_id, None)


class _FakeCollection:
    def __init__(self, store: dict):
        self._store = store

    def document(self, doc_id: str) -> _FakeDocRef:
        return _FakeDocRef(self._store, doc_id)

    def stream(self):
        return [_FakeSnapshot(exists=True, data=data, doc_id=doc_id) for doc_id, data in self._store.items()]


class _FakeFirestoreClient:
    def __init__(self):
        self._stores: dict[str, dict] = {}

    def collection(self, name: str) -> _FakeCollection:
        return _FakeCollection(self._stores.setdefault(name, {}))


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeFirestoreClient:
    client = _FakeFirestoreClient()
    monkeypatch.setattr(muting, "_get_client", lambda: client)
    return client


def _seed(client: _FakeFirestoreClient, doc_id: str, *, expire_at: datetime, **extra) -> None:
    data = {
        "rule_id": "r",
        "project_id": None,
        "reason": "test",
        "muted_by": "tester",
        "created_at": datetime.now(UTC),
        "expire_at": expire_at,
        **extra,
    }
    client.collection(muting._COLLECTION).document(doc_id).set(data)


def test_is_muted_false_when_no_mute_exists(fake_client) -> None:
    assert muting.is_muted("some_rule", "some-project") is False


def test_is_muted_true_for_active_rule_wide_mute(fake_client) -> None:
    _seed(fake_client, "rule::resource_created", expire_at=datetime.now(UTC) + timedelta(hours=1))
    assert muting.is_muted("resource_created", None) is True
    assert muting.is_muted("resource_created", "any-project") is True  # rule-wide covers every project


def test_is_muted_true_for_active_project_scoped_mute_only_for_that_project(fake_client) -> None:
    _seed(
        fake_client,
        "rule_project::resource_created::prj-a",
        expire_at=datetime.now(UTC) + timedelta(hours=1),
    )
    assert muting.is_muted("resource_created", "prj-a") is True
    assert muting.is_muted("resource_created", "prj-b") is False
    assert muting.is_muted("resource_created", None) is False


def test_is_muted_false_for_expired_mute_even_if_document_still_exists(fake_client) -> None:
    """The core correctness guarantee: Firestore's TTL deletion can lag up
    to ~24h, so is_muted() must never trust document existence alone --
    only the expire_at timestamp itself.
    """
    _seed(fake_client, "rule::resource_created", expire_at=datetime.now(UTC) - timedelta(minutes=1))
    assert muting.is_muted("resource_created", None) is False


def test_is_muted_never_raises_on_client_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom():
        raise RuntimeError("firestore unavailable")

    monkeypatch.setattr(muting, "_get_client", boom)
    assert muting.is_muted("resource_created", "prj-a") is False


def test_create_mute_writes_expected_fields(fake_client) -> None:
    record = muting.create_mute(
        rule_id="resource_created", project_id="prj-a", duration_hours=4, reason="load test", muted_by="alice"
    )
    assert record.rule_id == "resource_created"
    assert record.project_id == "prj-a"
    assert record.reason == "load test"
    assert record.muted_by == "alice"
    assert abs((record.expire_at - record.created_at) - timedelta(hours=4)) < timedelta(seconds=5)

    stored = fake_client.collection(muting._COLLECTION).document("rule_project::resource_created::prj-a").get()
    assert stored.exists
    assert stored.to_dict()["reason"] == "load test"


def test_create_mute_without_project_id_uses_rule_wide_doc_id(fake_client) -> None:
    muting.create_mute(rule_id="resource_created", project_id=None, duration_hours=1, reason="r", muted_by="bob")
    assert fake_client.collection(muting._COLLECTION).document("rule::resource_created").get().exists


def test_clear_mute_removes_it_and_returns_true(fake_client) -> None:
    muting.create_mute(rule_id="resource_created", project_id="prj-a", duration_hours=1, reason="r", muted_by="bob")
    assert muting.clear_mute(rule_id="resource_created", project_id="prj-a") is True
    assert muting.is_muted("resource_created", "prj-a") is False


def test_clear_mute_returns_false_when_nothing_to_clear(fake_client) -> None:
    assert muting.clear_mute(rule_id="never_muted", project_id=None) is False


def test_list_mutes_returns_all_records(fake_client) -> None:
    muting.create_mute(rule_id="rule_a", project_id=None, duration_hours=1, reason="a", muted_by="alice")
    muting.create_mute(rule_id="rule_b", project_id="prj-x", duration_hours=2, reason="b", muted_by="bob")

    records = muting.list_mutes()
    rule_ids = {r.rule_id for r in records}
    assert rule_ids == {"rule_a", "rule_b"}


def test_list_mutes_skips_malformed_records(fake_client) -> None:
    fake_client.collection(muting._COLLECTION).document("broken").set({"reason": "missing required fields"})
    assert muting.list_mutes() == []
