from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mute_web import app as mute_web_app
from src.muting import MuteRecord

IAP_HEADER = "X-Goog-IAP-JWT-Assertion"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("IAP_AUDIENCE", "/projects/123/locations/asia-south1/services/mute-web")
    mute_web_app.app.config["TESTING"] = True
    return mute_web_app.app.test_client()


def _authorize_as(monkeypatch: pytest.MonkeyPatch, email: str = "admin@docugenieai.com") -> None:
    """Stub out IAP JWT verification to simulate a request that genuinely
    passed through IAP as `email`. verify_token's real implementation
    checks signature/expiry/audience against Google's public keys -- not
    something a unit test should (or safely could) exercise for real.
    """
    monkeypatch.setattr(
        mute_web_app.id_token,
        "verify_token",
        lambda *a, **k: {"iss": "https://cloud.google.com/iap", "email": email},
    )


# -----------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------


def test_health_check_returns_ok(client) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "ok"


# -----------------------------------------------------------------------
# IAP verification -- access denied paths never call muting.create_mute.
# -----------------------------------------------------------------------


def test_mute_get_without_iap_header_is_denied(client) -> None:
    response = client.get("/mute?rule_id=resource_created")
    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_mute_get_with_unverifiable_jwt_is_denied(client, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a, **k):
        raise ValueError("signature verification failed")

    monkeypatch.setattr(mute_web_app.id_token, "verify_token", boom)
    response = client.get("/mute?rule_id=resource_created", headers={IAP_HEADER: "not-a-real-jwt"})
    assert response.status_code == 403


def test_mute_get_wrong_issuer_is_denied(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mute_web_app.id_token, "verify_token", lambda *a, **k: {"iss": "https://evil.example", "email": "a@b.com"}
    )
    response = client.get("/mute?rule_id=resource_created", headers={IAP_HEADER: "token"})
    assert response.status_code == 403


def test_mute_get_missing_email_claim_is_denied(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mute_web_app.id_token, "verify_token", lambda *a, **k: {"iss": "https://cloud.google.com/iap"}
    )
    response = client.get("/mute?rule_id=resource_created", headers={IAP_HEADER: "token"})
    assert response.status_code == 403


def test_mute_get_missing_iap_audience_env_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAP_AUDIENCE", raising=False)
    mute_web_app.app.config["TESTING"] = True
    client = mute_web_app.app.test_client()
    response = client.get("/mute?rule_id=resource_created", headers={IAP_HEADER: "token"})
    assert response.status_code == 403


def test_unsigned_authenticated_user_email_header_is_never_trusted(client) -> None:
    """The spoofable X-Goog-Authenticated-User-Email header must never
    substitute for a verified JWT -- only the IAP_HEADER assertion counts.
    """
    response = client.get(
        "/mute?rule_id=resource_created",
        headers={"X-Goog-Authenticated-User-Email": "accounts.google.com:attacker@evil.example"},
    )
    assert response.status_code == 403


# -----------------------------------------------------------------------
# GET /mute -- confirmation page, never mutes anything itself.
# -----------------------------------------------------------------------


def test_mute_get_valid_jwt_shows_confirmation_form(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch, email="admin@docugenieai.com")
    response = client.get(
        "/mute?rule_id=resource_created&project_id=prj-dg-devops-test", headers={IAP_HEADER: "token"}
    )
    assert response.status_code == 200
    body = response.text
    assert "resource_created" in body
    assert "prj-dg-devops-test" in body
    assert "admin@docugenieai.com" in body
    assert '<form method="POST" action="/mute">' in body


def test_mute_get_shows_org_wide_scope_when_no_project_id(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch)
    response = client.get("/mute?rule_id=resource_created", headers={IAP_HEADER: "token"})
    assert response.status_code == 200
    assert "org-wide" in response.text


def test_mute_get_missing_rule_id_is_rejected(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch)
    response = client.get("/mute", headers={IAP_HEADER: "token"})
    assert response.status_code == 400


def test_mute_get_never_creates_a_mute(client, monkeypatch: pytest.MonkeyPatch) -> None:
    """A GET must never have a side effect -- email link-scanners/prefetchers
    routinely fetch links automatically.
    """
    _authorize_as(monkeypatch)
    calls = []
    monkeypatch.setattr(mute_web_app.muting, "create_mute", lambda **kwargs: calls.append(kwargs))
    client.get("/mute?rule_id=resource_created", headers={IAP_HEADER: "token"})
    assert calls == []


# -----------------------------------------------------------------------
# POST /mute -- the actual mute action.
# -----------------------------------------------------------------------


def _fake_record(**overrides) -> MuteRecord:
    defaults = dict(
        rule_id="resource_created",
        project_id="prj-dg-devops-test",
        reason="Muted via email link",
        muted_by="admin@docugenieai.com",
        created_at=datetime(2026, 8, 12, tzinfo=UTC),
        expire_at=datetime(2026, 8, 12, 4, tzinfo=UTC),
    )
    defaults.update(overrides)
    return MuteRecord(**defaults)


def test_mute_post_without_iap_header_is_denied_and_never_creates_a_mute(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    monkeypatch.setattr(mute_web_app.muting, "create_mute", lambda **kwargs: calls.append(kwargs))
    response = client.post("/mute", data={"rule_id": "resource_created"})
    assert response.status_code == 403
    assert calls == []


def test_mute_post_creates_mute_with_verified_caller_email(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch, email="admin@docugenieai.com")
    calls = []

    def fake_create_mute(**kwargs):
        calls.append(kwargs)
        return _fake_record(rule_id=kwargs["rule_id"], project_id=kwargs["project_id"])

    monkeypatch.setattr(mute_web_app.muting, "create_mute", fake_create_mute)

    response = client.post(
        "/mute",
        data={
            "rule_id": "resource_created",
            "project_id": "prj-dg-devops-test",
            "duration_hours": "4",
            "reason": "planned maintenance",
        },
        headers={IAP_HEADER: "token"},
    )

    assert response.status_code == 200
    assert "Muted" in response.text
    assert len(calls) == 1
    assert calls[0]["rule_id"] == "resource_created"
    assert calls[0]["project_id"] == "prj-dg-devops-test"
    assert calls[0]["duration_hours"] == 4.0
    assert calls[0]["reason"] == "planned maintenance"
    # muted_by comes from the VERIFIED JWT email claim, never from the
    # submitted form -- a malicious form post can't impersonate someone else.
    assert calls[0]["muted_by"] == "admin@docugenieai.com"


def test_mute_post_ignores_form_supplied_muted_by(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch, email="real-admin@docugenieai.com")
    calls = []
    monkeypatch.setattr(mute_web_app.muting, "create_mute", lambda **kwargs: calls.append(kwargs) or _fake_record())

    client.post(
        "/mute",
        data={"rule_id": "resource_created", "muted_by": "someone-else@evil.example"},
        headers={IAP_HEADER: "token"},
    )

    assert calls[0]["muted_by"] == "real-admin@docugenieai.com"


def test_mute_post_missing_rule_id_is_rejected(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch)
    calls = []
    monkeypatch.setattr(mute_web_app.muting, "create_mute", lambda **kwargs: calls.append(kwargs))
    response = client.post("/mute", data={}, headers={IAP_HEADER: "token"})
    assert response.status_code == 400
    assert calls == []


def test_mute_post_org_wide_when_project_id_omitted(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch)
    calls = []
    monkeypatch.setattr(
        mute_web_app.muting,
        "create_mute",
        lambda **kwargs: calls.append(kwargs) or _fake_record(project_id=None),
    )
    client.post("/mute", data={"rule_id": "resource_created"}, headers={IAP_HEADER: "token"})
    assert calls[0]["project_id"] is None


@pytest.mark.parametrize(
    "submitted,expected",
    [
        ("999999", 168.0),  # clamped to the 7-day max
        ("0", 0.25),  # clamped to the 15-minute min
        ("not-a-number", 4.0),  # falls back to the default rather than raising
    ],
)
def test_mute_post_duration_hours_clamped(
    client, monkeypatch: pytest.MonkeyPatch, submitted: str, expected: float
) -> None:
    _authorize_as(monkeypatch)
    calls = []
    monkeypatch.setattr(mute_web_app.muting, "create_mute", lambda **kwargs: calls.append(kwargs) or _fake_record())
    client.post(
        "/mute",
        data={"rule_id": "resource_created", "duration_hours": submitted},
        headers={IAP_HEADER: "token"},
    )
    assert calls[0]["duration_hours"] == expected


def test_mute_post_default_reason_when_omitted(client, monkeypatch: pytest.MonkeyPatch) -> None:
    _authorize_as(monkeypatch)
    calls = []
    monkeypatch.setattr(mute_web_app.muting, "create_mute", lambda **kwargs: calls.append(kwargs) or _fake_record())
    client.post("/mute", data={"rule_id": "resource_created"}, headers={IAP_HEADER: "token"})
    assert calls[0]["reason"] == "Muted via email link"
