from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from googleapiclient.errors import HttpError

from src.senders import gmail_sender
from src.senders.gmail_sender import DelegatedGmailClient, GmailSendError, MailerConfig


class _FakeIamClient:
    def __init__(self) -> None:
        self.calls = 0

    def sign_jwt(self, request: dict) -> SimpleNamespace:
        assert isinstance(request["payload"], str)  # must be a JSON string, not a dict
        json.loads(request["payload"])  # must be valid JSON
        self.calls += 1
        return SimpleNamespace(signed_jwt="fake-signed-jwt")


class _FakeResponse:
    def __init__(self, status_code: int, json_data: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text or json.dumps(self._json_data)

    def json(self) -> dict:
        return self._json_data


class _FakeGmailService:
    def __init__(self) -> None:
        self.send_calls: list[dict] = []

    def users(self) -> _FakeGmailService:
        return self

    def messages(self) -> _FakeGmailService:
        return self

    def send(self, userId: str, body: dict) -> _FakeGmailService:
        self.send_calls.append({"userId": userId, "body": body})
        return self

    def execute(self) -> dict:
        return {"id": "msg-123"}


def _wire_success(
    monkeypatch: pytest.MonkeyPatch, client: DelegatedGmailClient
) -> tuple[_FakeIamClient, _FakeGmailService, list]:
    iam_client = _FakeIamClient()
    client._iam_client_instance = iam_client
    service = _FakeGmailService()
    build_calls: list = []
    monkeypatch.setattr(
        gmail_sender,
        "build",
        lambda *args, **kwargs: (build_calls.append((args, kwargs)), service)[1],
    )
    post_calls: list = []

    def fake_post(url, data, timeout):
        post_calls.append((url, data, timeout))
        return _FakeResponse(200, {"access_token": "fake-token", "expires_in": 3600})

    monkeypatch.setattr(gmail_sender.requests, "post", fake_post)
    return iam_client, service, post_calls


def test_token_caching_hit(monkeypatch: pytest.MonkeyPatch, mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    iam_client, service, post_calls = _wire_success(monkeypatch, client)

    client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")
    client.send(to=["a@example.com"], subject="s2", html_body="<p>y</p>", text_body="y")

    assert iam_client.calls == 1
    assert len(post_calls) == 1
    assert len(service.send_calls) == 2


def test_forced_refresh_near_expiry(monkeypatch: pytest.MonkeyPatch, mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    iam_client, _service, post_calls = _wire_success(monkeypatch, client)

    client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")
    assert iam_client.calls == 1
    assert len(post_calls) == 1

    # Simulate a token that's about to expire (inside the refresh margin).
    client._token_expiry = gmail_sender.time.time() + 100

    client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")
    assert iam_client.calls == 2
    assert len(post_calls) == 2


def test_403_raises_without_retry(monkeypatch: pytest.MonkeyPatch, mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    client._iam_client_instance = _FakeIamClient()
    post_calls: list = []

    def fake_post(url, data, timeout):
        post_calls.append(1)
        return _FakeResponse(403, text="permission denied")

    monkeypatch.setattr(gmail_sender.requests, "post", fake_post)

    with pytest.raises(GmailSendError):
        client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")

    assert len(post_calls) == 1


def test_429_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch, mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    client._iam_client_instance = _FakeIamClient()
    service = _FakeGmailService()
    monkeypatch.setattr(gmail_sender, "build", lambda *a, **k: service)

    responses = [
        _FakeResponse(429, text="rate limited"),
        _FakeResponse(200, {"access_token": "fake-token", "expires_in": 3600}),
    ]

    def fake_post(url, data, timeout):
        return responses.pop(0)

    monkeypatch.setattr(gmail_sender.requests, "post", fake_post)

    message_id = client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")

    assert message_id == "msg-123"
    assert responses == []


def test_5xx_exhausts_attempts(monkeypatch: pytest.MonkeyPatch, mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    client._iam_client_instance = _FakeIamClient()
    post_calls: list = []

    def fake_post(url, data, timeout):
        post_calls.append(1)
        return _FakeResponse(503, text="unavailable")

    monkeypatch.setattr(gmail_sender.requests, "post", fake_post)

    with pytest.raises(GmailSendError):
        client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")

    assert len(post_calls) == mailer_config.max_attempts


def test_404_raises_without_retry_and_mentions_userid(
    monkeypatch: pytest.MonkeyPatch, mailer_config: MailerConfig
) -> None:
    client = DelegatedGmailClient(mailer_config)
    _wire_success(monkeypatch, client)

    def raise_404() -> dict:
        raise HttpError(
            resp=SimpleNamespace(status=404, reason="Not Found"),
            content=b'{"error": "not found"}',
        )

    class _FailingService(_FakeGmailService):
        def execute(self) -> dict:
            return raise_404()

    monkeypatch.setattr(gmail_sender, "build", lambda *a, **k: _FailingService())

    with pytest.raises(GmailSendError, match="userId"):
        client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")


def test_empty_recipient_list_raises(mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    with pytest.raises(GmailSendError):
        client.send(to=[], subject="s", html_body="<p>x</p>", text_body="x")


def test_mime_part_order_text_then_html(mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    message = client.build_mime(to=["a@example.com"], subject="s", html_body="<p>hi</p>", text_body="hi")

    parts = message.get_payload()
    assert [part.get_content_type() for part in parts] == ["text/plain", "text/html"]


def test_userid_equals_gmail_sender(monkeypatch: pytest.MonkeyPatch, mailer_config: MailerConfig) -> None:
    client = DelegatedGmailClient(mailer_config)
    _iam_client, service, _post_calls = _wire_success(monkeypatch, client)

    client.send(to=["a@example.com"], subject="s", html_body="<p>x</p>", text_body="x")

    assert service.send_calls[0]["userId"] == mailer_config.sender


def test_from_env_missing_required_var_names_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GMAIL_DELEGATED_SA", raising=False)
    monkeypatch.delenv("GMAIL_SENDER", raising=False)

    with pytest.raises(GmailSendError, match="GMAIL_DELEGATED_SA"):
        MailerConfig.from_env(env={})
