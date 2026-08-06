"""Keyless Gmail delivery via IAM Credentials signJwt + domain-wide delegation.

The Cloud Function's runtime identity (an IAM service account with no key
file) signs a short-lived JWT asserting delegated authority over a Workspace
mailbox, exchanges it for an OAuth access token, and uses that token to send
mail through the Gmail API. No service account key ever exists on disk.

Auth flow implemented here:
    1. Build a JWT claim set (iss=service account, sub=impersonated mailbox,
       scope=gmail.send, aud=token endpoint, iat/exp).
    2. Sign it via IAMCredentialsClient.sign_jwt() -- Google holds the
       private key; we never see it.
    3. Exchange the signed JWT for an access token via the OAuth2 token
       endpoint (grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer).
    4. Build a Gmail API client from that access token.
    5. Send mail with users().messages().send(userId=<sub>, ...).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid
from typing import Any, TypeVar

import requests
from google.api_core import exceptions as gax_exceptions
from google.cloud import iam_credentials_v1
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.send"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWT_LIFETIME_SECONDS = 3600
TOKEN_REFRESH_MARGIN_SECONDS = 300
RETRY_BACKOFF_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)

_AUTH_ERROR_HINT = (
    "Likely causes: (1) domain-wide delegation for this service account's "
    "client ID is not authorized for the gmail.send scope in the Workspace "
    "Admin Console, (2) the sender mailbox does not hold a Gmail license, "
    "or (3) the JWT 'sub' claim does not match the mailbox being "
    "impersonated (a sub/userId mismatch)."
)

T = TypeVar("T")


class GmailSendError(RuntimeError):
    """Raised for any unrecoverable failure preparing or sending Gmail mail."""


@dataclass(frozen=True)
class MailerConfig:
    """Configuration for the delegated Gmail client, sourced from the environment.

    Required env vars: GMAIL_DELEGATED_SA, GMAIL_SENDER.
    Optional env vars: GMAIL_SENDER_NAME, GMAIL_MAX_ATTEMPTS, GMAIL_TIMEOUT.
    """

    delegated_sa: str
    sender: str
    sender_name: str = "GCP Audit Platform"
    max_attempts: int = 4
    timeout: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> MailerConfig:
        """Build a MailerConfig from environment variables.

        Raises GmailSendError naming the specific variable if a required
        one is missing or empty.
        """
        source: Mapping[str, str] = env if env is not None else os.environ
        return cls(
            delegated_sa=_require_env(source, "GMAIL_DELEGATED_SA"),
            sender=_require_env(source, "GMAIL_SENDER"),
            sender_name=source.get("GMAIL_SENDER_NAME", "GCP Audit Platform"),
            max_attempts=int(source.get("GMAIL_MAX_ATTEMPTS", "4")),
            timeout=float(source.get("GMAIL_TIMEOUT", "30")),
        )

    @property
    def sender_domain(self) -> str:
        """The domain portion of the sender mailbox, used for Message-ID generation."""
        return self.sender.rsplit("@", 1)[-1]


def _require_env(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not value:
        raise GmailSendError(f"Missing required environment variable: {name}")
    return value


class _RetryableError(Exception):
    """Internal signal that an attempt failed but may succeed on retry."""


def _with_retry(attempt: Callable[[], T], *, max_attempts: int, description: str) -> T:
    """Run `attempt` up to `max_attempts` times with exponential backoff on _RetryableError."""
    last_error: Exception | None = None
    for attempt_number in range(1, max_attempts + 1):
        try:
            return attempt()
        except _RetryableError as exc:
            last_error = exc
            logger.warning(
                "gmail_send_retry",
                extra={
                    "description": description,
                    "attempt": attempt_number,
                    "max_attempts": max_attempts,
                },
            )
            if attempt_number < max_attempts:
                delay = RETRY_BACKOFF_SECONDS[min(attempt_number - 1, len(RETRY_BACKOFF_SECONDS) - 1)]
                time.sleep(delay)
    raise GmailSendError(f"{description} failed after {max_attempts} attempts: {last_error}") from last_error


class DelegatedGmailClient:
    """Sends mail through the Gmail API using keyless domain-wide delegation."""

    def __init__(self, config: MailerConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._token_expiry: float = 0.0
        self._service: Any = None
        self._iam_client_instance: iam_credentials_v1.IAMCredentialsClient | None = None

    @property
    def _iam_client(self) -> iam_credentials_v1.IAMCredentialsClient:
        if self._iam_client_instance is None:
            self._iam_client_instance = iam_credentials_v1.IAMCredentialsClient()
        return self._iam_client_instance

    def _sign_jwt(self) -> str:
        """Sign the delegation JWT claim set via IAM Credentials signJwt (step 1-2)."""
        now = int(time.time())
        claims = {
            "iss": self._config.delegated_sa,
            "sub": self._config.sender,
            "scope": GMAIL_SCOPE,
            "aud": TOKEN_URL,
            "iat": now,
            "exp": now + JWT_LIFETIME_SECONDS,
        }
        request = {
            "name": f"projects/-/serviceAccounts/{self._config.delegated_sa}",
            "payload": json.dumps(claims),
        }

        def attempt() -> str:
            try:
                response = self._iam_client.sign_jwt(request=request)
            except (gax_exceptions.TooManyRequests, gax_exceptions.ServiceUnavailable) as exc:
                raise _RetryableError(f"signJwt transient failure: {exc}") from exc
            except gax_exceptions.GoogleAPICallError as exc:
                code = getattr(exc, "code", None)
                if code is not None and int(code) >= 500:
                    raise _RetryableError(f"signJwt failed: {exc}") from exc
                raise GmailSendError(f"signJwt failed: {exc}. {_AUTH_ERROR_HINT}") from exc
            except (ConnectionError, TimeoutError, OSError) as exc:
                raise _RetryableError(f"network error calling signJwt: {exc}") from exc
            return str(response.signed_jwt)

        return _with_retry(attempt, max_attempts=self._config.max_attempts, description="signJwt")

    def _exchange_token(self, signed_jwt: str) -> tuple[str, float]:
        """Exchange the signed JWT for a delegated access token (step 3)."""

        def attempt() -> tuple[str, float]:
            try:
                response = requests.post(
                    TOKEN_URL,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                        "assertion": signed_jwt,
                    },
                    timeout=self._config.timeout,
                )
            except requests.exceptions.RequestException as exc:
                raise _RetryableError(f"network error during token exchange: {exc}") from exc

            if response.status_code == 200:
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise GmailSendError(f"token exchange returned invalid JSON: {exc}") from exc
                access_token = str(payload["access_token"])
                expires_in = float(payload.get("expires_in", JWT_LIFETIME_SECONDS))
                return access_token, expires_in

            if response.status_code == 429 or response.status_code >= 500:
                raise _RetryableError(f"token exchange returned HTTP {response.status_code}")

            raise GmailSendError(
                f"token exchange failed with HTTP {response.status_code}: {response.text}. "
                f"{_AUTH_ERROR_HINT}"
            )

        return _with_retry(attempt, max_attempts=self._config.max_attempts, description="token exchange")

    def _ensure_fresh_token(self) -> None:
        """Refresh the cached access token if missing or within the expiry margin."""
        now = time.time()
        if self._access_token is not None and now < self._token_expiry - TOKEN_REFRESH_MARGIN_SECONDS:
            return
        with self._lock:
            now = time.time()
            if self._access_token is not None and now < self._token_expiry - TOKEN_REFRESH_MARGIN_SECONDS:
                return
            signed_jwt = self._sign_jwt()
            access_token, expires_in = self._exchange_token(signed_jwt)
            credentials = Credentials(token=access_token)  # type: ignore[no-untyped-call]
            self._service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
            self._access_token = access_token
            self._token_expiry = now + expires_in
            logger.info("gmail_token_refreshed", extra={"expires_in": expires_in})

    def build_mime(
        self,
        *,
        to: Sequence[str],
        subject: str,
        html_body: str,
        text_body: str = "",
        cc: Sequence[str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> MIMEMultipart:
        """Build a multipart/alternative MIME message (text/plain then text/html).

        RFC 2046 treats the last alternative part as preferred, so text/html
        is attached second.
        """
        if not to:
            raise GmailSendError("Cannot build a message with an empty recipient list")

        message = MIMEMultipart("alternative")
        message.attach(MIMEText(text_body, "plain", "utf-8"))
        message.attach(MIMEText(html_body, "html", "utf-8"))

        message["To"] = ", ".join(formataddr(("", address)) for address in to)
        if cc:
            message["Cc"] = ", ".join(formataddr(("", address)) for address in cc)
        message["From"] = formataddr((self._config.sender_name, self._config.sender))
        message["Subject"] = subject
        message["Message-ID"] = make_msgid(domain=self._config.sender_domain)

        if headers:
            for key, value in headers.items():
                message[key] = value

        return message

    def send(
        self,
        *,
        to: Sequence[str],
        subject: str,
        html_body: str,
        text_body: str = "",
        cc: Sequence[str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        """Send an HTML (+ plain-text fallback) email and return the Gmail message id.

        `userId` on the underlying API call always equals `GMAIL_SENDER`
        (MailerConfig.sender), the same value used as the `sub` claim when
        signing the delegation JWT -- a mismatch between the two is what
        causes the API to return 404.
        """
        if not to:
            raise GmailSendError("Cannot send an email with an empty recipient list")

        self._ensure_fresh_token()
        message = self.build_mime(
            to=to, subject=subject, html_body=html_body, text_body=text_body, cc=cc, headers=headers
        )
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")

        def attempt() -> str:
            try:
                result = (
                    self._service.users()
                    .messages()
                    .send(userId=self._config.sender, body={"raw": raw})
                    .execute()
                )
            except HttpError as exc:
                status = exc.resp.status if exc.resp is not None else None
                if status == 429 or (status is not None and status >= 500):
                    raise _RetryableError(f"Gmail send returned HTTP {status}") from exc
                if status == 404:
                    raise GmailSendError(
                        f"Gmail send failed with HTTP 404 (Not Found) for "
                        f"userId={self._config.sender!r}. The `userId` passed to "
                        "messages().send() must exactly match the `sub` claim used to "
                        "sign the delegated JWT -- both must equal GMAIL_SENDER. Check "
                        "for a mismatch."
                    ) from exc
                if status in (400, 401, 403):
                    raise GmailSendError(
                        f"Gmail send failed with HTTP {status}. {_AUTH_ERROR_HINT}"
                    ) from exc
                raise GmailSendError(f"Gmail send failed with HTTP {status}: {exc}") from exc
            except (ConnectionError, TimeoutError, OSError) as exc:
                raise _RetryableError(f"network error during Gmail send: {exc}") from exc
            return str(result["id"])

        return _with_retry(attempt, max_attempts=self._config.max_attempts, description="Gmail send")


_client_singleton: DelegatedGmailClient | None = None
_singleton_lock = threading.Lock()


def get_client() -> DelegatedGmailClient:
    """Return a process-wide DelegatedGmailClient, reusing cached tokens across warm invocations."""
    global _client_singleton
    if _client_singleton is None:
        with _singleton_lock:
            if _client_singleton is None:
                _client_singleton = DelegatedGmailClient(MailerConfig.from_env())
    return _client_singleton
