"""Webhook Alert downstream destination adapter with cryptographic HMAC signing.

Guarantees:
1. Cryptographic Authenticity: Computes HMAC-SHA256 signature in X-Signature-SHA256 header.
2. Replay Protection: Injects aware UTC ISO timestamp in X-Timestamp-ISO header.
3. Channel Privacy Guard: Defaults to unmask_pii=False to protect shared team chat
   channels (Slack, Discord, Teams) from customer PII leakage.
4. Auto-Format: Generates standard incident JSON or Slack Block Kit cards based on target host.
5. Strict HTTPS and domain allowlist enforcement.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict
from typing import Any
from urllib.parse import urlparse

import requests
import requests.exceptions

from utils.adapters.base import (
    AdapterError,
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
    is_connection_setup_error,
)
from utils.adapters.webhook_format import (
    build_alert_payload,
    build_security_headers,
    build_slack_payload,
)
from utils.config import ConfigError, get_config

logger = logging.getLogger("utils.adapters.webhook_adapter")


class WebhookAdapter(BaseDestinationAdapter):
    """Destination adapter delivering cryptographically signed incident webhook alerts."""

    name: str = "webhook"

    def __init__(
        self,
        target: str | None = None,
        secret_key: str | None = None,
        secret_env: str = "WEBHOOK_SECRET_KEY",  # nosec B107 # noqa: S107
        unmask_pii: bool = False,
        allowed_hosts: list[str] | None = None,
        request_timeout_seconds: float = 10.0,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__()
        cfg = self._load_dest_config()

        self._target = target if target is not None else cfg.get(
            "target", "https://events.mycompany.internal/triage-alerts"
        )
        self._secret_key = secret_key
        self._secret_env = secret_env or cfg.get("secret_env", "WEBHOOK_SECRET_KEY")

        if unmask_pii is not None:
            self._unmask_pii = bool(unmask_pii)
        else:
            self._unmask_pii = bool(cfg.get("unmask_pii", False))

        self._request_timeout_seconds = float(
            cfg.get("request_timeout_seconds", request_timeout_seconds)
        )

        # Host allowlist derivation: strictly enforce explicit parameter or config.yaml list
        if allowed_hosts is not None:
            self._allowed_hosts = [h.lower() for h in allowed_hosts]
        else:
            cfg_hosts = cfg.get("allowed_hosts")
            if cfg_hosts and isinstance(cfg_hosts, list):
                self._allowed_hosts = sorted(
                    {h.lower() for h in cfg_hosts if isinstance(h, str) and h.strip()}
                )
            else:
                self._allowed_hosts = []

        self._session = session or requests.Session()

    def _load_dest_config(self) -> dict[str, Any]:
        """Loads destinations.webhook configuration safely with fallback."""
        try:
            full_cfg = get_config()
            return full_cfg.get("destinations", {}).get("webhook", {})
        except (ConfigError, OSError, KeyError, TypeError, ValueError):
            return {}

    def _get_secret_key(self) -> str:
        """Retrieves active webhook signing secret from instance or environment."""
        if self._secret_key is not None:
            return self._secret_key.strip()
        return os.environ.get(self._secret_env, "").strip()

    def validate_config(self) -> bool:
        """Validates that destination target, allowed hosts, and signing secrets are configured."""
        if not self._target or not isinstance(self._target, str):
            return False

        parsed = urlparse(self._target)
        if parsed.scheme != "https":
            return False

        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname not in self._allowed_hosts:
            return False

        secret = self._get_secret_key()
        return bool(secret and secret.strip())

    def health_check(self) -> bool:
        """Checks configuration readiness for webhook dispatch."""
        return self.validate_config()

    def check_duplicate(self, idempotency_key: str, payload: DispatchPayload) -> str | None:
        """Deduplication pre-check. Stateless webhooks rely on the outbox ledger."""
        return None

    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        """Dispatches an incident alert via signed HTTP POST.

        Args:
            payload: Sanitized immutable dispatch payload.

        Returns:
            DispatchResult containing the remote alert identifier.

        Raises:
            AdapterTransientError: On rate limit (429), server unavailable (503), or network drop.
            AdapterPermanentError: On bad request (400), auth failure (401/403), or schema error.
            AdapterUnknownOutcomeError: On post-submission network timeout.
        """
        if not self.validate_config():
            raise AdapterPermanentError("webhook_not_configured")

        parsed_target = urlparse(self._target)
        hostname = (parsed_target.hostname or "").lower()

        # Dual payload selection
        if hostname == "hooks.slack.com":
            payload_dict = build_slack_payload(
                asdict(payload),
                unmask_pii=self._unmask_pii,
            )
        else:
            payload_dict = build_alert_payload(
                asdict(payload),
                unmask_pii=self._unmask_pii,
            )

        payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        headers = build_security_headers(
            payload_bytes=payload_bytes,
            secret=self._get_secret_key(),
            idempotency_key=payload.idempotency_key,
            email_id=payload.email_id,
        )

        timeout = (5.0, self._request_timeout_seconds)

        try:
            res = self._session.request(
                method="POST",
                url=self._target,
                data=payload_bytes,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            logger.error(
                "dispatch_ssl_error email_id=%s reason=webhook_ssl_error", payload.email_id
            )
            raise AdapterPermanentError("webhook_ssl_error") from exc
        except requests.exceptions.ConnectTimeout as exc:
            logger.warning("dispatch_connect_timeout email_id=%s", payload.email_id)
            raise AdapterTransientError("webhook_connect_timeout") from exc
        except requests.exceptions.ConnectionError as exc:
            if is_connection_setup_error(exc):
                logger.warning("dispatch_connection_failed email_id=%s", payload.email_id)
                raise AdapterTransientError("webhook_connection_failed") from exc
            logger.error("dispatch_connection_error email_id=%s", payload.email_id)
            raise AdapterUnknownOutcomeError("webhook_connection_error") from exc
        except (requests.exceptions.ReadTimeout, requests.exceptions.ChunkedEncodingError) as exc:
            logger.error("dispatch_network_timeout email_id=%s", payload.email_id)
            raise AdapterUnknownOutcomeError("webhook_network_timeout") from exc
        except AdapterError:
            raise
        except requests.RequestException as exc:
            raise AdapterUnknownOutcomeError("webhook_unknown_error") from exc

        status = res.status_code
        if status in (200, 201, 202, 204):
            remote_id = f"webhook:{payload.email_id}"
            logger.info("dispatch_alert_sent email_id=%s remote_id=%s", payload.email_id, remote_id)
            return DispatchResult(remote_id=remote_id)

        if status == 429:
            raise AdapterTransientError("webhook_rate_limited")
        if status == 503:
            raise AdapterTransientError("webhook_service_unavailable")
        if 500 <= status < 600:
            raise AdapterUnknownOutcomeError(f"webhook_server_error_{status}")
        if status in (400, 422):
            raise AdapterPermanentError("webhook_invalid_payload")
        if status in (401, 403):
            raise AdapterPermanentError("webhook_auth_failed")

        raise AdapterPermanentError(f"webhook_http_{status}")
