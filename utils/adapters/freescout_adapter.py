"""FreeScout Helpdesk downstream adapter with output hardening and thread continuity.

Guarantees:
1. Universal Selective Unmasking: Restores contact context (PERSON, EMAIL, PHONE, IP_ADDRESS)
   and customer email while strictly keeping secrets (CREDIT_CARD, SSN, IBAN, API_KEY) masked.
2. System-owned correlation marker is anchored at index 0 of thread text.
3. Thread continuity: Appends replies to existing active conversations matching thread_id.
4. Deduplication pre-check: Scans mailbox conversations to prevent duplicate ticket creation.
5. Strict HTTPS, domain allowlist enforcement, and sensitive header stripping in logs.
"""

import contextlib
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
from utils.adapters.freescout_format import (
    build_conversation_payload,
    build_thread_reply_payload,
    parse_marker,
)
from utils.config import ConfigError, get_config

logger = logging.getLogger("utils.adapters.freescout_adapter")


class FreeScoutAdapter(BaseDestinationAdapter):
    """Destination adapter interfacing with FreeScout Helpdesk REST API v1."""

    name: str = "freescout"

    def __init__(
        self,
        target: str | None = None,
        api_key: str | None = None,
        api_key_env: str = "FREESCOUT_API_KEY",
        mailbox_id: int | None = None,
        unmask_pii: bool = True,
        allowed_hosts: list[str] | None = None,
        request_timeout_seconds: float = 15.0,
        precheck_duplicates: bool = True,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__()
        cfg = self._load_dest_config()

        self._target = target if target is not None else cfg.get("target", "https://support.mycompany.com")
        self._api_key = api_key
        self._api_key_env = api_key_env or cfg.get("api_key_env", "FREESCOUT_API_KEY")

        if mailbox_id is not None:
            self._mailbox_id = int(mailbox_id)
        else:
            self._mailbox_id = int(cfg.get("mailbox_id", 1))

        if unmask_pii is not None:
            self._unmask_pii = bool(unmask_pii)
        else:
            self._unmask_pii = bool(cfg.get("unmask_pii", True))

        self._request_timeout_seconds = float(
            cfg.get("request_timeout_seconds", request_timeout_seconds)
        )
        self._precheck_duplicates = bool(
            cfg.get("precheck_duplicates", precheck_duplicates)
        )

        # Host allowlist derivation
        parsed_target = urlparse(self._target)
        target_host = (parsed_target.hostname or "").lower()
        if allowed_hosts is not None:
            self._allowed_hosts = [h.lower() for h in allowed_hosts]
        else:
            cfg_hosts = cfg.get("allowed_hosts")
            hosts_set: set[str] = set()
            if cfg_hosts and isinstance(cfg_hosts, list):
                hosts_set.update(h.lower() for h in cfg_hosts)
            if target_host:
                hosts_set.add(target_host)
            self._allowed_hosts = sorted(hosts_set)

        self._session = session or requests.Session()

    def _load_dest_config(self) -> dict[str, Any]:
        """Loads destinations.freescout configuration safely with fallback."""
        try:
            full_cfg = get_config()
            return full_cfg.get("destinations", {}).get("freescout", {})
        except (ConfigError, OSError, KeyError, TypeError, ValueError):
            return {}

    def _get_api_key(self) -> str:
        """Retrieves active API key from instance or environment."""
        if self._api_key:
            return self._api_key
        return os.environ.get(self._api_key_env, "").strip()

    def validate_config(self) -> bool:
        """Validates that destination target, API key, and mailbox_id are correctly configured."""
        key = self._get_api_key()
        if not key:
            return False

        if not self._target or not isinstance(self._target, str):
            return False

        parsed = urlparse(self._target)
        if parsed.scheme != "https":
            return False

        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname not in self._allowed_hosts:
            return False

        return isinstance(self._mailbox_id, int) and self._mailbox_id > 0

    def health_check(self) -> bool:
        """Executes a non-mutating authentication/connectivity check against FreeScout API."""
        if not self.validate_config():
            return False
        try:
            res = self._request(
                "GET",
                "/api/conversations",
                params={"mailboxId": self._mailbox_id, "page": 1},
            )
            return res.status_code == 200
        except (requests.RequestException, AdapterError):
            return False

    def _request(
        self,
        method: str,
        path_or_url: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> requests.Response:
        """Executes a single HTTP request with strict allowlisting and validation."""
        if path_or_url.startswith("https://") or path_or_url.startswith("http://"):
            url = path_or_url
        else:
            base = self._target.rstrip("/")
            path = path_or_url if path_or_url.startswith("/") else f"/{path_or_url}"
            url = f"{base}{path}"

        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise AdapterPermanentError("freescout_insecure_scheme")
        if parsed.username or parsed.password:
            raise AdapterPermanentError("freescout_credentials_in_url")

        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname not in self._allowed_hosts:
            raise AdapterPermanentError("freescout_host_not_allowed")

        api_key = self._get_api_key()
        if not api_key:
            raise AdapterPermanentError("freescout_missing_api_key")

        headers = {
            "Accept": "application/json",
            "X-FreeScout-API-Key": api_key,
            "User-Agent": "Customer-Email-Triage-Automation",
        }
        if method.upper() in ("POST", "PUT", "PATCH"):
            headers["Content-Type"] = "application/json"

        timeout = (5.0, self._request_timeout_seconds)

        return self._session.request(
            method=method,
            url=url,
            params=params,
            headers=headers,
            json=json_data,
            timeout=timeout,
            allow_redirects=False,
        )

    def _extract_conversations_from_response(self, data: Any) -> list[dict[str, Any]]:
        """Normalizes FreeScout conversation list response across API pagination styles."""
        if not isinstance(data, dict):
            return []
        if "_embedded" in data and isinstance(data["_embedded"], dict):
            convs = data["_embedded"].get("conversations")
            if isinstance(convs, list):
                return convs
        if "items" in data and isinstance(data["items"], list):
            return data["items"]
        if "conversations" in data and isinstance(data["conversations"], list):
            return data["conversations"]
        return []

    def find_duplicate_or_thread(
        self, idempotency_key: str, thread_id: str | None
    ) -> tuple[str | None, int | None]:
        """Scans recent mailbox conversations for duplicate keys and thread continuity.

        Args:
            idempotency_key: Target idempotency key.
            thread_id: Incoming email thread ID.

        Returns:
            Tuple of (duplicate_remote_id, matching_conversation_id).
        """
        try:
            res = self._request(
                "GET",
                "/api/conversations",
                params={"mailboxId": self._mailbox_id, "status": "all", "page": 1},
            )
            if res.status_code != 200:
                return None, None
            data = res.json()
        except (requests.RequestException, AdapterError, ValueError):
            return None, None

        conversations = self._extract_conversations_from_response(data)
        dup_id: str | None = None
        matching_thread_conv_id: int | None = None

        for conv in conversations:
            if not isinstance(conv, dict):
                continue
            conv_id = conv.get("id")
            threads = conv.get("threads")
            if isinstance(threads, list):
                for thread in threads:
                    if not isinstance(thread, dict):
                        continue
                    body = thread.get("body") or thread.get("text")
                    marker = parse_marker(body)
                    if marker:
                        if marker.get("key") == idempotency_key and not dup_id:
                            dup_id = f"freescout:{conv_id}"
                        if (
                            thread_id
                            and marker.get("thread_id") == thread_id
                            and not matching_thread_conv_id
                            and conv_id is not None
                        ):
                            with contextlib.suppress(ValueError, TypeError):
                                matching_thread_conv_id = int(conv_id)

        return dup_id, matching_thread_conv_id

    def check_duplicate(self, idempotency_key: str, payload: DispatchPayload) -> str | None:
        """Queries recent mailbox conversations to check if this item was already dispatched.

        Args:
            idempotency_key: Target idempotency key.
            payload: Outbound payload.

        Returns:
            remote_id string e.g. 'freescout:12345' if found, else None.
        """
        dup_id, _ = self.find_duplicate_or_thread(idempotency_key, payload.thread_id)
        return dup_id

    def check_thread_continuity(self, thread_id: str, payload: DispatchPayload) -> int | None:
        """Checks if an existing conversation matches the incoming email's thread_id.

        Args:
            thread_id: Incoming email thread ID.
            payload: Outbound payload.

        Returns:
            Matching conversation ID integer or None.
        """
        _, conv_id = self.find_duplicate_or_thread(payload.idempotency_key, thread_id)
        return conv_id

    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        """Dispatches an approved email to FreeScout with deduplication and thread continuity.

        Args:
            payload: Sanitized immutable dispatch payload.

        Returns:
            DispatchResult containing the remote FreeScout identifier.

        Raises:
            AdapterTransientError: On rate limit (429), server unavailable (503), or network drop.
            AdapterPermanentError: On auth failure (401/403) or schema validation error (422).
            AdapterUnknownOutcomeError: On post-submission network timeout.
        """
        if not self.validate_config():
            raise AdapterPermanentError("freescout_not_configured")

        # 1. Deduplication & Thread Continuity Pre-Check
        if self._precheck_duplicates:
            dup_id, existing_conv_id = self.find_duplicate_or_thread(
                payload.idempotency_key, payload.thread_id
            )
            if dup_id:
                logger.info(
                    "dispatch_duplicate_found email_id=%s remote_id=%s",
                    payload.email_id,
                    dup_id,
                )
                return DispatchResult(remote_id=dup_id)

            if existing_conv_id:
                record = (
                    payload.to_dict(include_pii=self._unmask_pii)
                    if isinstance(payload, DispatchPayload)
                    else asdict(payload)
                )
                thread_payload = build_thread_reply_payload(
                    record,
                    idempotency_key=payload.idempotency_key,
                    unmask_pii=self._unmask_pii,
                )
                try:
                    res = self._request(
                        "POST",
                        f"/api/conversations/{existing_conv_id}/threads",
                        json_data=thread_payload,
                    )
                except requests.exceptions.SSLError as exc:
                    logger.error(
                        "dispatch_ssl_error email_id=%s reason=freescout_ssl_error",
                        payload.email_id,
                    )
                    raise AdapterPermanentError("freescout_ssl_error") from exc
                except requests.exceptions.ConnectTimeout as exc:
                    logger.warning("dispatch_connect_timeout email_id=%s", payload.email_id)
                    raise AdapterTransientError("freescout_connect_timeout") from exc
                except requests.exceptions.ConnectionError as exc:
                    if is_connection_setup_error(exc):
                        logger.warning("dispatch_connection_failed email_id=%s", payload.email_id)
                        raise AdapterTransientError("freescout_connection_failed") from exc
                    logger.error("dispatch_connection_error email_id=%s", payload.email_id)
                    raise AdapterUnknownOutcomeError("freescout_connection_error") from exc
                except (
                    requests.exceptions.ReadTimeout,
                    requests.exceptions.ChunkedEncodingError,
                ) as exc:
                    logger.error("dispatch_network_timeout email_id=%s", payload.email_id)
                    raise AdapterUnknownOutcomeError("freescout_network_timeout") from exc
                except AdapterError:
                    raise
                except requests.RequestException as exc:
                    raise AdapterUnknownOutcomeError("freescout_unknown_error") from exc

                if res.status_code == 201:
                    try:
                        reply_data = res.json()
                        thread_msg_id = reply_data.get("id")
                    except (ValueError, AttributeError):
                        thread_msg_id = "appended"
                    remote_id = f"freescout:{existing_conv_id}#thread:{thread_msg_id}"
                    return DispatchResult(remote_id=remote_id)
                elif res.status_code == 429:
                    raise AdapterTransientError("freescout_rate_limited")
                elif res.status_code == 503:
                    raise AdapterTransientError("freescout_service_unavailable")
                elif 500 <= res.status_code < 600:
                    raise AdapterUnknownOutcomeError(
                        f"freescout_server_error_{res.status_code}"
                    )
                elif 400 <= res.status_code < 500:
                    if res.status_code == 422:
                        raise AdapterPermanentError("freescout_validation_failed")
                    if res.status_code in (401, 403):
                        raise AdapterPermanentError("freescout_auth_failed")
                    raise AdapterPermanentError(f"freescout_http_{res.status_code}")
                else:
                    raise AdapterUnknownOutcomeError(
                        f"freescout_unexpected_status_{res.status_code}"
                    )

        # 2. Create New Conversation
        record = (
            payload.to_dict(include_pii=self._unmask_pii)
            if isinstance(payload, DispatchPayload)
            else asdict(payload)
        )
        conv_payload = build_conversation_payload(
            record,
            mailbox_id=self._mailbox_id,
            idempotency_key=payload.idempotency_key,
            unmask_pii=self._unmask_pii,
        )

        try:
            res = self._request(
                "POST",
                "/api/conversations",
                json_data=conv_payload,
            )
        except requests.exceptions.SSLError as exc:
            logger.error(
                "dispatch_ssl_error email_id=%s reason=freescout_ssl_error", payload.email_id
            )
            raise AdapterPermanentError("freescout_ssl_error") from exc
        except requests.exceptions.ConnectTimeout as exc:
            logger.warning("dispatch_connect_timeout email_id=%s", payload.email_id)
            raise AdapterTransientError("freescout_connect_timeout") from exc
        except requests.exceptions.ConnectionError as exc:
            if is_connection_setup_error(exc):
                logger.warning("dispatch_connection_failed email_id=%s", payload.email_id)
                raise AdapterTransientError("freescout_connection_failed") from exc
            logger.error("dispatch_connection_error email_id=%s", payload.email_id)
            raise AdapterUnknownOutcomeError("freescout_connection_error") from exc
        except (requests.exceptions.ReadTimeout, requests.exceptions.ChunkedEncodingError) as exc:
            logger.error("dispatch_network_timeout email_id=%s", payload.email_id)
            raise AdapterUnknownOutcomeError("freescout_network_timeout") from exc
        except AdapterError:
            raise
        except requests.RequestException as exc:
            raise AdapterUnknownOutcomeError("freescout_unknown_error") from exc

        status = res.status_code
        if status == 201:
            try:
                data = res.json()
                conv_id = data.get("id")
            except (ValueError, AttributeError):
                conv_id = None

            if not conv_id and "Location" in res.headers:
                conv_id = res.headers["Location"].rstrip("/").split("/")[-1]

            if not conv_id:
                raise AdapterUnknownOutcomeError("freescout_missing_conversation_id")

            remote_id = f"freescout:{conv_id}"
            logger.info("dispatch_created email_id=%s remote_id=%s", payload.email_id, remote_id)
            return DispatchResult(remote_id=remote_id)

        if status == 429:
            raise AdapterTransientError("freescout_rate_limited")
        if status == 503:
            raise AdapterTransientError("freescout_service_unavailable")
        if 500 <= status < 600:
            raise AdapterUnknownOutcomeError(f"freescout_server_error_{status}")
        if status == 422:
            raise AdapterPermanentError("freescout_validation_failed")
        if status in (401, 403):
            raise AdapterPermanentError("freescout_auth_failed")

        raise AdapterPermanentError(f"freescout_http_{status}")
