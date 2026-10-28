"""HubSpot CRM downstream destination adapter with formula defanging and lead scoring.

Guarantees:
1. Universal Selective Unmasking: Restores prospect contact details (PERSON, EMAIL,
   PHONE, IP_ADDRESS) and corporate domain while keeping secrets (CREDIT_CARD, SSN,
   IBAN, API_KEY) strictly masked.
2. Formula / CSV Injection Protection: Neutralizes spreadsheet execution vulnerabilities
   (=, +, -, @, \\t, \\r) across all fields.
3. Idempotency & Collision Recovery: Pre-checks prospect existence by email before creation
   and recovers existing IDs on 409 conflict collisions without false failures.
4. Strict HTTPS, domain allowlist enforcement, and sensitive header stripping in logs.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import asdict
from typing import Any
from urllib.parse import quote, urlparse

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
)
from utils.adapters.crm_format import build_hubspot_payload
from utils.config import ConfigError, get_config

logger = logging.getLogger("utils.adapters.crm_adapter")

EXISTING_ID_RE = re.compile(r"Existing ID:\s*(\d+)", re.IGNORECASE)


class CRMAdapter(BaseDestinationAdapter):
    """Destination adapter interfacing with HubSpot CRM REST API v3."""

    name: str = "crm"

    def __init__(
        self,
        target: str | None = None,
        api_key: str | None = None,
        api_key_env: str = "CRM_API_KEY",
        unmask_pii: bool = True,
        allowed_hosts: list[str] | None = None,
        request_timeout_seconds: float = 15.0,
        precheck_duplicates: bool = True,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__()
        cfg = self._load_dest_config()

        self._target = target if target is not None else cfg.get("target", "https://api.hubapi.com")
        self._api_key = api_key
        self._api_key_env = api_key_env or cfg.get("api_key_env", "CRM_API_KEY")

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
        """Loads destinations.crm configuration safely with fallback."""
        try:
            full_cfg = get_config()
            return full_cfg.get("destinations", {}).get("crm", {})
        except (ConfigError, OSError, KeyError, TypeError, ValueError):
            return {}

    def _get_api_key(self) -> str:
        """Retrieves active API key from instance or environment."""
        if self._api_key is not None:
            return self._api_key.strip()
        return os.environ.get(self._api_key_env, "").strip()

    def validate_config(self) -> bool:
        """Validates that target, API key, and host allowlist are correctly configured."""
        key = self._get_api_key()
        if not key:
            return False

        if not self._target or not isinstance(self._target, str):
            return False

        parsed = urlparse(self._target)
        if parsed.scheme != "https":
            return False

        hostname = (parsed.hostname or "").lower()
        return bool(hostname and hostname in self._allowed_hosts)

    def health_check(self) -> bool:
        """Executes a non-mutating connectivity check against HubSpot API."""
        if not self.validate_config():
            return False
        try:
            res = self._request(
                "GET",
                "/crm/v3/objects/contacts",
                params={"limit": 1},
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
            raise AdapterPermanentError("crm_insecure_scheme")
        if parsed.username or parsed.password:
            raise AdapterPermanentError("crm_credentials_in_url")

        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname not in self._allowed_hosts:
            raise AdapterPermanentError("crm_host_not_allowed")

        api_key = self._get_api_key()
        if not api_key:
            raise AdapterPermanentError("crm_missing_api_key")

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
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

    def _extract_id_from_409(self, data: Any) -> str | None:
        """Extracts existing contact ID from HubSpot 409 conflict error responses."""
        if not isinstance(data, dict):
            return None

        # Format A: context.id list
        context = data.get("context")
        if isinstance(context, dict):
            ctx_id = context.get("id")
            if isinstance(ctx_id, list) and ctx_id:
                return str(ctx_id[0])
            if isinstance(ctx_id, (str, int)):
                return str(ctx_id)

        # Format B: message contains 'Existing ID: 12345'
        message = str(data.get("message") or "")
        match = EXISTING_ID_RE.search(message)
        if match:
            return match.group(1)

        return None

    def check_duplicate(self, idempotency_key: str, payload: DispatchPayload) -> str | None:
        """Queries HubSpot for an existing contact by email address.

        Args:
            idempotency_key: Target idempotency key.
            payload: Outbound payload.

        Returns:
            remote_id string e.g. 'crm:1059281' if found, else None.
        """
        contact_payload = build_hubspot_payload(
            asdict(payload),
            idempotency_key=idempotency_key,
            unmask_pii=self._unmask_pii,
        )
        email = contact_payload["properties"].get("email", "").strip()
        if not email or "@" not in email:
            return None

        try:
            res = self._request(
                "GET",
                f"/crm/v3/objects/contacts/{quote(email)}",
                params={"idProperty": "email"},
            )
            if res.status_code == 200:
                data = res.json()
                contact_id = data.get("id")
                if contact_id:
                    return f"crm:{contact_id}"
        except (requests.RequestException, AdapterError, ValueError):
            return None

        return None

    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        """Dispatches an approved sales inquiry to HubSpot CRM as a qualified lead.

        Args:
            payload: Sanitized immutable dispatch payload.

        Returns:
            DispatchResult containing the remote HubSpot contact identifier.

        Raises:
            AdapterTransientError: On rate limit (429), server unavailable (503), or network drop.
            AdapterPermanentError: On auth failure (401/403) or schema validation error (422).
            AdapterUnknownOutcomeError: On post-submission network timeout.
        """
        if not self.validate_config():
            raise AdapterPermanentError("crm_not_configured")

        # 1. Build Ingestion Payload
        contact_payload = build_hubspot_payload(
            asdict(payload),
            idempotency_key=payload.idempotency_key,
            unmask_pii=self._unmask_pii,
        )

        # 2. Deduplication Pre-Check
        if self._precheck_duplicates:
            email = contact_payload["properties"].get("email", "").strip()
            if email and "@" in email:
                try:
                    res = self._request(
                        "GET",
                        f"/crm/v3/objects/contacts/{quote(email)}",
                        params={"idProperty": "email"},
                    )
                    if res.status_code == 200:
                        data = res.json()
                        contact_id = data.get("id")
                        if contact_id:
                            dup_id = f"crm:{contact_id}"
                            logger.info(
                                "dispatch_duplicate_found email_id=%s remote_id=%s",
                                payload.email_id,
                                dup_id,
                            )
                            return DispatchResult(remote_id=dup_id)
                except (requests.RequestException, AdapterError, ValueError):
                    pass

        try:
            res = self._request(
                "POST",
                "/crm/v3/objects/contacts",
                json_data=contact_payload,
            )
        except requests.exceptions.ReadTimeout as exc:
            raise AdapterUnknownOutcomeError("crm_network_timeout") from exc
        except requests.exceptions.ConnectionError as exc:
            raise AdapterTransientError("crm_connection_failed") from exc
        except AdapterError:
            raise
        except requests.RequestException as exc:
            raise AdapterUnknownOutcomeError("crm_unknown_error") from exc

        status = res.status_code
        if status == 201:
            try:
                data = res.json()
                contact_id = data.get("id")
            except (ValueError, AttributeError):
                contact_id = None

            if not contact_id and "Location" in res.headers:
                contact_id = res.headers["Location"].rstrip("/").split("/")[-1]

            if not contact_id:
                raise AdapterUnknownOutcomeError("crm_missing_contact_id")

            remote_id = f"crm:{contact_id}"
            logger.info("dispatch_created email_id=%s remote_id=%s", payload.email_id, remote_id)
            return DispatchResult(remote_id=remote_id)

        # Handle 409 Conflict collision recovery
        if status == 409:
            try:
                data = res.json()
            except (ValueError, AttributeError):
                data = {}
            existing_id = self._extract_id_from_409(data)
            if existing_id:
                remote_id = f"crm:{existing_id}"
                logger.info(
                    "dispatch_collision_recovered email_id=%s remote_id=%s",
                    payload.email_id,
                    remote_id,
                )
                return DispatchResult(remote_id=remote_id)
            raise AdapterPermanentError("crm_conflict_unresolved")

        if status == 429:
            raise AdapterTransientError("crm_rate_limited")
        if status in (502, 503, 504):
            raise AdapterTransientError("crm_service_unavailable")
        if status in (400, 422):
            raise AdapterPermanentError("crm_validation_failed")
        if status in (401, 403):
            raise AdapterPermanentError("crm_auth_failed")

        raise AdapterPermanentError(f"crm_http_{status}")
