"""GitHub Issues downstream adapter with output hardening and idempotency verification.

Follows the strict BaseDestinationAdapter contract:
1. Zero unmasked customer PII or raw email text is ever transmitted or logged.
2. System-owned correlation marker is anchored at index 0 of the issue body.
3. Untrusted customer text is neutralized and wrapped inside adaptive code fences.
4. HTTP calls are strictly HTTPS, allowlisted, redirect-blocked, and rate-limit classified.
5. All raised adapter exceptions carry short constant machine-readable reasons.
"""

import logging
import os
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
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
    is_connection_setup_error,
)
from utils.adapters.github_format import (
    build_issue_body,
    build_labels,
    parse_marker,
    sanitize_title,
)
from utils.config import get_config

logger = logging.getLogger("utils.adapters.github_adapter")

# Backward-compatible alias for canonical helper in utils.adapters.base
_is_connection_setup_error = is_connection_setup_error


class GitHubAdapter(BaseDestinationAdapter):
    """Adapter for dispatching Bug Reports and Feature Requests to GitHub Issues."""

    name: str = "github"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        """Initializes the GitHub Issues adapter.

        Args:
            config: Optional pre-loaded config dict. Defaults to get_config().
            session: Optional requests.Session instance for dependency injection.
        """
        if config is None:
            config = get_config()
        self._config = config
        self._session = session if session is not None else requests.Session()

        dest_cfg = config.get("destinations", {}).get("github", {})
        self._token_env = dest_cfg.get("token_env", "GITHUB_TOKEN")
        self._target = dest_cfg.get("target", "")
        self._labels = list(dest_cfg.get("labels", ["triage:automated"]))
        self._api_base_url = dest_cfg.get("api_base_url", "https://api.github.com")
        self._allowed_hosts = [
            h.lower() for h in dest_cfg.get("allowed_hosts", ["api.github.com"])
        ]
        self._request_timeout_seconds = float(
            dest_cfg.get("request_timeout_seconds", 15.0)
        )
        self._duplicate_lookback_hours = int(
            dest_cfg.get("duplicate_lookback_hours", 72)
        )
        self._duplicate_max_pages = int(dest_cfg.get("duplicate_max_pages", 10))
        self._precheck_duplicates = bool(dest_cfg.get("precheck_duplicates", True))
        self._api_version = dest_cfg.get("api_version")

        bot_login_cfg = dest_cfg.get("bot_login")
        self._bot_login_cached: str | None = (
            bot_login_cfg.strip()
            if isinstance(bot_login_cfg, str) and bot_login_cfg.strip()
            else None
        )
        self._bot_login_lock = threading.Lock()
        self.config_problem: str | None = None

    def _get_token(self) -> str:
        """Reads and strips the authentication token from environment at call time."""
        if not self._token_env:
            return ""
        return os.environ.get(self._token_env, "").strip()

    def _request(
        self,
        method: str,
        path_or_url: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> requests.Response:
        """Executes a single HTTP request through the session with strict validation."""
        if path_or_url.startswith("https://") or path_or_url.startswith("http://"):
            url = path_or_url
        else:
            base = self._api_base_url.rstrip("/")
            path = path_or_url if path_or_url.startswith("/") else f"/{path_or_url}"
            url = f"{base}{path}"

        # Re-check URL before every call
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise AdapterPermanentError("github_insecure_scheme")
        if parsed.username or parsed.password:
            raise AdapterPermanentError("github_url_credentials_not_allowed")
        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname not in self._allowed_hosts:
            raise AdapterPermanentError("github_host_not_allowed")

        token = self._get_token()
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "email-triage-bot",
        }
        if method.upper() == "POST":
            headers["Content-Type"] = "application/json"
        if self._api_version:
            headers["X-GitHub-Api-Version"] = self._api_version

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

    def validate_config(self) -> bool:
        """Validates adapter configuration without making any network calls."""
        token = self._get_token()
        if not token:
            self.config_problem = "token_missing"
            return False
        if token == "your_github_token_here":  # nosec B105 # noqa: S105
            self.config_problem = "token_placeholder"
            return False
        if not self._target or not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", self._target):
            self.config_problem = "bad_target"
            return False
        if not self._api_base_url:
            self.config_problem = "host_not_allowed"
            return False
        try:
            parsed = urlparse(self._api_base_url)
        except Exception:  # noqa: BLE001
            self.config_problem = "host_not_allowed"
            return False
        if parsed.scheme != "https":
            self.config_problem = "host_not_allowed"
            return False
        if parsed.username or parsed.password:
            self.config_problem = "host_not_allowed"
            return False
        hostname = (parsed.hostname or "").lower()
        if not hostname or hostname not in self._allowed_hosts:
            self.config_problem = "host_not_allowed"
            return False

        self.config_problem = None
        return True

    def health_check(self) -> bool:
        """Executes a non-mutating authentication check against GitHub REST API."""
        try:
            res = self._request("GET", "/user")
            if res.status_code == 200:
                data = res.json()
                return isinstance(data, dict) and bool(data.get("login"))
            return False
        except Exception:  # noqa: BLE001
            return False

    def _bot_login(self) -> str:
        """Resolves and caches the bot username for duplicate filtering."""
        if self._bot_login_cached:
            return self._bot_login_cached

        with self._bot_login_lock:
            if self._bot_login_cached:
                return self._bot_login_cached

            try:
                res = self._request("GET", "/user")
                if res.status_code == 200:
                    data = res.json()
                    if isinstance(data, dict):
                        login = data.get("login")
                        if isinstance(login, str) and login.strip():
                            self._bot_login_cached = login.strip()
                            return self._bot_login_cached
            except AdapterPermanentError:
                raise
            except Exception as exc:
                raise AdapterError("github_bot_login_undetermined") from exc

            raise AdapterError("github_bot_login_undetermined")

    def check_duplicate(
        self,
        idempotency_key: str,
        payload: DispatchPayload,
        now: Callable[[], datetime] | None = None,
    ) -> str | None:
        """Queries repository issues to detect previously created duplicate tickets."""
        bot_login = self._bot_login()
        if "/" not in self._target:
            raise AdapterPermanentError("github_bad_target")
        owner, repo = self._target.split("/", 1)
        path = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/issues"

        now_dt = now() if now is not None else datetime.now(UTC)
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=UTC)
        since_dt = (
            now_dt - timedelta(hours=self._duplicate_lookback_hours)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        for page_num in range(1, self._duplicate_max_pages + 1):
            params: dict[str, Any] = {
                "state": "all",
                "creator": bot_login,
                "since": since_dt,
                "sort": "created",
                "direction": "desc",
                "per_page": 100,
                "page": page_num,
            }

            try:
                res = self._request("GET", path, params=params)
            except AdapterPermanentError:
                raise
            except Exception as exc:
                raise AdapterError("github_duplicate_check_failed") from exc

            if res.status_code != 200:
                raise AdapterError("github_duplicate_check_failed")

            try:
                items = res.json()
            except Exception as exc:
                raise AdapterError("github_duplicate_check_failed") from exc

            if not isinstance(items, list):
                raise AdapterError("github_duplicate_check_failed")

            for item in items:
                if not isinstance(item, dict):
                    continue
                if "pull_request" in item:
                    continue
                user_dict = item.get("user")
                if not isinstance(user_dict, dict):
                    continue
                login = user_dict.get("login")
                if not login or str(login).lower() != bot_login.lower():
                    continue
                item_body = item.get("body")
                if item_body is None or not isinstance(item_body, str):
                    continue
                marker_key = parse_marker(item_body)
                if marker_key == idempotency_key:
                    num = item.get("number")
                    return f"{owner}/{repo}#{num}"

            if len(items) < 100:
                return None

            if len(items) == 100 and page_num == self._duplicate_max_pages:
                raise AdapterError("github_duplicate_scan_truncated")

        return None

    def dispatch(self, payload: DispatchPayload) -> DispatchResult:
        """Transmits the sanitized payload to GitHub Issues API."""
        if not isinstance(payload, DispatchPayload) or payload.action_type != "create_issue":
            raise AdapterPermanentError("github_invalid_action_type")

        try:
            title = sanitize_title(payload.masked_subject, payload.category)
            body = build_issue_body(payload)
            labels = build_labels(payload, base_labels=self._labels)
        except ValueError as exc:
            raise AdapterPermanentError("github_format_invalid") from exc

        if self._precheck_duplicates:
            try:
                remote_id = self.check_duplicate(payload.idempotency_key, payload)
                if remote_id:
                    logger.info(
                        "dispatch email_id=%s status=200 outcome=DispatchResult duplicate=true",
                        payload.email_id,
                    )
                    return DispatchResult(remote_id=remote_id)
            except AdapterPermanentError:
                raise
            except AdapterError as exc:
                raise AdapterTransientError("github_precheck_failed") from exc

        if "/" not in self._target:
            raise AdapterPermanentError("github_bad_target")
        owner, repo = self._target.split("/", 1)
        path = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/issues"
        json_data = {
            "title": title,
            "body": body,
            "labels": labels,
        }

        try:
            res = self._request("POST", path, json_data=json_data)
        except requests.exceptions.SSLError as exc:
            logger.error("dispatch_ssl_error email_id=%s reason=github_ssl_error", payload.email_id)
            raise AdapterPermanentError("github_ssl_error") from exc
        except requests.exceptions.ConnectTimeout as exc:
            logger.warning(
                "dispatch_connect_timeout email_id=%s reason=github_connect_timeout",
                payload.email_id,
            )
            raise AdapterTransientError("github_connect_timeout") from exc
        except requests.exceptions.ConnectionError as exc:
            if _is_connection_setup_error(exc):
                logger.warning(
                    "dispatch_connection_failed email_id=%s reason=github_connection_failed",
                    payload.email_id,
                )
                raise AdapterTransientError("github_connection_failed") from exc
            logger.error(
                "dispatch_connection_error email_id=%s reason=github_connection_error",
                payload.email_id,
            )
            raise AdapterUnknownOutcomeError("github_connection_error") from exc
        except (requests.exceptions.ReadTimeout, requests.exceptions.ChunkedEncodingError) as exc:
            logger.error(
                "dispatch_network_timeout email_id=%s reason=github_network_timeout",
                payload.email_id,
            )
            raise AdapterUnknownOutcomeError("github_network_timeout") from exc
        except AdapterError:
            raise
        except Exception as exc:
            logger.error(
                "dispatch_unknown_error email_id=%s reason=github_unknown_network_error",
                payload.email_id,
            )
            raise AdapterUnknownOutcomeError("github_unknown_network_error") from exc

        status = res.status_code
        if status == 201:
            try:
                data = res.json()
            except Exception as exc:
                logger.error(
                    "dispatch_invalid_json email_id=%s status=%d", payload.email_id, status
                )
                raise AdapterUnknownOutcomeError("github_invalid_response_json") from exc
            if not isinstance(data, dict):
                logger.error(
                    "dispatch_invalid_shape email_id=%s status=%d", payload.email_id, status
                )
                raise AdapterUnknownOutcomeError("github_invalid_response_shape")
            num = data.get("number")
            if not isinstance(num, int) or isinstance(num, bool):
                logger.error(
                    "dispatch_missing_number email_id=%s status=%d", payload.email_id, status
                )
                raise AdapterUnknownOutcomeError("github_missing_issue_number")
            remote_id = f"{owner}/{repo}#{num}"
            logger.info(
                "dispatch email_id=%s status=%d outcome=DispatchResult",
                payload.email_id,
                status,
            )
            return DispatchResult(remote_id=remote_id)

        if 200 <= status < 300:
            logger.error("dispatch_unexpected_2xx email_id=%s status=%d", payload.email_id, status)
            raise AdapterUnknownOutcomeError("github_unexpected_2xx_status")

        if 300 <= status < 400:
            logger.error("dispatch_redirect email_id=%s status=%d", payload.email_id, status)
            raise AdapterPermanentError("github_redirect_error")

        if status == 429:
            logger.warning("dispatch_rate_limited email_id=%s status=%d", payload.email_id, status)
            raise AdapterTransientError("github_rate_limited")

        if status == 403:
            if res.headers.get("x-ratelimit-remaining") == "0":
                logger.warning(
                    "dispatch_primary_rate_limit email_id=%s status=%d",
                    payload.email_id,
                    status,
                )
                raise AdapterTransientError("github_primary_rate_limit")
            if "retry-after" in res.headers:
                logger.warning(
                    "dispatch_secondary_rate_limit email_id=%s status=%d",
                    payload.email_id,
                    status,
                )
                raise AdapterTransientError("github_secondary_rate_limit")
            logger.error("dispatch_forbidden email_id=%s status=%d", payload.email_id, status)
            raise AdapterPermanentError("github_forbidden")

        if 400 <= status < 500:
            logger.error("dispatch_client_error email_id=%s status=%d", payload.email_id, status)
            raise AdapterPermanentError("github_client_error")

        if 500 <= status < 600:
            logger.error("dispatch_server_error email_id=%s status=%d", payload.email_id, status)
            raise AdapterUnknownOutcomeError("github_server_error")

        logger.error("dispatch_unknown_status email_id=%s status=%d", payload.email_id, status)
        raise AdapterUnknownOutcomeError("github_unknown_status")


def create_github_adapter(
    config: dict[str, Any] | None = None,
    session: requests.Session | None = None,
) -> GitHubAdapter:
    """Factory creating a GitHubAdapter instance with optional dependency injection."""
    return GitHubAdapter(config=config, session=session)
