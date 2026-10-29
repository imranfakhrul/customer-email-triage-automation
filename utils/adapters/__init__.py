"""Thread-safe adapter registry and downstream service exports."""

import logging
import threading
from typing import Any

from utils.adapters.base import (
    AdapterError,
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
)
from utils.adapters.crm_adapter import CRMAdapter
from utils.adapters.freescout_adapter import FreeScoutAdapter
from utils.adapters.github_adapter import GitHubAdapter, create_github_adapter
from utils.adapters.webhook_adapter import WebhookAdapter
from utils.config import get_config

logger = logging.getLogger("triage.adapters")

VALID_ADAPTER_NAMES = ("github", "freescout", "crm", "webhook")

_ADAPTER_REGISTRY: dict[str, BaseDestinationAdapter] = {}
_REGISTRY_LOCK = threading.Lock()


def register_adapter(name: str, adapter: BaseDestinationAdapter) -> None:
    """Registers an adapter instance under a canonical service name.

    Thread-safe.

    Args:
        name: One of ('github', 'freescout', 'crm', 'webhook').
        adapter: Instance of BaseDestinationAdapter.

    Raises:
        ValueError: If name is not a permitted service name or adapter is invalid.
    """
    if name not in VALID_ADAPTER_NAMES:
        raise ValueError(
            f"Invalid adapter name '{name}'. Permitted names: {VALID_ADAPTER_NAMES}"
        )
    if not isinstance(adapter, BaseDestinationAdapter):
        raise ValueError(
            f"Adapter must be an instance of BaseDestinationAdapter, got {type(adapter).__name__}"
        )

    with _REGISTRY_LOCK:
        _ADAPTER_REGISTRY[name] = adapter


def get_adapter(name: str) -> BaseDestinationAdapter | None:
    """Retrieves the registered adapter instance for a canonical service name.

    Thread-safe.

    Args:
        name: One of ('github', 'freescout', 'crm', 'webhook').

    Returns:
        The registered BaseDestinationAdapter instance, or None if not registered.

    Raises:
        ValueError: If name is not a permitted service name.
    """
    if name not in VALID_ADAPTER_NAMES:
        raise ValueError(
            f"Invalid adapter name '{name}'. Permitted names: {VALID_ADAPTER_NAMES}"
        )

    with _REGISTRY_LOCK:
        return _ADAPTER_REGISTRY.get(name)


def reset_adapters() -> None:
    """Clears all registered adapters (used for test isolation)."""
    with _REGISTRY_LOCK:
        _ADAPTER_REGISTRY.clear()


def register_active_adapters(
    config: dict[str, Any] | None = None,
) -> dict[str, BaseDestinationAdapter]:
    """Registers adapters for all destinations marked as enabled in configuration.

    Thread-safe and idempotent. Only instantiates and registers adapters for
    destinations where 'enabled: true' in config['destinations'].

    Args:
        config: System configuration dictionary. If None, loaded via get_config().

    Returns:
        Dictionary of active, registered adapters keyed by destination name.
    """
    if config is None:
        config = get_config()

    destinations_cfg = config.get("destinations", {})
    if not isinstance(destinations_cfg, dict):
        return {}

    registered: dict[str, BaseDestinationAdapter] = {}

    for name in VALID_ADAPTER_NAMES:
        dest_cfg = destinations_cfg.get(name)
        if not isinstance(dest_cfg, dict) or not dest_cfg.get("enabled", False):
            continue

        with _REGISTRY_LOCK:
            existing = _ADAPTER_REGISTRY.get(name)
            if existing is not None:
                registered[name] = existing
                continue

        # Instantiate enabled adapter
        try:
            adapter: BaseDestinationAdapter | None = None
            if name == "github":
                adapter = GitHubAdapter(config=config)
            elif name == "freescout":
                adapter = FreeScoutAdapter(
                    target=dest_cfg.get("target"),
                    api_key_env=dest_cfg.get("api_key_env", "FREESCOUT_API_KEY"),
                    mailbox_id=dest_cfg.get("mailbox_id"),
                    unmask_pii=bool(dest_cfg.get("unmask_pii", True)),
                    allowed_hosts=dest_cfg.get("allowed_hosts"),
                    request_timeout_seconds=float(
                        dest_cfg.get("request_timeout_seconds", 15.0)
                    ),
                    precheck_duplicates=bool(
                        dest_cfg.get("precheck_duplicates", True)
                    ),
                )
            elif name == "crm":
                adapter = CRMAdapter(
                    target=dest_cfg.get("target"),
                    api_key_env=dest_cfg.get("api_key_env", "CRM_API_KEY"),
                    unmask_pii=bool(dest_cfg.get("unmask_pii", True)),
                    allowed_hosts=dest_cfg.get("allowed_hosts"),
                    request_timeout_seconds=float(
                        dest_cfg.get("request_timeout_seconds", 15.0)
                    ),
                    precheck_duplicates=bool(
                        dest_cfg.get("precheck_duplicates", True)
                    ),
                )
            elif name == "webhook":
                adapter = WebhookAdapter(
                    target=dest_cfg.get("target"),
                    secret_env=dest_cfg.get("secret_env", "WEBHOOK_SECRET_KEY"),
                    unmask_pii=bool(dest_cfg.get("unmask_pii", False)),
                    allowed_hosts=dest_cfg.get("allowed_hosts"),
                    request_timeout_seconds=float(
                        dest_cfg.get("request_timeout_seconds", 10.0)
                    ),
                )

            if adapter is not None:
                register_adapter(name, adapter)
                registered[name] = adapter
                logger.info(
                    "[AdapterRegistry] Registered active adapter for destination: %s",
                    name,
                )
        except (AdapterError, ValueError, KeyError, TypeError, OSError) as exc:
            logger.warning(
                "[AdapterRegistry] Failed to initialize adapter '%s': %s",
                name,
                exc.__class__.__name__,
            )

    return registered


__all__ = [
    "VALID_ADAPTER_NAMES",
    "AdapterError",
    "AdapterPermanentError",
    "AdapterTransientError",
    "AdapterUnknownOutcomeError",
    "BaseDestinationAdapter",
    "CRMAdapter",
    "DispatchPayload",
    "DispatchResult",
    "FreeScoutAdapter",
    "GitHubAdapter",
    "WebhookAdapter",
    "create_github_adapter",
    "get_adapter",
    "register_active_adapters",
    "register_adapter",
    "reset_adapters",
]
