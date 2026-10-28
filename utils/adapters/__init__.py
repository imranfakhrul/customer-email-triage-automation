"""Thread-safe adapter registry and downstream service exports."""

import threading

from utils.adapters.base import (
    AdapterError,
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    BaseDestinationAdapter,
    DispatchPayload,
    DispatchResult,
)
from utils.adapters.freescout_adapter import FreeScoutAdapter
from utils.adapters.github_adapter import GitHubAdapter, create_github_adapter

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


__all__ = [
    "VALID_ADAPTER_NAMES",
    "AdapterError",
    "AdapterPermanentError",
    "AdapterTransientError",
    "AdapterUnknownOutcomeError",
    "BaseDestinationAdapter",
    "DispatchPayload",
    "DispatchResult",
    "FreeScoutAdapter",
    "GitHubAdapter",
    "create_github_adapter",
    "get_adapter",
    "register_adapter",
    "reset_adapters",
]
