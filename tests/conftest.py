"""Pytest configuration and test environment isolation fixtures.

Enforces deterministic test isolation (Fix C2):
1. Blocks all unmocked outbound WAN network egress across requests, httpx, and raw sockets.
2. Sanitizes external AI credentials from os.environ by default so tests run hermetically.
3. Resets process-wide singleton caches before and after each test.
"""

import os
import socket
from urllib.parse import urlparse
import pytest

from utils.config import reset_config_cache
from utils.jev_client import reset_default_client
from nodes.classifier import reset_default_classifier_client


# ==============================================================================
# Outbound Network Egress Guard
# ==============================================================================

class NetworkEgressBlockedError(RuntimeError):
    """Raised when an unmocked outbound network call is attempted during tests."""


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _is_loopback(host_or_url: str) -> bool:
    """Returns True if the destination is a local loopback interface or Unix socket."""
    if not host_or_url:
        return False
    s = str(host_or_url).strip().lower()
    if s.startswith("/"):
        return True
    if s in _LOOPBACK_HOSTS:
        return True
    if "://" in s:
        try:
            parsed = urlparse(s)
            return (parsed.hostname or "").lower() in _LOOPBACK_HOSTS
        except Exception:
            return False
    return False


# Guard raw sockets
_orig_socket_connect = socket.socket.connect


def _guarded_socket_connect(self, address):
    host = address[0] if isinstance(address, tuple) and len(address) > 0 else str(address)
    if not _is_loopback(host):
        raise NetworkEgressBlockedError(
            f"CRITICAL: Outbound socket connection blocked in test environment! Destination: {address}"
        )
    return _orig_socket_connect(self, address)


socket.socket.connect = _guarded_socket_connect


# Guard requests HTTPAdapter
try:
    import requests.adapters

    _orig_httpadapter_send = requests.adapters.HTTPAdapter.send

    def _guarded_httpadapter_send(self, request, **kwargs):
        url = str(getattr(request, "url", ""))
        if not _is_loopback(url):
            raise NetworkEgressBlockedError(
                f"CRITICAL: Outbound HTTP request via requests blocked in test environment! URL: {url}"
            )
        return _orig_httpadapter_send(self, request, **kwargs)

    requests.adapters.HTTPAdapter.send = _guarded_httpadapter_send
except ImportError:
    pass


# Guard httpx
try:
    import httpx

    _orig_httpx_handle_request = httpx.HTTPTransport.handle_request

    def _guarded_httpx_handle_request(self, request, *args, **kwargs):
        url = str(getattr(request, "url", ""))
        if not _is_loopback(url):
            raise NetworkEgressBlockedError(
                f"CRITICAL: Outbound HTTP request via httpx blocked in test environment! URL: {url}"
            )
        return _orig_httpx_handle_request(self, request, *args, **kwargs)

    httpx.HTTPTransport.handle_request = _guarded_httpx_handle_request

    if hasattr(httpx, "AsyncHTTPTransport"):
        _orig_httpx_handle_async_request = httpx.AsyncHTTPTransport.handle_async_request

        async def _guarded_httpx_handle_async_request(self, request, *args, **kwargs):
            url = str(getattr(request, "url", ""))
            if not _is_loopback(url):
                raise NetworkEgressBlockedError(
                    f"CRITICAL: Outbound async HTTP request via httpx blocked in test environment! URL: {url}"
                )
            return await _orig_httpx_handle_async_request(self, request, *args, **kwargs)

        httpx.AsyncHTTPTransport.handle_async_request = _guarded_httpx_handle_async_request
except ImportError:
    pass


# ==============================================================================
# Hermetic Test Environment Isolation Fixture
# ==============================================================================

EXTERNAL_API_KEYS = [
    "JEV_API_KEY",
    "GROQ_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "LANGCHAIN_API_KEY",
    "LANGSMITH_API_KEY",
    "GITHUB_TOKEN",
    "FREESCOUT_API_KEY",
    "CRM_API_KEY",
    "WEBHOOK_SECRET_KEY",
    "WEBHOOK_SECRET",
    "GMAIL_CLIENT_ID",
    "GMAIL_CLIENT_SECRET",
    "GMAIL_REFRESH_TOKEN",
    "GMAIL_ACCESS_TOKEN",
]


@pytest.fixture(autouse=True)
def isolate_test_environment(monkeypatch):
    """Ensures each test runs in a clean, hermetic environment without ambient API keys."""
    # Strip ambient external credentials unless explicitly set within the test itself
    for key in EXTERNAL_API_KEYS:
        if key in os.environ:
            monkeypatch.delenv(key, raising=False)

    reset_config_cache()
    reset_default_client()
    reset_default_classifier_client()

    yield

    reset_config_cache()
    reset_default_client()
    reset_default_classifier_client()
