"""Unit tests for Fix C2: Deterministic Test Environment Isolation.

Verifies:
1. Outbound network egress via requests, httpx, and raw sockets is blocked.
2. Loopback connections (127.0.0.1 / localhost) remain unblocked by the egress guard.
3. Ambient live API keys in host environment are hermetically stripped by default.
4. Pipeline with offline=True runs deterministically without network egress even if keys are set.
5. JevClient with missing/placeholder keys operates deterministically offline.
"""

import os
import socket
import unittest
from unittest.mock import patch

import pytest
import requests
import httpx

from db.database import TriageDatabase
from pipeline import create_triage_pipeline, run_triage_pipeline
from tests.conftest import NetworkEgressBlockedError
from utils.jev_client import JevClient


class TestDeterministicTestIsolation(unittest.TestCase):
    """Verifies test environment hermetic isolation and zero outbound network egress."""

    def test_unmocked_requests_to_external_api_blocked(self):
        """Unmocked HTTP request via requests to external domain must raise NetworkEgressBlockedError."""
        with pytest.raises(NetworkEgressBlockedError) as exc_info:
            requests.post(
                "https://api.typesafe.ai/v1/systemone",
                json={"test": "payload"},
                timeout=2.0,
            )
        assert "api.typesafe.ai" in str(exc_info.value)

    def test_unmocked_httpx_to_external_api_blocked(self):
        """Unmocked HTTP request via httpx to external domain must raise NetworkEgressBlockedError."""
        with pytest.raises(NetworkEgressBlockedError) as exc_info:
            httpx.get("https://api.groq.com/openai/v1/models", timeout=2.0)
        assert "api.groq.com" in str(exc_info.value)

    def test_raw_socket_to_external_ip_blocked(self):
        """Unmocked raw socket connect to WAN IP must raise NetworkEgressBlockedError."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(NetworkEgressBlockedError) as exc_info:
                s.connect(("8.8.8.8", 53))
            assert "8.8.8.8" in str(exc_info.value)
        finally:
            s.close()

    def test_loopback_connection_not_blocked_by_guard(self):
        """Loopback address (127.0.0.1) must not be rejected by NetworkEgressBlockedError."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Connecting to a closed local port raises ConnectionRefusedError, NOT NetworkEgressBlockedError
            with pytest.raises(Exception) as exc_info:
                s.connect(("127.0.0.1", 59999))
            assert not isinstance(exc_info.value, NetworkEgressBlockedError)
            assert isinstance(exc_info.value, ConnectionRefusedError)
        finally:
            s.close()

    def test_ambient_keys_stripped_by_isolation_fixture(self):
        """External AI and integration keys must be absent by default in tests despite host .env."""
        keys_to_check = [
            "JEV_API_KEY",
            "GROQ_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "FREESCOUT_API_KEY",
            "CRM_API_KEY",
            "WEBHOOK_SECRET_KEY",
            "WEBHOOK_SECRET",
            "GMAIL_CLIENT_ID",
            "GMAIL_CLIENT_SECRET",
            "GMAIL_REFRESH_TOKEN",
        ]
        for key in keys_to_check:
            assert os.environ.get(key) is None or os.environ.get(key) == ""

    def test_offline_pipeline_with_real_looking_keys_completes_offline(self):
        """Pipeline with offline=True completes deterministically offline even if keys are injected."""
        with patch.dict(os.environ, {
            "JEV_API_KEY": "sk_live_super_secret_token_12345",
            "GROQ_API_KEY": "gsk_live_super_secret_token_12345",
        }):
            import tempfile
            temp_dir = tempfile.TemporaryDirectory()
            try:
                db_path = os.path.join(temp_dir.name, "c2_test.db")
                db = TriageDatabase(db_path=db_path)
                pipeline = create_triage_pipeline(db=db, offline=True)

                payload = {
                    "email_id": "em_c2_test_offline_001",
                    "sender_email": "client@enterprise.com",
                    "email_subject": "Production question regarding API limits",
                    "email_body": "Hello support, what are the daily rate limits for webhooks? Thanks!",
                }
                res = run_triage_pipeline(payload, pipeline=pipeline, db=db, offline=True)
                assert res.get("routing_status") == "gatekeeper_approved"
                assert res.get("dispatch_status") == "done"
            finally:
                temp_dir.cleanup()

    def test_jev_client_with_dummy_keys_respects_mock(self):
        """Explicit mock post is honored while real egress remains blocked."""
        with patch("requests.post") as mock_post:
            mock_resp = unittest.mock.MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "answers": {
                    "is_spam": {"type": "noul", "noul": 0.05},
                    "is_threat": {"type": "noul", "noul": 0.02},
                }
            }
            mock_post.return_value = mock_resp

            client = JevClient(api_key="sk_test_dummy_key", groq_api_key="")
            result = client.classify(
                subject="Pricing inquiry",
                body="We want to upgrade to Enterprise plan.",
                sender="buyer@corp.com",
            )
            assert result.get("decision") == "legitimate"
            assert result.get("classifier_used") == "jev"
            assert mock_post.called
