"""Test suite verifying Gmail Pub/Sub Mailbox Connector & Auth Lifecycle (P2-12)."""

import base64
from typing import Any
from unittest.mock import MagicMock

import pytest

from utils.mailbox.base import BaseMailboxConnector
from utils.mailbox.gmail_connector import (
    GmailConnector,
    decode_base64url,
    extract_email_auth_results,
    parse_gmail_message_payload,
)
from utils.unmasker import resolve_dispatch_content


def _encode_b64url(text: str) -> str:
    """Helper to encode text to base64url without padding."""
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8").rstrip("=")


class TestBaseMailboxConnector:
    """Tests for abstract BaseMailboxConnector."""

    def test_cannot_instantiate_abstract_base_connector(self):
        with pytest.raises(TypeError):
            BaseMailboxConnector()  # type: ignore[abstract]


class TestMimeDecodingAndAuthHeaders:
    """Tests for MIME parsing, base64url decoding, and SPF/DKIM/DMARC evaluation."""

    def test_decode_base64url_with_and_without_padding(self):
        raw = "Hello, this is a customer inquiry with special characters & symbols: <>&"
        encoded_unpadded = _encode_b64url(raw)
        assert decode_base64url(encoded_unpadded) == raw

        # Also test with manual padding
        padded = encoded_unpadded + "=="
        assert decode_base64url(padded) == raw

    def test_parse_gmail_message_payload_multipart_alternative(self):
        body_text = "Postgres connection pool exhausted since morning."
        body_html = "<p>Postgres connection pool exhausted since morning.</p>"

        payload = {
            "id": "msg_12345",
            "threadId": "thread_abcde",
            "snippet": "Postgres connection pool...",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Postgres pool OOM crash"},
                    {"name": "From", "value": "Alice Admin <alice@enterprise.com>"},
                    {"name": "To", "value": "support@mycompany.com"},
                    {"name": "Date", "value": "Wed, 28 Oct 2026 12:00:00 +0000"},
                    {"name": "Message-ID", "value": "<msg_12345@enterprise.com>"},
                ],
                "mimeType": "multipart/alternative",
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {"data": _encode_b64url(body_text), "size": len(body_text)},
                    },
                    {
                        "mimeType": "text/html",
                        "body": {"data": _encode_b64url(body_html), "size": len(body_html)},
                    },
                ],
            },
        }

        parsed = parse_gmail_message_payload(payload)
        assert parsed["email_id"] == "msg_12345"
        assert parsed["message_id"] == "<msg_12345@enterprise.com>"
        assert parsed["thread_id"] == "thread_abcde"
        assert parsed["sender_email"] == "alice@enterprise.com"
        assert parsed["sender_domain"] == "enterprise.com"
        assert parsed["email_subject"] == "Postgres pool OOM crash"
        assert parsed["email_body"] == body_text
        assert parsed["raw_body"] == body_text

    def test_parse_gmail_message_html_only_fallback(self):
        html_content = "<div>Please <b>reset</b> my 2FA access token.</div>"
        payload = {
            "id": "msg_html_only",
            "threadId": "thread_html",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "2FA Reset"},
                    {"name": "From", "value": "bob@client.io"},
                    {"name": "Message-ID", "value": "<html_msg@client.io>"},
                ],
                "mimeType": "text/html",
                "body": {"data": _encode_b64url(html_content)},
            },
        }

        parsed = parse_gmail_message_payload(payload)
        assert parsed["sender_email"] == "bob@client.io"
        assert "Please reset my 2FA access token." in parsed["email_body"]

    def test_extract_email_auth_results_pass(self):
        headers = [
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; "
                    "dkim=pass header.i=@enterprise.com header.s=20230601; "
                    "spf=pass (google.com: domain of alice@enterprise.com designates 192.0.2.1); "
                    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=enterprise.com"
                ),
            },
            {
                "name": "Received-SPF",
                "value": "pass (google.com: domain of alice@enterprise.com designates 192.0.2.1)",
            },
        ]
        auth = extract_email_auth_results(headers)
        assert auth["auth_status"] == "pass"
        assert auth["spf"] == "pass"
        assert auth["dkim"] == "pass"
        assert auth["dmarc"] == "pass"

    def test_extract_email_auth_results_spoofed_fail(self):
        headers = [
            {
                "name": "Authentication-Results",
                "value": (
                    "mx.google.com; "
                    "dkim=fail (bad signature) header.i=@bank.com; "
                    "spf=fail (domain of attacker@evil.org does not designate 198.51.100.1); "
                    "dmarc=fail (p=REJECT) header.from=bank.com"
                ),
            },
            {"name": "Received-SPF", "value": "fail"},
        ]
        auth = extract_email_auth_results(headers)
        assert auth["auth_status"] == "fail"
        assert auth["spf"] == "fail"
        assert auth["dkim"] == "fail"
        assert auth["dmarc"] == "fail"

    def test_extract_email_auth_results_missing_headers(self):
        headers = [{"name": "Subject", "value": "No auth headers"}]
        auth = extract_email_auth_results(headers)
        assert auth["auth_status"] == "none"
        assert auth["spf"] == "none"
        assert auth["dkim"] == "none"
        assert auth["dmarc"] == "none"

    def test_pipeline_prepare_and_ingest_preserves_auth_status(self):
        """Verify that prepare_initial_state and ingest_node preserve auth_status."""
        from nodes.ingest import ingest_node
        from pipeline import prepare_initial_state

        raw_payload = {
            "email_id": "em_auth_pres_01",
            "message_id": "<auth01@acme.com>",
            "sender_email": "alice@acme.com",
            "email_subject": "Auth Status Pipeline Test",
            "email_body": "Checking auth preservation.",
            "auth_status": "pass",
        }

        # 1. Test prepare_initial_state
        initial = prepare_initial_state(raw_payload)
        assert initial.get("auth_status") == "pass"

        # 2. Test ingest_node
        ingested = ingest_node(initial, db=None)
        assert ingested.get("auth_status") == "pass"



class TestGmailConnectorLifecycleAndAPI:
    """Tests for OAuth lifecycle, history sync, and original text re-fetch."""

    @pytest.fixture
    def mock_session(self):
        session = MagicMock()
        return session

    def test_token_auto_refresh_on_initialization_or_expiry(self, mock_session):
        # Configure mock response for token endpoint
        token_response = MagicMock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "ya29.new_refreshed_access_token_12345",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_session.post.return_value = token_response

        connector = GmailConnector(
            client_id="mock_client_id.apps.googleusercontent.com",
            client_secret="mock_client_secret",
            refresh_token="mock_refresh_token",
            session=mock_session,
        )

        token = connector.get_valid_access_token()
        assert token == "ya29.new_refreshed_access_token_12345"
        mock_session.post.assert_called_once()
        assert "oauth2.googleapis.com/token" in mock_session.post.call_args[0][0]

    def test_fetch_history_incremental_sync(self, mock_session):
        connector = GmailConnector(
            access_token="mock_access_token",
            session=mock_session,
        )

        history_resp = MagicMock()
        history_resp.status_code = 200
        history_resp.json.return_value = {
            "history": [
                {
                    "id": "1001",
                    "messagesAdded": [
                        {"message": {"id": "msg_001", "threadId": "thread_001"}},
                        {"message": {"id": "msg_002", "threadId": "thread_002"}},
                    ],
                },
                {
                    "id": "1002",
                    "messagesAdded": [
                        {"message": {"id": "msg_002", "threadId": "thread_002"}},  # Duplicate ID
                        {"message": {"id": "msg_003", "threadId": "thread_003"}},
                    ],
                },
            ],
            "historyId": "1003",
        }
        mock_session.get.return_value = history_resp

        messages = connector.fetch_new_messages(start_history_id="1000")
        assert len(messages) == 3
        msg_ids = [m["id"] for m in messages]
        assert msg_ids == ["msg_001", "msg_002", "msg_003"]

    def test_refetch_original_email_lookup(self, mock_session):
        connector = GmailConnector(
            access_token="mock_access_token",
            session=mock_session,
        )

        raw_body_text = "Original unmasked customer problem: Call me at +1 555-0199."
        msg_resp = MagicMock()
        msg_resp.status_code = 200
        msg_resp.json.return_value = {
            "id": "msg_original_01",
            "threadId": "thread_01",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Original Subject Line"},
                    {"name": "From", "value": "Customer Name <customer@domain.com>"},
                    {"name": "Message-ID", "value": "<msg_orig_01@domain.com>"},
                ],
                "mimeType": "text/plain",
                "body": {"data": _encode_b64url(raw_body_text)},
            },
        }
        mock_session.get.return_value = msg_resp

        fetched = connector.refetch_original_email("msg_original_01")
        assert fetched is not None
        assert fetched["email_body"] == raw_body_text
        assert fetched["sender_email"] == "customer@domain.com"

        # Verify integration with unmasker.resolve_dispatch_content
        mock_record: dict[str, Any] = {
            "message_id": "msg_original_01",
            "sender_email": "customer@domain.com",
            "sender_domain": "domain.com",
            "masked_subject": "Masked Subject",
            "masked_body": "[PERSON_1] called regarding outage.",
            "token_map": None,  # Token map absent in worker mode!
        }

        resolved = resolve_dispatch_content(
            mock_record,
            unmask_pii=True,
            mailbox_fetcher=(
                lambda mid: fetched["email_body"] if mid == "msg_original_01" else None
            ),
        )
        assert resolved["body"] == raw_body_text
        assert resolved["customer_email"] == "customer@domain.com"
        assert resolved["is_unmasked"] is True

    def test_setup_watch_subscription(self, mock_session):
        connector = GmailConnector(
            access_token="mock_access_token",
            session=mock_session,
        )

        watch_resp = MagicMock()
        watch_resp.status_code = 200
        watch_resp.json.return_value = {
            "historyId": "99999",
            "expiration": "1761667200000",
        }
        mock_session.post.return_value = watch_resp

        result = connector.setup_watch(
            topic_name="projects/my-triage-project/topics/gmail-push-topic",
            label_ids=["INBOX"],
        )
        assert result["historyId"] == "99999"
        assert result["expiration"] == "1761667200000"
        mock_session.post.assert_called_once()
        assert "users/me/watch" in mock_session.post.call_args[0][0]


class TestEmlFileParser:
    """Tests for native RFC 822 .eml MIME parsing."""

    def test_parse_eml_bytes_plain_text(self):
        from utils.mailbox.eml_parser import parse_eml_bytes

        raw_eml = (
            b'From: Alex Chen <alex.chen@innovatech.com>\r\n'
            b'To: support@triage.internal\r\n'
            b'Subject: Production crash on checkout\r\n'
            b'Date: Fri, 30 Oct 2026 00:00:00 +0000\r\n'
            b'Message-ID: <msg-12345@innovatech.com>\r\n'
            b'Authentication-Results: mx.google.com; dkim=pass; spf=pass\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n'
            b'\r\n'
            b'Hi Support Team,\r\n'
            b'Our checkout crashes with 500 error. Call me at +1 555-0199.\r\n'
            b'Sent from my iPhone\r\n'
        )

        parsed = parse_eml_bytes(raw_eml)
        assert parsed["sender_email"] == "alex.chen@innovatech.com"
        assert parsed["sender_domain"] == "innovatech.com"
        assert parsed["email_subject"] == "Production crash on checkout"
        assert parsed["message_id"] == "<msg-12345@innovatech.com>"
        assert parsed["auth_status"] == "pass"
        assert "checkout crashes with 500 error" in parsed["email_body"]
        assert "Sent from my iPhone" in parsed["email_body"]

