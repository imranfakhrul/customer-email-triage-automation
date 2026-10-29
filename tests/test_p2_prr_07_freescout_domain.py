"""Tests for PRR-07: FreeScout Non-Routable Fallback Domain (RFC 2606).

Guarantees:
1. When unmask_pii=False, synthetic customer email addresses MUST use the non-routable
   RFC 2606 domain (@invalid), e.g. 'triage+{email_id}@invalid'.
2. Synthetic customer email addresses MUST NEVER use the customer's real sender_domain,
   preventing agent replies from bouncing or reaching catch-all mailboxes on third-party domains.
3. Thread append payloads (build_thread_reply_payload) similarly use '@invalid' on fallback.
4. When unmask_pii=True and sender_email is missing or empty, customer email falls back
   cleanly to '@invalid' rather than using sender_domain.
5. When unmask_pii=True and sender_email is present, customer email resolves to real sender_email.
"""

from typing import Any
from unittest.mock import MagicMock, patch

from utils.adapters.base import DispatchPayload
from utils.adapters.freescout_adapter import FreeScoutAdapter
from utils.adapters.freescout_format import (
    NON_ROUTABLE_FALLBACK_DOMAIN,
    build_conversation_payload,
    build_thread_reply_payload,
)


class TestFreeScoutNonRoutableFallbackDomain:
    """Tests verifying non-routable @invalid domain in FreeScout formatting."""

    def test_conversation_payload_uses_invalid_domain_when_unmask_pii_false(self) -> None:
        """When unmask_pii=False, customer email uses @invalid and never sender_domain."""
        assert NON_ROUTABLE_FALLBACK_DOMAIN == "invalid"
        record: dict[str, Any] = {
            "email_id": "em_domain_01",
            "message_id": "<msg01@victim-company.com>",
            "thread_id": "th_domain_01",
            "sender_email": "ceo@victim-company.com",
            "sender_domain": "victim-company.com",
            "masked_subject": "Confidential Security Inquiry",
            "masked_body": "Please assist with audit findings.",
        }

        payload = build_conversation_payload(
            record=record,
            mailbox_id=42,
            idempotency_key="em_domain_01:freescout:create_ticket",
            unmask_pii=False,
        )

        expected_fallback = "triage+em_domain_01@invalid"
        assert payload["customer"]["email"] == expected_fallback
        assert payload["threads"][0]["customer"]["email"] == expected_fallback

        # Verify real domain NEVER leaks into customer email
        assert "victim-company.com" not in payload["customer"]["email"]
        assert "victim-company.com" not in payload["threads"][0]["customer"]["email"]

    def test_thread_reply_payload_uses_invalid_domain_when_unmask_pii_false(self) -> None:
        """Thread reply payload fallback must similarly use @invalid."""
        record: dict[str, Any] = {
            "email_id": "em_domain_02",
            "message_id": "<msg02@bank.example.org>",
            "thread_id": "th_domain_02",
            "sender_email": "user@bank.example.org",
            "sender_domain": "bank.example.org",
            "masked_subject": "Follow-up question",
            "masked_body": "Still waiting on response.",
        }

        reply_payload = build_thread_reply_payload(
            record=record,
            idempotency_key="em_domain_02:freescout:reply",
            unmask_pii=False,
        )

        assert reply_payload["customer"]["email"] == "triage+em_domain_02@invalid"
        assert "bank.example.org" not in reply_payload["customer"]["email"]

    def test_fallback_when_unmask_pii_true_but_sender_email_absent(self) -> None:
        """If unmask_pii=True but sender_email is absent/empty, use @invalid fallback."""
        record: dict[str, Any] = {
            "email_id": "em_domain_03",
            "message_id": "<msg03@domain.com>",
            "thread_id": "th_domain_03",
            "sender_email": "",
            "sender_domain": "domain.com",
            "masked_subject": "Missing sender email",
            "masked_body": "Anonymous customer text.",
        }

        payload = build_conversation_payload(
            record=record,
            mailbox_id=1,
            idempotency_key="em_domain_03:freescout:create_ticket",
            unmask_pii=True,
        )

        assert payload["customer"]["email"] == "triage+em_domain_03@invalid"
        assert "domain.com" not in payload["customer"]["email"]

    def test_real_customer_email_used_when_unmask_pii_true(self) -> None:
        """When unmask_pii=True and sender_email is provided, real customer email is used."""
        record: dict[str, Any] = {
            "email_id": "em_domain_04",
            "message_id": "<msg04@legit.io>",
            "thread_id": "th_domain_04",
            "sender_email": "support-seeker@legit.io",
            "sender_domain": "legit.io",
            "masked_subject": "Help ticket",
            "masked_body": "Need assistance.",
        }

        payload = build_conversation_payload(
            record=record,
            mailbox_id=1,
            idempotency_key="em_domain_04:freescout:create_ticket",
            unmask_pii=True,
        )

        assert payload["customer"]["email"] == "support-seeker@legit.io"

    @patch.dict("os.environ", {"FREESCOUT_API_KEY": "test-key"})
    def test_freescout_adapter_dispatch_unmask_pii_false_sends_invalid_domain(self) -> None:
        """FreeScoutAdapter dispatch with unmask_pii=False sends customer email with @invalid."""
        adapter = FreeScoutAdapter(
            target="https://support.example.com",
            mailbox_id=1,
            unmask_pii=False,
        )

        dispatch_payload = DispatchPayload(
            email_id="em_dispatch_domain_01",
            message_id="<msg_disp_01@customer.org>",
            thread_id="th_disp_01",
            category="General Query",
            priority="Medium",
            sentiment="Neutral",
            customer_emotion="Calm",
            summary="General inquiry",
            suggested_team="Support",
            confidence=0.90,
            masked_subject="Masked Subject",
            masked_body="Masked customer body text.",
            sender_domain="customer.org",
            p2_classifier_used="offline_heuristic",
            action_type="create_ticket",
            idempotency_key="em_dispatch_domain_01:freescout:create_ticket",
            sender_email="real.person@customer.org",
        )

        with patch.object(adapter, "_request") as mock_req:
            resp_list = MagicMock()
            resp_list.status_code = 200
            resp_list.json.return_value = {"_embedded": {"conversations": []}}

            resp_post = MagicMock()
            resp_post.status_code = 201
            resp_post.json.return_value = {"id": 99112}

            mock_req.side_effect = [resp_list, resp_post]

            result = adapter.dispatch(dispatch_payload)
            assert result.remote_id == "freescout:99112"

            post_call = mock_req.call_args_list[1]
            sent_json = post_call.kwargs.get("json_data") or post_call[1].get("json_data")
            assert sent_json["customer"]["email"] == "triage+em_dispatch_domain_01@invalid"
            assert "customer.org" not in sent_json["customer"]["email"]
