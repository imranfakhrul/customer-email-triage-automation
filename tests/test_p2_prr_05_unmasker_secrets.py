"""Tests for PRR-05: Unmasker Missing Text Safeguard & Re-Fetch Secret Scrubbing.

Guarantees:
1. Invariant 5: If masked text ('masked_subject' or 'masked_body') is missing or None,
   resolve_dispatch_content fails closed by raising ValueError (diverting to HITL review).
2. Raw fallback elimination: Unmasker never reads raw 'body', 'cleaned_body', 'email_body',
   or 'subject' fields.
3. Invariant 1: When re-fetching original email via mailbox_fetcher (worker mode), re-fetched
   text is re-masked and high-risk secrets (CREDIT_CARD, SSN, IBAN, API_KEY) remain strictly
   redacted placeholder tokens, while allowed contact entities (PERSON, EMAIL, PHONE, IP_ADDRESS)
   are selectively restored.
4. Invariant 2: token_map is never returned or leaked outside the unmasker.
"""

from typing import Any

import pytest

from utils.unmasker import resolve_dispatch_content


class TestUnmaskerMissingTextSafeguards:
    """Tests verifying fail-closed behavior when masked text is absent."""

    def test_missing_masked_subject_raises_value_error(self) -> None:
        """When masked_subject is None or omitted, raise ValueError."""
        record: dict[str, Any] = {
            "email_id": "em_err_01",
            "masked_body": "Here is the masked body.",
            "sender_email": "user@example.com",
        }
        with pytest.raises(ValueError, match="required masked text"):
            resolve_dispatch_content(record, unmask_pii=False)

        record_none = dict(record, masked_subject=None)
        with pytest.raises(ValueError, match="required masked text"):
            resolve_dispatch_content(record_none, unmask_pii=False)

    def test_missing_masked_body_raises_value_error(self) -> None:
        """When masked_body is None or omitted, raise ValueError."""
        record: dict[str, Any] = {
            "email_id": "em_err_02",
            "masked_subject": "Valid Masked Subject",
            "sender_email": "user@example.com",
        }
        with pytest.raises(ValueError, match="required masked text"):
            resolve_dispatch_content(record, unmask_pii=False)

        record_none = dict(record, masked_body=None)
        with pytest.raises(ValueError, match="required masked text"):
            resolve_dispatch_content(record_none, unmask_pii=False)

    def test_never_falls_back_to_raw_body_or_subject(self) -> None:
        """Raw body, cleaned_body, email_body, and subject must not be read."""
        raw_record: dict[str, Any] = {
            "email_id": "em_err_03",
            "subject": "Raw Subject",
            "body": "Raw customer body with card 4111 1111 1111 1111",
            "cleaned_body": "Cleaned body with secret",
            "email_body": "Email body with secret",
            "sender_email": "user@example.com",
        }
        # Without masked_subject and masked_body, it must raise rather than reading raw fields
        with pytest.raises(ValueError, match="required masked text"):
            resolve_dispatch_content(raw_record, unmask_pii=False)

    def test_empty_masked_body_does_not_fall_back_to_raw_body(self) -> None:
        """Empty string masked_body must not evaluate 'or body' to expose raw text."""
        record: dict[str, Any] = {
            "email_id": "em_err_04",
            "masked_subject": "Subject Line",
            "masked_body": "",
            "body": "LEAKED_RAW_BODY_CONTENT_12345",
            "sender_email": "user@example.com",
        }
        result = resolve_dispatch_content(record, unmask_pii=False)
        assert result["body"] == ""
        assert "LEAKED_RAW_BODY_CONTENT_12345" not in result["body"]


class TestUnmaskerMailboxRefetchSecretScrubbing:
    """Tests verifying secret scrubbing and contact unmasking on mailbox re-fetch."""

    def test_mailbox_refetch_scrubs_secrets_while_restoring_contact_entities(self) -> None:
        """Mailbox re-fetch re-masks raw text: secrets remain masked, contact info restored."""
        raw_mailbox_text = (
            "Hi Support, I am Alice Cooper at alice@company.com, phone +1 555-0199. "
            "My card is 4111 1111 1111 1111, SSN 123-45-6789, and my server is 192.168.1.50."
        )

        record: dict[str, Any] = {
            "email_id": "em_refetch_01",
            "message_id": "<refetch_msg_001@company.com>",
            "sender_email": "alice@company.com",
            "sender_domain": "company.com",
            "masked_subject": "Billing inquiry for [PERSON_1_xxxx]",
            "masked_body": "Masked body placeholder from database.",
            "token_map": None,  # absent in worker mode
        }

        def fake_mailbox_fetcher(msg_id: str) -> str:
            assert msg_id == "<refetch_msg_001@company.com>"
            return raw_mailbox_text

        result = resolve_dispatch_content(
            record,
            unmask_pii=True,
            mailbox_fetcher=fake_mailbox_fetcher,
        )

        body = result["body"]

        # Safe contact entities ARE restored
        assert "Alice Cooper" in body
        assert "alice@company.com" in body
        assert "+1 555-0199" in body
        assert "192.168.1.50" in body

        # High-risk secrets MUST REMAIN MASKED with placeholder tokens
        assert "4111 1111 1111 1111" not in body
        assert "[CREDIT_CARD_1_" in body

        assert "123-45-6789" not in body
        assert "[SSN_1_" in body

        # Invariant checks
        assert result["customer_email"] == "alice@company.com"
        assert result["is_unmasked"] is True
        assert "CREDIT_CARD" not in result["restored_entity_types"]
        assert "SSN" not in result["restored_entity_types"]

    def test_mailbox_refetch_with_unmask_pii_false_does_not_call_fetcher(self) -> None:
        """When unmask_pii=False, mailbox_fetcher is never called and masked text is returned."""
        fetcher_called = False

        def spy_fetcher(msg_id: str) -> str:
            nonlocal fetcher_called
            fetcher_called = True
            return "Raw text that should never be fetched"

        record: dict[str, Any] = {
            "email_id": "em_refetch_02",
            "message_id": "<refetch_msg_002@company.com>",
            "sender_email": "bob@example.com",
            "masked_subject": "Subject with [PERSON_1_0000]",
            "masked_body": "Body with [CREDIT_CARD_1_0000]",
            "token_map": None,
        }

        result = resolve_dispatch_content(
            record,
            unmask_pii=False,
            mailbox_fetcher=spy_fetcher,
        )

        assert fetcher_called is False
        assert result["subject"] == "Subject with [PERSON_1_0000]"
        assert result["body"] == "Body with [CREDIT_CARD_1_0000]"
        assert result["customer_email"] is None

    def test_mailbox_refetch_handles_fetcher_exception_fail_closed(self) -> None:
        """If mailbox_fetcher raises an exception, fall back safely to masked_body."""
        def broken_fetcher(msg_id: str) -> str:
            raise ConnectionError("Mailbox API connection timeout")

        record: dict[str, Any] = {
            "email_id": "em_refetch_03",
            "message_id": "<broken_msg_003@company.com>",
            "sender_email": "carol@example.com",
            "masked_subject": "Safe Masked Subject",
            "masked_body": "Safe Masked Body with [PERSON_1_1111]",
            "token_map": None,
        }

        result = resolve_dispatch_content(
            record,
            unmask_pii=True,
            mailbox_fetcher=broken_fetcher,
        )

        # Falls back cleanly to masked_body
        assert result["body"] == "Safe Masked Body with [PERSON_1_1111]"
        assert result["customer_email"] == "carol@example.com"
