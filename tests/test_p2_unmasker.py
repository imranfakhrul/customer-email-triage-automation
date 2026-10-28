"""Tests for Universal Selective Unmasking helper (utils/unmasker.py)."""


from utils.unmasker import (
    resolve_dispatch_content,
)


def test_unmasker_when_unmask_pii_false_strictly_returns_masked_text():
    """Invariant: When unmask_pii=False, returns strictly masked text and no raw customer email."""
    record = {
        "email_id": "em_001",
        "sender_email": "john.doe@company.com",
        "sender_domain": "company.com",
        "masked_subject": "Urgent ticket for [PERSON_1_a1b2]",
        "masked_body": "Contact me at [EMAIL_1_c3d4] or card [CREDIT_CARD_1_e5f6].",
        "token_map": {
            "[PERSON_1_a1b2]": "John Doe",
            "[EMAIL_1_c3d4]": "john.doe@company.com",
            "[CREDIT_CARD_1_e5f6]": "4111-2222-3333-4444",
        },
    }

    result = resolve_dispatch_content(record, unmask_pii=False)

    assert result["subject"] == "Urgent ticket for [PERSON_1_a1b2]"
    assert result["body"] == "Contact me at [EMAIL_1_c3d4] or card [CREDIT_CARD_1_e5f6]."
    assert result["customer_email"] is None
    assert result["sender_domain"] == "company.com"
    assert result["is_unmasked"] is False
    assert result["restored_entity_types"] == ()


def test_unmasker_restores_contact_entities_but_blocks_secrets():
    """Invariant: When unmask_pii=True, PERSON, EMAIL, PHONE, IP_ADDRESS are restored,

    while CREDIT_CARD, SSN, IBAN, API_KEY remain strictly masked.
    """
    record = {
        "email_id": "em_002",
        "sender_email": "alice@fintech.io",
        "sender_domain": "fintech.io",
        "masked_subject": "Issue for [PERSON_1_99aa] from [IP_ADDRESS_1_11bb]",
        "masked_body": (
            "Hi, I am [PERSON_1_99aa] at [EMAIL_1_22cc], phone [PHONE_1_33dd]. "
            "My card [CREDIT_CARD_1_44ee], SSN [SSN_1_55ff], IBAN [IBAN_1_66gg], and "
            "key [API_KEY_1_77hh] failed."
        ),
        "token_map": {
            "[PERSON_1_99aa]": "Alice Cooper",
            "[EMAIL_1_22cc]": "alice@fintech.io",
            "[PHONE_1_33dd]": "+1-555-0199",
            "[IP_ADDRESS_1_11bb]": "192.168.1.100",
            "[CREDIT_CARD_1_44ee]": "4111-2222-3333-4444",
            "[SSN_1_55ff]": "123-45-6789",
            "[IBAN_1_66gg]": "GB82WEST12345698765432",
            "[API_KEY_1_77hh]": "sk-proj-supersecretkey12345",
        },
    }

    result = resolve_dispatch_content(record, unmask_pii=True)

    # Subject restored contact/IP
    assert result["subject"] == "Issue for Alice Cooper from 192.168.1.100"

    # Body restored contact info
    assert "Hi, I am Alice Cooper at alice@fintech.io, phone +1-555-0199." in result["body"]

    # Secrets REMAIN MASKED
    assert "[CREDIT_CARD_1_44ee]" in result["body"]
    assert "4111-2222-3333-4444" not in result["body"]

    assert "[SSN_1_55ff]" in result["body"]
    assert "123-45-6789" not in result["body"]

    assert "[IBAN_1_66gg]" in result["body"]
    assert "GB82WEST12345698765432" not in result["body"]

    assert "[API_KEY_1_77hh]" in result["body"]
    assert "sk-proj-supersecretkey12345" not in result["body"]

    # Customer email bound to real sender
    assert result["customer_email"] == "alice@fintech.io"
    assert result["sender_domain"] == "fintech.io"
    assert result["is_unmasked"] is True
    assert set(result["restored_entity_types"]) == {"PERSON", "EMAIL", "PHONE", "IP_ADDRESS"}


def test_unmasker_fallback_when_token_map_missing():
    """Worker mode fallback: When token_map is absent, binds customer_email to sender_email

    and retains masked_body (or calls optional mailbox_fetcher).
    """
    record = {
        "email_id": "em_003",
        "message_id": "<msg003@domain.com>",
        "sender_email": "bob@domain.com",
        "sender_domain": "domain.com",
        "masked_subject": "Help with [PERSON_1_0000]",
        "masked_body": "Please email [EMAIL_1_0000].",
        # token_map is absent
    }

    # Case A: No mailbox_fetcher
    result_no_fetcher = resolve_dispatch_content(record, unmask_pii=True)
    assert result_no_fetcher["subject"] == "Help with [PERSON_1_0000]"
    assert result_no_fetcher["body"] == "Please email [EMAIL_1_0000]."
    assert result_no_fetcher["customer_email"] == "bob@domain.com"
    assert result_no_fetcher["is_unmasked"] is True

    # Case B: With mailbox_fetcher
    def fake_fetcher(msg_id: str) -> str:
        assert msg_id == "<msg003@domain.com>"
        return "Unmasked raw body from authorized mailbox connector."

    result_with_fetcher = resolve_dispatch_content(
        record, unmask_pii=True, mailbox_fetcher=fake_fetcher
    )
    assert result_with_fetcher["body"] == "Unmasked raw body from authorized mailbox connector."
    assert result_with_fetcher["customer_email"] == "bob@domain.com"


def test_unmasker_custom_allowed_entities():
    """Verify that specifying custom allowed_entity_types restricts restoration."""
    record = {
        "email_id": "em_004",
        "sender_email": "user@test.org",
        "masked_subject": "Greetings [PERSON_1_1111]",
        "masked_body": "My phone is [PHONE_1_2222] and email [EMAIL_1_3333]",
        "token_map": {
            "[PERSON_1_1111]": "Charlie",
            "[PHONE_1_2222]": "555-1234",
            "[EMAIL_1_3333]": "user@test.org",
        },
    }

    # Only restore PERSON
    result = resolve_dispatch_content(
        record, unmask_pii=True, allowed_entity_types={"PERSON"}
    )
    assert result["subject"] == "Greetings Charlie"
    assert "[PHONE_1_2222]" in result["body"]
    assert "[EMAIL_1_3333]" in result["body"]
    assert result["restored_entity_types"] == ("PERSON",)


def test_unmasker_secret_entities_cannot_be_forced_by_allowed_types():
    """Security Invariant: High risk secrets are blocked even if included

    in allowed_entity_types.
    """
    record = {
        "email_id": "em_005",
        "sender_email": "user@test.org",
        "masked_subject": "Card info",
        "masked_body": "Card: [CREDIT_CARD_1_9999]",
        "token_map": {
            "[CREDIT_CARD_1_9999]": "4111-2222-3333-4444",
        },
    }

    # Attacker / misconfigured caller attempts to unmask CREDIT_CARD
    result = resolve_dispatch_content(
        record, unmask_pii=True, allowed_entity_types={"CREDIT_CARD", "PERSON"}
    )
    assert "4111-2222-3333-4444" not in result["body"]
    assert "[CREDIT_CARD_1_9999]" in result["body"]
    assert "CREDIT_CARD" not in result["restored_entity_types"]


def test_unmasker_handles_sender_domain_derivation():
    """Verify domain extraction from sender_email when sender_domain is missing."""
    record = {
        "email_id": "em_006",
        "sender_email": "User.Name@Sub.Example.CO.UK",
        "masked_subject": "Test",
        "masked_body": "Test body",
    }
    result = resolve_dispatch_content(record, unmask_pii=False)
    assert result["sender_domain"] == "sub.example.co.uk"
