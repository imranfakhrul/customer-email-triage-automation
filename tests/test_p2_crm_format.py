"""Unit tests for CRM output formatting, formula injection defanging, and lead scoring."""

from utils.adapters.crm_format import (
    build_hubspot_payload,
    calculate_lead_score,
    extract_company_domain,
    is_freemail_domain,
    sanitize_crm_field,
)


def test_sanitize_crm_field_defangs_formula_injection():
    # Attack payloads attempting CSV/Formula Injection in Excel / Google Sheets
    attacks = [
        "=cmd|' /C calc'!A0",
        "+SUM(A1:A10)",
        "-1234+5678",
        "@SUM(B1:B2)",
        "\t=1+1",
        "\r+alert()",
    ]
    for attack in attacks:
        sanitized = sanitize_crm_field(attack)
        assert sanitized.startswith("'"), f"Failed to defang formula injection in: {attack!r}"
        assert sanitized.lstrip("'") == attack.lstrip(" \t\r\n")

    # Safe inputs should not be prepended with quote
    safe_cases = [
        ("Jane Doe", "Jane Doe"),
        ("123 Main Street", "123 Main Street"),
        ("Hello, we need a pricing quote", "Hello, we need a pricing quote"),
        ("", ""),
        (None, ""),
    ]
    for input_val, expected in safe_cases:
        assert sanitize_crm_field(input_val) == expected


def test_sanitize_crm_field_strips_bidi_and_control_chars():
    bidi_attack = "Jane\u202e\u2066Doe\u202c\u2069"
    sanitized = sanitize_crm_field(bidi_attack)
    assert "\u202e" not in sanitized
    assert "\u2066" not in sanitized
    assert sanitized == "JaneDoe"


def test_is_freemail_domain():
    freemail_domains = [
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
        "mail.com",
        "GMAIL.COM",
    ]
    for d in freemail_domains:
        assert is_freemail_domain(d) is True, f"Expected freemail for {d}"

    corporate_domains = [
        "enterprise.com",
        "acme.org",
        "cloud-scale.io",
        "bank-corp.us",
    ]
    for d in corporate_domains:
        assert is_freemail_domain(d) is False, f"Expected non-freemail for {d}"


def test_extract_company_domain():
    assert extract_company_domain("alice@salesforce.com", "salesforce.com") == "salesforce.com"
    assert extract_company_domain("bob@gmail.com", "gmail.com") == ""
    assert extract_company_domain("carol@corp.tech", "") == "corp.tech"
    assert extract_company_domain("", "") == ""


def test_calculate_lead_score_table():
    test_cases = [
        # (category, priority, domain, sentiment, expected_score)
        ("Demo Request", "Critical", "enterprise.com", "Positive", 100),  # 70+20+15+5=110 -> 100
        ("Demo Request", "High", "enterprise.com", "Neutral", 100),      # 70+15+15+0=100
        ("Pricing Inquiry", "High", "enterprise.com", "Neutral", 90),     # 60+15+15+0=90
        ("Pricing Inquiry", "Medium", "gmail.com", "Positive", 70),       # 60+5+0+5=70
        ("General Query", "Low", "gmail.com", "Negative", 20),           # 30+0+0-10=20
        ("Demo Request", "Low", "gmail.com", "Negative", 60),            # 70+0+0-10=60
        ("Other", "Low", "gmail.com", "Negative", 20),                  # 30+0+0-10=20
    ]
    for cat, prio, dom, sent, expected in test_cases:
        score = calculate_lead_score(category=cat, priority=prio, domain=dom, sentiment=sent)
        assert score == expected, (
            f"Failed for {cat}, {prio}, {dom}, {sent}: got {score}, expected {expected}"
        )


def test_build_hubspot_payload_unmask_pii():
    record = {
        "email_id": "em_crm_001",
        "message_id": "<msg01@prospect.com>",
        "thread_id": "th_crm_001",
        "category": "Demo Request",
        "priority": "High",
        "sentiment": "Positive",
        "customer_emotion": "curious",
        "summary": "Enterprise demo request",
        "suggested_team": "Sales",
        "confidence": 0.95,
        "masked_subject": "Need demo for [PERSON_1_a1b2]",
        "masked_body": (
            "Hi team,\n"
            "My name is [PERSON_1_a1b2], phone [PHONE_1_a1b2], email [EMAIL_1_a1b2].\n"
            "Card is [CREDIT_CARD_1_a1b2] and api key is [API_KEY_1_a1b2].\n"
            "We would like a demo for 500 enterprise seats."
        ),
        "sender_email": "jane@prospect.com",
        "sender_domain": "prospect.com",
        "token_map": {
            "[PERSON_1_a1b2]": "Jane Prospect",
            "[PHONE_1_a1b2]": "+1-555-0199",
            "[EMAIL_1_a1b2]": "jane@prospect.com",
            "[CREDIT_CARD_1_a1b2]": "4111-2222-3333-4444",
            "[API_KEY_1_a1b2]": "sk_live_secret12345",
        },
    }
    idempotency_key = "idemp_crm_test_001"

    payload = build_hubspot_payload(
        record=record,
        idempotency_key=idempotency_key,
        unmask_pii=True,
    )

    props = payload["properties"]
    assert props["email"] == "jane@prospect.com"
    assert props["firstname"] == "Jane"
    assert props["lastname"] == "Prospect"
    assert props["phone"] == "+1-555-0199"
    assert props["company"] == "prospect.com"
    assert props["hs_lead_status"] == "NEW"
    assert props["lead_score"] == "100"  # 70 + 15 + 15 + 5 = 105 -> clamped to 100
    assert props["triage_email_id"] == "em_crm_001"
    assert props["triage_idempotency_key"] == idempotency_key

    # Contact context unmasked in message:
    assert "Jane Prospect" in props["message"]
    assert "+1-555-0199" in props["message"]
    # Secrets MUST remain masked:
    assert "[CREDIT_CARD_1_a1b2]" in props["message"]
    assert "4111-2222-3333-4444" not in props["message"]
    assert "[API_KEY_1_a1b2]" in props["message"]
    assert "sk_live_secret12345" not in props["message"]


def test_build_hubspot_payload_formula_defanged():
    record = {
        "email_id": "em_crm_002",
        "sender_email": "bad@actor.com",
        "sender_domain": "actor.com",
        "masked_subject": "=cmd|' /C calc'!A0",
        "masked_body": "@SUM(1+1)\n+calc.exe",
        "category": "Pricing Inquiry",
        "priority": "Medium",
        "sentiment": "Neutral",
    }
    payload = build_hubspot_payload(
        record=record,
        idempotency_key="idemp_crm_002",
        unmask_pii=False,
    )
    props = payload["properties"]
    assert props["message"].startswith("'")
