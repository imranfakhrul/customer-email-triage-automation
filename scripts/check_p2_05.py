"""Manual verification script for Milestone [P2-05].

Verifies FreeScout Helpdesk downstream adapter & Universal Selective Unmasking.

Usage:
    ./venv/bin/python scripts/check_p2_05.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from unittest.mock import MagicMock  # noqa: E402

from utils.adapters.base import DispatchPayload  # noqa: E402
from utils.adapters.freescout_adapter import FreeScoutAdapter  # noqa: E402
from utils.adapters.freescout_format import (  # noqa: E402
    build_conversation_payload,
    build_thread_reply_payload,
    parse_marker,
)
from utils.unmasker import resolve_dispatch_content  # noqa: E402


def require(condition: bool, msg: str = "") -> None:
    """Assertion helper avoiding S101 bandit flags in standalone scripts."""
    if not condition:
        raise RuntimeError(f"Check requirement failed: {msg}")


def run_checks() -> None:
    print("=" * 70)
    print(" RUNNING MANUAL VERIFICATION FOR MILESTONE [P2-05]")
    print(" FreeScout Helpdesk Adapter & Universal Selective Unmasking")
    print("=" * 70)

    # -------------------------------------------------------------
    # Check 1: Universal Selective Unmasking
    # -------------------------------------------------------------
    print("\n[Check 1] Universal Selective Unmasking (Privacy Invariant #1)")
    state = {
        "email_id": "em_test_001",
        "sender_email": "john.doe@customer.com",
        "sender_domain": "customer.com",
        "masked_subject": "Urgent: Billing issue for [PERSON_1]",
        "masked_body": (
            "Hi, my name is [PERSON_1], email [EMAIL_1], phone [PHONE_1], server [IP_ADDRESS_1].\n"
            "My payment card is [CREDIT_CARD_1] and api token is [API_KEY_1]. Please help!"
        ),
        "token_map": {
            "[PERSON_1]": "John Doe",
            "[EMAIL_1]": "john.doe@customer.com",
            "[PHONE_1]": "+1-555-0199",
            "[IP_ADDRESS_1]": "192.168.1.100",
            "[CREDIT_CARD_1]": "4111-2222-3333-4444",
            "[API_KEY_1]": "sk_live_secret123456789",
        },
    }

    # Case A: unmask_pii=True (FreeScout/CRM)
    content_unmasked = resolve_dispatch_content(state, unmask_pii=True)
    require(
        content_unmasked["customer_email"] == "john.doe@customer.com",
        "customer_email should match sender_email",
    )
    require("John Doe" in content_unmasked["body"], "PERSON should be unmasked")
    require("john.doe@customer.com" in content_unmasked["body"], "EMAIL should be unmasked")
    require("+1-555-0199" in content_unmasked["body"], "PHONE should be unmasked")
    require("192.168.1.100" in content_unmasked["body"], "IP_ADDRESS should be unmasked")
    # Secrets MUST remain masked:
    require("[CREDIT_CARD_1]" in content_unmasked["body"], "CREDIT_CARD token must remain masked")
    require("4111-2222-3333-4444" not in content_unmasked["body"], "Raw card must not appear")
    require("[API_KEY_1]" in content_unmasked["body"], "API_KEY token must remain masked")
    require("sk_live_secret123456789" not in content_unmasked["body"], "Raw secret must not appear")
    print("  -> unmask_pii=True: Contact info restored; secrets permanently masked. [PASS]")

    # Case B: unmask_pii=False (GitHub/Webhook)
    content_masked = resolve_dispatch_content(state, unmask_pii=False)
    require(content_masked["customer_email"] is None, "customer_email should be suppressed")
    require("[PERSON_1]" in content_masked["body"], "PERSON token must remain masked")
    require("John Doe" not in content_masked["body"], "Original name must not appear")
    print("  -> unmask_pii=False: All tokens masked, customer email suppressed. [PASS]")

    # -------------------------------------------------------------
    # Check 2: FreeScout Payload Formatting & Output Hardening
    # -------------------------------------------------------------
    print("\n[Check 2] FreeScout Formatting & Correlation Marker Anchoring")
    raw_payload_dict = {
        "email_id": "em_test_001",
        "thread_id": "th_abc_123",
        "sender_email": "alice@company.com",
        "sender_domain": "company.com",
        "masked_subject": "Need assistance with order",
        "masked_body": (
            "Hello <b>FreeScout</b>!\nLine 2.\n[PERSON_1]\n<script>alert('xss')</script>"
        ),
        "token_map": {"[PERSON_1]": "Alice Smith"},
        "suggested_actions": ["reply_urgent"],
        "confidence": 0.95,
        "category": "support",
    }
    idempotency_key = "idemp_fs_manual_test_001"

    conv_payload = build_conversation_payload(
        raw_payload_dict,
        mailbox_id=42,
        idempotency_key=idempotency_key,
        unmask_pii=True,
    )

    thread_item = conv_payload["threads"][0]
    # Anchored marker check
    marker = parse_marker(thread_item["text"])
    if marker is None:
        raise RuntimeError("Marker must parse from thread text")
    require(marker["key"] == idempotency_key, "Marker key must match idempotency key")
    require(marker["thread_id"] == "th_abc_123", "Marker thread_id must match thread")
    require(
        thread_item["text"].startswith("<!-- triage-bot:v1"),
        "Marker must be anchored at index 0",
    )
    # Defanging check in HTML body
    require("<script>" not in thread_item["text"], "<script> tag must be escaped")
    require("&lt;script&gt;" in thread_item["text"], "Escaped &lt;script&gt; must be present")
    # Customer binding
    require(
        conv_payload["customer"]["email"] == "alice@company.com",
        "Customer email must match sender",
    )
    print("  -> Payload formatted: Correlation marker anchored at index 0. [PASS]")
    print("  -> XSS tags defanged in HTML. Customer bound to real email. [PASS]")

    # -------------------------------------------------------------
    # Check 3: Thread Continuity Reply Formatting
    # -------------------------------------------------------------
    print("\n[Check 3] Thread Reply Formatting (Conversation Continuity)")
    reply_payload = build_thread_reply_payload(
        raw_payload_dict,
        idempotency_key=idempotency_key,
        unmask_pii=True,
    )
    require(reply_payload["type"] == "customer", "Reply type must be customer")
    require(
        reply_payload["text"].startswith("<!-- triage-bot:v1"),
        "Reply text must anchor marker at index 0",
    )
    print("  -> Thread reply payload generated with matching thread correlation. [PASS]")

    # -------------------------------------------------------------
    # Check 4: FreeScoutAdapter Mock Dispatch Execution
    # -------------------------------------------------------------
    print("\n[Check 4] FreeScoutAdapter End-to-End Simulation")
    mock_session = MagicMock()

    # Pre-check GET returns empty conversations list
    get_res = MagicMock(status_code=200)
    get_res.json.return_value = {"_embedded": {"conversations": []}}

    # POST returns 201 Created with conversation ID 88120
    post_res = MagicMock(status_code=201)
    post_res.json.return_value = {"id": 88120}

    mock_session.request.side_effect = [get_res, post_res]

    adapter = FreeScoutAdapter(
        target="https://support.example.com",
        api_key="manual_test_key_xyz",
        mailbox_id=42,
        session=mock_session,
    )

    record = {
        "email_id": "em_001",
        "message_id": "<msg001@example.com>",
        "thread_id": "th_001",
        "category": "support",
        "priority": "P2",
        "sentiment": "neutral",
        "customer_emotion": "curious",
        "summary": "Order status inquiry",
        "suggested_team": "Support",
        "confidence": 0.98,
        "masked_subject": "Order #1234 status",
        "masked_body": "Where is my order?",
        "sender_email": "buyer@shop.com",
        "sender_domain": "shop.com",
        "p2_classifier_used": "rules",
    }

    payload = DispatchPayload.from_record(
        record=record,
        action_type="create_ticket",
        idempotency_key=idempotency_key,
    )

    result = adapter.dispatch(payload)
    require(
        result.remote_id == "freescout:88120",
        f"Expected freescout:88120, got {result.remote_id}",
    )
    print(f"  -> Dispatch succeeded! Returned remote_id: {result.remote_id} [PASS]")

    print("\n" + "=" * 70)
    print(" ALL 4 CHECKS PASSED SUCCESSFULLY (100%)")
    print("=" * 70)


if __name__ == "__main__":
    try:
        run_checks()
    except (RuntimeError, ValueError) as exc:
        print(f"FAILED: {exc!r}", file=sys.stderr)
        sys.exit(1)
