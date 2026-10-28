"""Manual verification script for Milestone [P2-06].

Verifies HubSpot CRM downstream adapter, formula injection defanging, and lead scoring.

Usage:
    ./venv/bin/python scripts/check_p2_06.py
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
from utils.adapters.crm_adapter import CRMAdapter  # noqa: E402
from utils.adapters.crm_format import (  # noqa: E402
    build_hubspot_payload,
    calculate_lead_score,
    extract_company_domain,
    is_freemail_domain,
    sanitize_crm_field,
)


def require(condition: bool, msg: str = "") -> None:
    """Assertion helper avoiding S101 bandit flags in standalone scripts."""
    if not condition:
        raise RuntimeError(f"Check requirement failed: {msg}")


def run_checks() -> None:
    print("=" * 70)
    print(" RUNNING MANUAL VERIFICATION FOR MILESTONE [P2-06]")
    print(" HubSpot CRM Lead Ingestion Adapter & Output Hardening")
    print("=" * 70)

    # -------------------------------------------------------------
    # Check 1: Formula / CSV Injection Defanging
    # -------------------------------------------------------------
    print("\n[Check 1] Formula / CSV Injection Defanging (Spreadsheet Security)")
    attacks = ["=cmd|' /C calc'!A0", "+SUM(A1:B10)", "-100+200", "@SUM(1+1)", "\t=calc()"]
    for attack in attacks:
        defanged = sanitize_crm_field(attack)
        require(defanged.startswith("'"), f"Must prepend single quote: {attack}")
    # Normal international phone starting with '+' should be preserved
    phone_safe = sanitize_crm_field("+1-555-0199")
    require(phone_safe == "+1-555-0199", "Safe international phone should preserve '+'")
    print("  -> Formula injection payloads neutralized with single quote prefix. [PASS]")
    print("  -> International phone numbers preserved cleanly. [PASS]")

    # -------------------------------------------------------------
    # Check 2: Domain Extraction & Deterministic Lead Scoring
    # -------------------------------------------------------------
    print("\n[Check 2] Domain Classification & Deterministic Lead Scoring")
    require(is_freemail_domain("gmail.com") is True, "gmail.com must be freemail")
    require(is_freemail_domain("enterprise.com") is False, "enterprise.com must be corporate")
    corp_domain = extract_company_domain("lead@salesforce.com", "salesforce.com")
    require(corp_domain == "salesforce.com", "Corporate domain must be extracted")

    # Demo Request + High + Enterprise + Neutral = 70 + 15 + 15 + 0 = 100
    score_corp = calculate_lead_score("Demo Request", "High", "enterprise.com", "Neutral")
    require(score_corp == 100, f"Expected 100, got {score_corp}")

    # Demo Request + High + Freemail + Neutral = 70 + 15 + 0 + 0 = 85
    score_free = calculate_lead_score("Demo Request", "High", "gmail.com", "Neutral")
    require(score_free == 85, f"Expected 85, got {score_free}")
    print(f"  -> Enterprise prospect lead score: {score_corp}/100. [PASS]")
    print(f"  -> Freemail prospect lead score: {score_free}/100. [PASS]")

    # -------------------------------------------------------------
    # Check 3: Universal Selective Unmasking in HubSpot Payload
    # -------------------------------------------------------------
    print("\n[Check 3] Selective Unmasking & Secret Retention in CRM Payload")
    record = {
        "email_id": "em_crm_manual_01",
        "message_id": "<msg01@acmecorp.com>",
        "thread_id": "th_crm_01",
        "category": "Demo Request",
        "priority": "High",
        "sentiment": "Positive",
        "customer_emotion": "curious",
        "summary": "Demo request for 500 enterprise seats",
        "suggested_team": "Sales",
        "confidence": 0.98,
        "masked_subject": "Demo request for [PERSON_1]",
        "masked_body": (
            "Hi Sales Team,\n"
            "My name is [PERSON_1], phone [PHONE_1], email [EMAIL_1].\n"
            "Card is [CREDIT_CARD_1] and api token is [API_KEY_1].\n"
            "We would like to request an enterprise demo."
        ),
        "sender_email": "jane@acmecorp.com",
        "sender_domain": "acmecorp.com",
        "token_map": {
            "[PERSON_1]": "Jane Prospect",
            "[PHONE_1]": "+1-555-0199",
            "[EMAIL_1]": "jane@acmecorp.com",
            "[CREDIT_CARD_1]": "4111-2222-3333-4444",
            "[API_KEY_1]": "sk_live_secret123456789",
        },
    }
    idempotency_key = "idemp_crm_manual_01"

    payload = build_hubspot_payload(record, idempotency_key=idempotency_key, unmask_pii=True)
    props = payload["properties"]

    require(props["email"] == "jane@acmecorp.com", "Prospect email must match")
    require(props["firstname"] == "Jane", "Firstname must be extracted")
    require(props["lastname"] == "Prospect", "Lastname must be extracted")
    require(props["phone"] == "+1-555-0199", "Phone must be unmasked")
    require(props["company"] == "acmecorp.com", "Company domain must be set")
    # Secret verification
    require("[CREDIT_CARD_1]" in props["message"], "Card token must remain masked")
    require("4111-2222-3333-4444" not in props["message"], "Raw card must not appear")
    require("[API_KEY_1]" in props["message"], "API key token must remain masked")
    require("sk_live_secret123456789" not in props["message"], "Raw secret must not appear")
    print("  -> Contact info restored; credit cards & API tokens permanently masked. [PASS]")

    # -------------------------------------------------------------
    # Check 4: CRMAdapter End-to-End Simulation & 409 Recovery
    # -------------------------------------------------------------
    print("\n[Check 4] CRMAdapter End-to-End Dispatch & 409 Collision Recovery")
    mock_session = MagicMock()

    # Pre-check GET returns 404
    get_res = MagicMock(status_code=404)
    # POST returns 201 Created with id 1059281
    post_res = MagicMock(status_code=201)
    post_res.json.return_value = {"id": "1059281"}
    mock_session.request.side_effect = [get_res, post_res]

    adapter = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="manual_check_crm_key",
        session=mock_session,
    )

    dispatch_payload = DispatchPayload.from_record(
        record=record,
        action_type="create_lead",
        idempotency_key=idempotency_key,
    )

    result = adapter.dispatch(dispatch_payload)
    require(result.remote_id == "crm:1059281", f"Expected crm:1059281, got {result.remote_id}")
    print(f"  -> Dispatch succeeded! Returned remote_id: {result.remote_id} [PASS]")

    # 409 Collision Recovery Simulation
    mock_session_409 = MagicMock()
    post_409 = MagicMock(status_code=409)
    post_409.json.return_value = {
        "status": "error",
        "message": "Contact already exists. Existing ID: 1059281",
        "context": {"id": ["1059281"]},
    }
    mock_session_409.request.side_effect = [MagicMock(status_code=404), post_409]

    adapter_409 = CRMAdapter(
        target="https://api.hubapi.com",
        api_key="manual_check_crm_key",
        session=mock_session_409,
    )
    result_409 = adapter_409.dispatch(dispatch_payload)
    require(
        result_409.remote_id == "crm:1059281",
        f"Expected crm:1059281 from 409 recovery, got {result_409.remote_id}",
    )
    print(f"  -> 409 Collision recovered gracefully: {result_409.remote_id} [PASS]")

    print("\n" + "=" * 70)
    print(" ALL 4 CHECKS PASSED SUCCESSFULLY (100%)")
    print("=" * 70)


if __name__ == "__main__":
    try:
        run_checks()
    except (RuntimeError, ValueError) as exc:
        print(f"FAILED: {exc!r}", file=sys.stderr)
        sys.exit(1)
