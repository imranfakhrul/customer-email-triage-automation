"""Developer smoke test script for HubSpot CRM Destination Adapter.

Milestone [P2-10]:
Safe by default:
- In dry-run mode (default), exercises HubSpot contact properties formatting,
  CSV formula injection sanitization, and lead score computation without network calls.
- In live mode (requires --live and valid CRM_API_KEY),
  validates configuration and executes health check against HubSpot CRM API.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Anchor project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.adapters.crm_adapter import CRMAdapter  # noqa: E402
from utils.adapters.crm_format import build_hubspot_payload, sanitize_crm_field  # noqa: E402
from utils.config import get_config  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke test for HubSpot CRM adapter")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform real network health check against HubSpot API (requires API key)",
    )
    args = parser.parse_args()

    cfg = get_config()
    print("=" * 70)
    print(" HubSpot CRM Destination Adapter — Smoke Test")
    print("=" * 70)

    # 1. Format, unmasking, and formula sanitization demonstration
    dangerous_input = "=cmd|'/C calc'!A0"
    neutralized = sanitize_crm_field(dangerous_input)

    record = {
        "email_id": "em_smoke_crm_01",
        "sender_email": "jane.prospect@enterprise.com",
        "customer_email": "jane.prospect@enterprise.com",
        "sender_domain": "enterprise.com",
        "category": "Demo Request",
        "priority": "High",
        "sentiment": "Positive",
        "confidence": 0.95,
        "masked_subject": "Demo Request for Enterprise Suite",
        "masked_body": (
            "Hi, I am [PERSON_1]. Please contact me at [PHONE_1] regarding pricing."
        ),
        "token_map": {"[PERSON_1]": "Jane Prospect", "[PHONE_1]": "+1 555 333 4444"},
    }

    hubspot_payload = build_hubspot_payload(
        record=record,
        idempotency_key="em_smoke_crm_01:crm:create_lead",
        unmask_pii=True,
    )
    props = hubspot_payload["properties"]

    print("\n[+] Pure formatting & security verification:")
    print(f"    Formula defense : '{dangerous_input}' -> '{neutralized}'")
    print(f"    Contact Email   : {props.get('email')}")
    print(f"    Contact Name    : {props.get('firstname')} {props.get('lastname')}")
    print(f"    Lead Score      : {props.get('lead_score')}")
    print(f"    Lead Status     : {props.get('hs_lead_status')}")

    crm_cfg = cfg.get("destinations", {}).get("crm", {})
    target = crm_cfg.get("target", "https://api.hubapi.com")
    adapter = CRMAdapter(target=target)

    # 2. Live network check or dry-run instructions
    if args.live:
        print("\n[*] Live mode requested (--live). Checking HubSpot credentials...")
        api_key = os.environ.get(adapter._api_key_env)
        if not api_key:
            print(f"[-] Missing environment variable '{adapter._api_key_env}'.")
            print("    Please set a valid HubSpot Private App Token to run live integration.")
            sys.exit(0)

        is_valid = adapter.validate_config()
        print(f"    Config valid : {is_valid}")
        healthy = adapter.health_check()
        print(f"    API Health   : {'HEALTHY (200 OK)' if healthy else 'FAILED / UNAUTHORIZED'}")
    else:
        print("\n[+] Dry-run mode completed successfully.")
        print("    To run against live HubSpot API, execute:")
        print(f"    export {adapter._api_key_env}=pat_your_hubspot_token")
        print("    ./venv/bin/python scripts/crm_smoke_test.py --live\n")


if __name__ == "__main__":
    main()
