"""Developer smoke test script for Webhook Alert Destination Adapter.

Milestone [P2-10]:
Safe by default:
- In dry-run mode (default), exercises HMAC-SHA256 signature computation,
  JSON alert payload structuring, and header generation without network calls.
- In live mode (requires --live and valid WEBHOOK_SECRET_KEY),
  validates configuration and executes health check against destination webhook URL.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Anchor project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.adapters.base import DispatchPayload  # noqa: E402
from utils.adapters.webhook_adapter import WebhookAdapter  # noqa: E402
from utils.adapters.webhook_format import (  # noqa: E402
    build_alert_payload,
    compute_hmac_signature,
)
from utils.config import get_config  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke test for Webhook Alert adapter")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform real network health check against Webhook target (requires secret key)",
    )
    args = parser.parse_args()

    cfg = get_config()
    print("=" * 70)
    print(" Webhook Alert Destination Adapter — Smoke Test")
    print("=" * 70)

    # 1. Format and HMAC-SHA256 signing demonstration
    payload = DispatchPayload(
        email_id="em_smoke_wh_01",
        message_id="<smoke-wh-01@example.com>",
        thread_id="th_smoke_wh_01",
        category="Security/Account",
        priority="Critical",
        sentiment="Negative",
        customer_emotion="Angry",
        summary="Compromised account reported",
        suggested_team="Security",
        confidence=0.99,
        masked_subject="URGENT: Unauthorized login from IP [IP_ADDRESS_1]",
        masked_body="Someone accessed our account. Card ending in [CREDIT_CARD_1].",
        sender_domain="example.com",
        p2_classifier_used="jev",
        action_type="alert",
        idempotency_key="em_smoke_wh_01:webhook:alert",
    )

    record = payload.to_dict()
    alert_dict = build_alert_payload(record)
    mock_signing_key = "mock_signing_key_for_testing"
    payload_bytes = json.dumps(alert_dict).encode("utf-8")
    signature = compute_hmac_signature(payload_bytes, mock_signing_key)

    print("\n[+] Pure formatting & HMAC signature verification:")
    print(f"    Event Type    : {alert_dict.get('event')}")
    print(f"    Alert Priority: {alert_dict.get('priority')}")
    print(f"    HMAC Signature: {signature[:40]}...")
    print(f"    Payload Size  : {len(payload_bytes)} bytes UTF-8 JSON.")

    wh_cfg = cfg.get("destinations", {}).get("webhook", {})
    target = wh_cfg.get("target", "https://events.example.com/alerts")
    adapter = WebhookAdapter(target=target)

    # 2. Live network check or dry-run instructions
    if args.live:
        print("\n[*] Live mode requested (--live). Checking Webhook credentials...")
        secret = os.environ.get(adapter._secret_env)
        if not secret:
            print(f"[-] Missing environment variable '{adapter._secret_env}'.")
            print("    Please set a valid Webhook secret key to run live integration.")
            sys.exit(0)

        is_valid = adapter.validate_config()
        print(f"    Config valid : {is_valid}")
        healthy = adapter.health_check()
        print(f"    API Health   : {'HEALTHY (200 OK)' if healthy else 'FAILED / UNAUTHORIZED'}")
    else:
        print("\n[+] Dry-run mode completed successfully.")
        print("    To run against live Webhook target, execute:")
        print(f"    export {adapter._secret_env}=your_webhook_secret_key")
        print("    ./venv/bin/python scripts/webhook_smoke_test.py --live\n")


if __name__ == "__main__":
    main()
