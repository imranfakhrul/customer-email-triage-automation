"""Developer smoke test script for FreeScout Helpdesk Destination Adapter.

Milestone [P2-10]:
Safe by default:
- In dry-run mode (default), exercises conversation payload formatting, HTML conversion,
  correlation marker generation, and validation without network calls.
- In live mode (requires --live and valid FREESCOUT_API_KEY),
  validates configuration and executes health check against FreeScout API.
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

from utils.adapters.freescout_adapter import FreeScoutAdapter  # noqa: E402
from utils.adapters.freescout_format import build_conversation_payload, build_marker  # noqa: E402
from utils.config import get_config  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke test for FreeScout Helpdesk adapter")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform real network health check against FreeScout API (requires API key)",
    )
    args = parser.parse_args()

    cfg = get_config()
    print("=" * 70)
    print(" FreeScout Helpdesk Destination Adapter — Smoke Test")
    print("=" * 70)

    # 1. Format and conversation payload verification
    idempotency_key = "em_smoke_fs_01:freescout:create_ticket"
    record = {
        "email_id": "em_smoke_fs_01",
        "masked_subject": "Need help setting up custom SSO",
        "masked_body": "Hi, how do we configure SAML 2.0? Contact us at [PHONE_1].",
        "sender_email": "admin@acme.com",
        "sender_domain": "acme.com",
        "thread_id": "th_smoke_fs_01",
    }

    conv = build_conversation_payload(
        record=record,
        mailbox_id=1,
        idempotency_key=idempotency_key,
        unmask_pii=False,
    )
    marker = build_marker(idempotency_key, record["email_id"], record["thread_id"])

    print("\n[+] Pure formatting & payload verification:")
    print(f"    Subject    : {conv['subject']}")
    print(f"    Mailbox ID : {conv['mailboxId']}")
    print(f"    Type       : {conv['type']}")
    print(f"    Marker     : {marker.strip()[:60]}...")
    print(f"    Thread Text: {len(conv['threads'][0]['text'])} chars with HTML formatting.")

    fs_cfg = cfg.get("destinations", {}).get("freescout", {})
    target = fs_cfg.get("target", "https://support.example.com")
    adapter = FreeScoutAdapter(
        target=target,
        mailbox_id=int(fs_cfg.get("mailbox_id", 1)),
    )

    # 2. Live network check or dry-run instructions
    if args.live:
        print("\n[*] Live mode requested (--live). Checking FreeScout credentials...")
        api_key = os.environ.get(adapter._api_key_env)
        if not api_key:
            print(f"[-] Missing environment variable '{adapter._api_key_env}'.")
            print("    Please set a valid FreeScout API key to run live integration.")
            sys.exit(0)

        is_valid = adapter.validate_config()
        print(f"    Config valid : {is_valid}")
        healthy = adapter.health_check()
        print(f"    API Health   : {'HEALTHY (200 OK)' if healthy else 'FAILED / UNAUTHORIZED'}")
    else:
        print("\n[+] Dry-run mode completed successfully.")
        print("    To run against live FreeScout API, execute:")
        print(f"    export {adapter._api_key_env}=your_freescout_api_key")
        print("    ./venv/bin/python scripts/freescout_smoke_test.py --live\n")


if __name__ == "__main__":
    main()
