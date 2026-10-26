#!/usr/bin/env python3
"""Standalone Smoke Test for TypeSafe System One (Jev) Gatekeeper API.

Tests connectivity and classification against the live TypeSafe System One endpoint.
If no key or a placeholder key is configured, prints guidance and exits cleanly with 0.
"""

import json
import os
import sys

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env_var, load_config
from utils.jev_client import JevClient


def main() -> None:
    print("=" * 65)
    print("   TypeSafe System One (Jev) Gatekeeper Smoke Test")
    print("=" * 65)

    config = load_config()
    gatekeeper_cfg = config.get("gatekeeper", {})
    api_key_env = gatekeeper_cfg.get("api_key_env", "JEV_API_KEY")
    api_key = get_env_var(api_key_env) or os.environ.get("JEV_API_KEY", "")

    # Check key presence and placeholder status
    if not JevClient._is_valid_key(api_key):
        print("Jev key: missing")
        print("\n[!] Notice: No valid JEV_API_KEY detected in your environment or .env file.")
        print("    Add a real JEV_API_KEY to .env, then run this again.\n")
        sys.exit(0)

    print("Jev key: present")
    print("[*] Initializing JevClient...")
    client = JevClient(config=config, api_key=api_key)

    sample_subject = "Enterprise Plan Demo Request"
    sample_body = (
        "Hello Sales Team, our engineering department with 150 developers would like "
        "to schedule a product demonstration next Tuesday. Regards, Jordan."
    )
    sample_sender = "jordan@enterprise-client.com"

    print(f"\n[*] Sending harmless test email to Jev endpoint:\n    {client.api_url}")
    print(f"    Subject: {sample_subject}")
    print(f"    Sender:  {sample_sender}\n")

    result = client.classify(subject=sample_subject, body=sample_body, sender=sample_sender)

    print("--- [Mapped Triage Output] ---")
    print(json.dumps(result, indent=2))

    if result.get("classifier_used") != "jev":
        fallback_engine = result.get("classifier_used", "unknown")
        print(
            f"\n[-] Smoke test FAILED: TypeSafe System One (Jev) API did not produce decision "
            f"(fallback used: '{fallback_engine}')."
        )
        print("    Verify that JEV_API_KEY is valid, active, and has sufficient quota.\n")
        sys.exit(1)

    print("\n[+] Smoke test completed successfully!")


if __name__ == "__main__":
    main()
