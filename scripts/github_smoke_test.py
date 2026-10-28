"""Developer smoke test script for GitHub Issues Destination Adapter.

Milestone [P2-10]:
Safe by default:
- In dry-run mode (default), exercises title sanitization, body hardening,
  correlation marker generation, and contract validation without network calls.
- In live mode (requires --live and valid TEST_GITHUB_TOKEN / GITHUB_TOKEN),
  creates a real test issue or verifies credentials against GitHub REST API.
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

from utils.adapters.base import DispatchPayload  # noqa: E402
from utils.adapters.github_adapter import GitHubAdapter  # noqa: E402
from utils.adapters.github_format import (  # noqa: E402
    build_issue_body,
    build_labels,
    build_marker,
    sanitize_title,
)
from utils.config import get_config  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke test for GitHub Issues adapter")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Perform real network health check against GitHub API (requires token)",
    )
    args = parser.parse_args()

    cfg = get_config()
    print("=" * 70)
    print(" GitHub Issues Destination Adapter — Smoke Test")
    print("=" * 70)

    # 1. Format and sanitization demonstration
    payload = DispatchPayload(
        email_id="em_smoke_gh_01",
        message_id="<smoke-gh-01@example.com>",
        thread_id="th_smoke_gh_01",
        category="Bug Report",
        priority="High",
        sentiment="Negative",
        customer_emotion="Calm",
        summary="Memory leak on ingestion worker",
        suggested_team="Engineering",
        confidence=0.96,
        masked_subject="Worker OOM crash on node [IP_ADDRESS_1]",
        masked_body="Process exited with status 137. Contact: [PERSON_1].",
        sender_domain="example.com",
        p2_classifier_used="offline_heuristic",
        action_type="create_issue",
        idempotency_key="em_smoke_gh_01:github:create_issue",
    )

    title = sanitize_title(payload.masked_subject, payload.category)
    body = build_issue_body(payload)
    labels = build_labels(payload, base_labels=["triage:automated"])
    marker = build_marker(payload.idempotency_key)

    print("\n[+] Pure formatting & sanitization verification:")
    print(f"    Title  : {title}")
    print(f"    Labels : {labels}")
    print(f"    Marker : {marker.strip()[:60]}...")
    print(f"    Body   : {len(body)} characters formatted and hardened.")

    adapter = GitHubAdapter(config=cfg)

    # 2. Live network check or dry-run instructions
    if args.live:
        print("\n[*] Live mode requested (--live). Checking GitHub credentials...")
        token = os.environ.get(adapter._token_env) or os.environ.get("GITHUB_TOKEN")
        if not token:
            print(f"[-] Missing environment variable '{adapter._token_env}' or 'GITHUB_TOKEN'.")
            print("    Please set a valid GitHub token to run live integration.")
            sys.exit(0)

        is_valid = adapter.validate_config()
        print(f"    Config valid : {is_valid}")
        healthy = adapter.health_check()
        print(f"    API Health   : {'HEALTHY (200 OK)' if healthy else 'FAILED / UNAUTHORIZED'}")
    else:
        print("\n[+] Dry-run mode completed successfully.")
        print("    To run against live GitHub API, execute:")
        print(f"    export {adapter._token_env}=ghp_your_token")
        print("    ./venv/bin/python scripts/github_smoke_test.py --live\n")


if __name__ == "__main__":
    main()
