#!/usr/bin/env python3
"""CLI utility for Gmail Cloud Pub/Sub mailbox watch setup and automated 7-day renewal.

Usage:
    python scripts/renew_mailbox_watch.py --check
    python scripts/renew_mailbox_watch.py --renew
    python scripts/renew_mailbox_watch.py --renew --force
"""

import argparse
import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# Anchor project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.config import get_config  # noqa: E402
from utils.mailbox.gmail_connector import GmailConnector  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("renew_mailbox_watch")


def check_watch_status(config: dict[str, Any]) -> dict[str, Any]:
    """Inspects configured Pub/Sub topic and credential readiness for watch subscription."""
    mb_cfg = config.get("mailbox", {}).get("gmail", {})
    topic_name = os.environ.get("GMAIL_TOPIC_NAME") or mb_cfg.get("topic_name", "")
    has_credentials = bool(
        os.environ.get("GMAIL_ACCESS_TOKEN")
        or (
            os.environ.get("GMAIL_REFRESH_TOKEN")
            and os.environ.get("GMAIL_CLIENT_ID")
            and os.environ.get("GMAIL_CLIENT_SECRET")
        )
    )

    return {
        "status": "ready" if (topic_name and has_credentials) else "unconfigured",
        "topic_name": topic_name if topic_name else "NOT_CONFIGURED",
        "credentials_configured": has_credentials,
        "provider": "gmail",
        "watch_ttl_days": 7,
    }


def renew_watch_subscription(
    topic_name: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Submits watch subscription request to Gmail REST API."""
    cfg = get_config()
    mb_cfg = cfg.get("mailbox", {}).get("gmail", {})
    target_topic = topic_name or os.environ.get("GMAIL_TOPIC_NAME") or mb_cfg.get("topic_name", "")

    if not target_topic:
        logger.error("No GMAIL_TOPIC_NAME configured in environment or config.yaml")
        return {"success": False, "error": "Missing GMAIL_TOPIC_NAME"}

    if dry_run or not (
        os.environ.get("GMAIL_ACCESS_TOKEN") or os.environ.get("GMAIL_REFRESH_TOKEN")
    ):
        logger.info("[DRY-RUN] Simulating Pub/Sub watch renewal for topic: %s", target_topic)
        simulated_expiration = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)
        return {
            "success": True,
            "mode": "dry_run",
            "topicName": target_topic,
            "historyId": "simulated_history_id_1001",
            "expiration": str(int(simulated_expiration.timestamp() * 1000)),
            "expiration_iso": simulated_expiration.isoformat(),
        }

    connector = GmailConnector(config=cfg)
    result = connector.setup_watch(topic_name=target_topic)
    if "error" in result:
        return {"success": False, "error": result["error"]}

    exp_ms = int(result.get("expiration", "0"))
    exp_iso = (
        datetime.datetime.fromtimestamp(exp_ms / 1000.0, tz=datetime.UTC).isoformat()
        if exp_ms > 0
        else "UNKNOWN"
    )

    return {
        "success": True,
        "mode": "live",
        "topicName": target_topic,
        "historyId": result.get("historyId"),
        "expiration": result.get("expiration"),
        "expiration_iso": exp_iso,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gmail Cloud Pub/Sub mailbox watch setup and automated 7-day renewal."
    )
    parser.add_argument("--check", action="store_true", help="Check current watch configuration.")
    parser.add_argument("--renew", action="store_true", help="Renew or set up mailbox watch.")
    parser.add_argument("--topic", type=str, default=None, help="Custom Pub/Sub topic name.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Simulate renewal without live API call."
    )
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()
    cfg = get_config()

    if args.check:
        status_info = check_watch_status(cfg)
        if args.json:
            print(json.dumps(status_info, indent=2))
        else:
            cred_str = "Configured" if status_info["credentials_configured"] else "Missing"
            print("\n==================================================")
            print(" Gmail Pub/Sub Mailbox Watch Status")
            print("==================================================")
            print(f" Status        : {status_info['status']}")
            print(f" Topic Name    : {status_info['topic_name']}")
            print(f" Credentials   : {cred_str}")
            print(f" Watch TTL     : {status_info['watch_ttl_days']} days (auto renewal required)")
            print("==================================================\n")
    elif args.renew:
        result = renew_watch_subscription(topic_name=args.topic, dry_run=args.dry_run)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("\n==================================================")
            print(" Gmail Pub/Sub Watch Renewal Result")
            print("==================================================")
            print(f" Success       : {result.get('success')}")
            print(f" Mode          : {result.get('mode')}")
            print(f" Topic Name    : {result.get('topicName')}")
            print(f" History ID    : {result.get('historyId')}")
            print(f" Expiration    : {result.get('expiration_iso')}")
            print("==================================================\n")
        if not result.get("success"):
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
