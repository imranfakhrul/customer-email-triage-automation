#!/usr/bin/env python3
"""Live Gmail Mailbox Poller & End-to-End Triage Dispatcher.

Connects to Gmail via OAuth 2.0 (GmailConnector), imports incoming customer emails,
runs them through the complete 8-node LangGraph pipeline (Phase 1 + Phase 2),
and dispatches them live to GitHub Issues, HubSpot CRM, or Slack Alerts.

Usage:
    # Run once to check and triage newly arrived unread emails:
    python scripts/poll_mailbox.py --once --live

    # Run continuous polling daemon (polls every 15 seconds):
    python scripts/poll_mailbox.py --poll-interval 15 --live
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from db.database import TriageDatabase  # noqa: E402
from pipeline import create_triage_pipeline, run_triage_pipeline  # noqa: E402
from utils.config import get_config  # noqa: E402
from utils.mailbox.gmail_connector import GmailConnector  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("poll_mailbox")


def process_mailbox_once(
    connector: GmailConnector,
    db: TriageDatabase,
    live: bool = True,
    query: str | None = "is:unread",
    limit: int = 5,
) -> int:
    """Fetches new messages from Gmail and executes the full triage pipeline on each."""
    messages_meta = connector.fetch_new_messages(max_pages=1, query=query)
    if not messages_meta:
        logger.info("[Mailbox] No new messages matching query='%s' in inbox.", query or "all")
        return 0

    if limit > 0:
        messages_meta = messages_meta[:limit]

    logger.info("[Mailbox] Found %d message(s) to process.", len(messages_meta))
    pipeline = create_triage_pipeline(db=db, offline=(not live), phase2=True)

    processed = 0
    for meta in messages_meta:
        msg_id = meta.get("id")
        if not msg_id:
            continue

        # Check if already processed in SQLite
        with db.get_connection() as conn:
            cur = conn.execute(
                "SELECT 1 FROM email_triage WHERE email_id = ? OR message_id = ?",
                (msg_id, msg_id),
            )
            if cur.fetchone() is not None:
                logger.debug("[Mailbox] Skipping already ingested message %s", msg_id)
                continue

        full_email = connector.refetch_original_email(msg_id)
        if not full_email:
            logger.warning("[Mailbox] Could not fetch full message for id: %s", msg_id)
            continue

        logger.info(
            "\n" + "=" * 60 + "\n[+] Incoming Email Received from Gmail:\n"
            f"    From   : {full_email.get('sender_email')}\n"
            f"    Subject: {full_email.get('email_subject')}\n"
            f"    ID     : {msg_id}\n" + "=" * 60
        )

        result = run_triage_pipeline(
            full_email,
            pipeline=pipeline,
            db=db,
            offline=(not live),
            phase2=True,
        )

        cl = result.get("classification")
        cat = getattr(cl, "category", None) or (
            cl.get("category") if isinstance(cl, dict) else "Unknown"
        )
        prio = getattr(cl, "priority", None) or (
            cl.get("priority") if isinstance(cl, dict) else "Medium"
        )
        p2_status = result.get("p2_status")
        results = result.get("dispatch_results") or []

        logger.info(
            "[✓] Triaged Email: Category='%s' | Priority='%s' | Status='%s'",
            cat,
            prio,
            p2_status,
        )
        for r in results:
            logger.info(
                "    -> Destination: %s | Action: %s | Remote ID: %s",
                r.get("destination"),
                r.get("action_type"),
                r.get("remote_id"),
            )

        processed += 1

    return processed


def main() -> None:
    parser = argparse.ArgumentParser(description="Live Gmail Mailbox Poller & Triage Runner")
    parser.add_argument("--once", action="store_true", help="Poll once then exit")
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=15.0,
        help="Polling interval in seconds (default: 15.0)",
    )
    parser.add_argument(
        "--query", default="is:unread", help="Gmail search query (default: 'is:unread')"
    )
    parser.add_argument("--all", action="store_true", help="Fetch all messages, not just unread")
    parser.add_argument(
        "--limit", type=int, default=5, help="Max emails to process per cycle (default: 5)"
    )
    parser.add_argument("--live", action="store_true", help="Enable live outbound dispatching")
    args = parser.parse_args()

    search_query = None if args.all else args.query

    print("=" * 70)
    print(" Live Gmail Mailbox Poller & End-to-End Triage Dispatcher")
    print("=" * 70)

    cfg = get_config()
    connector = GmailConnector(config=cfg)

    # Validate Gmail credentials
    token = connector.get_valid_access_token()
    if not token:
        print("\n[-] Error: Gmail credentials are not configured or token refresh failed.")
        print("    Ensure GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, and")
        print("    GMAIL_REFRESH_TOKEN are set in .env.")
        print("    Run `python scripts/get_gmail_token.py` to authorize your Gmail account.")
        sys.exit(1)

    print("[+] Successfully authenticated with Gmail API via OAuth 2.0!")
    db = TriageDatabase()

    if args.once:
        process_mailbox_once(
            connector, db, live=args.live, query=search_query, limit=args.limit
        )
    else:
        q_label = search_query or "all"
        print(f"[*] Starting continuous mailbox polling ({args.poll_interval}s).")
        print(f"    Query filter: '{q_label}'\n")
        try:
            while True:
                process_mailbox_once(
                    connector, db, live=args.live, query=search_query, limit=args.limit
                )
                time.sleep(args.poll_interval)
        except KeyboardInterrupt:
            print("\n[!] Mailbox polling stopped gracefully.")


if __name__ == "__main__":
    main()
