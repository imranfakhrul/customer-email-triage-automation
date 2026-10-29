#!/usr/bin/env python3
"""Reviewer CLI interface for Human-in-the-Loop (HITL) Queue Management.

Provides an audit-trailed terminal interface to list, inspect, approve, reject, or reconcile
emails diverted to the HITL review queue or unknown dispatch outbox states.

Usage:
    hitl_cli.py list [--json] [--limit N]
    hitl_cli.py show EMAIL_ID
    hitl_cli.py approve EMAIL_ID --by NAME [--notes TEXT] [--category C] [--team T]
    hitl_cli.py reject EMAIL_ID --by NAME --notes TEXT
    hitl_cli.py reconcile EMAIL_ID --destination DEST --status STATUS --by NAME [--remote-id ID]

Exit codes:
    0: Success
    2: Invalid input or configuration error
    3: Email not found, not in pending review, or ledger row not found/invalid state
"""

import argparse
import contextlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Anchor project root
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

try:
    from db.database import HitlStateError, LedgerStateError, PersistenceError, TriageDatabase
    from utils.config import ConfigError
except Exception as exc:
    sys.stderr.write(f"Configuration error: {exc}\n")
    sys.exit(2)


class HitlArgumentParser(argparse.ArgumentParser):
    """Custom parser that exits with code 2 on argument errors without python tracebacks."""

    def error(self, message: str):
        sys.stderr.write(f"Error: {message}\n")
        sys.exit(2)


def format_age(created_at_str: Optional[str]) -> str:
    """Computes relative age string (e.g. '5m ago', '2h ago') from ISO timestamp."""
    if not created_at_str:
        return "unknown"
    try:
        clean_str = created_at_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        diff = datetime.now(timezone.utc) - dt
        total_seconds = max(0, int(diff.total_seconds()))
        if total_seconds < 60:
            return f"{total_seconds}s ago"
        elif total_seconds < 3600:
            return f"{total_seconds // 60}m ago"
        elif total_seconds < 86400:
            return f"{total_seconds // 3600}h ago"
        else:
            return f"{total_seconds // 86400}d ago"
    except Exception:
        return "unknown"


def truncate(text: Optional[str], max_len: int = 50) -> str:
    """Truncates long text with an ellipsis to prevent terminal bloat."""
    if not text:
        return ""
    clean = " ".join(str(text).split())
    if len(clean) > max_len:
        return clean[: max_len - 3] + "..."
    return clean


def format_item_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts strictly allowlisted fields without sender_email, raw subject, or body."""
    conf = row.get("p2_confidence")
    conf_float = float(conf) if conf is not None else 0.0
    return {
        "email_id": row.get("email_id", ""),
        "age": format_age(row.get("created_at")),
        "category": row.get("p2_category") or "Other",
        "priority": row.get("p2_priority") or "Medium",
        "confidence": conf_float,
        "reason": row.get("hitl_reason") or "",
        "masked_subject": row.get("masked_subject") or "",
        "masked_body": row.get("masked_body") or "",
    }


def get_db_instance() -> TriageDatabase:
    """Instantiates TriageDatabase under B5 config error handling rules."""
    try:
        return TriageDatabase()
    except ConfigError as ce:
        sys.stderr.write(f"Configuration error: {ce}\n")
        sys.exit(2)
    except Exception as exc:
        sys.stderr.write(f"Database initialization error: {type(exc).__name__}\n")
        sys.exit(2)


def cmd_list(args: argparse.Namespace) -> None:
    db = get_db_instance()
    rows = db.get_pending_hitl_reviews(limit=args.limit)
    items = [format_item_dict(r) for r in rows]

    if args.json:
        print(json.dumps(items, indent=2))
        sys.exit(0)

    if not items:
        print("No pending HITL reviews found.")
        sys.exit(0)

    print(
        f"{'EMAIL ID':<20} | {'AGE':<8} | {'CATEGORY':<18} | {'PRIO':<8} | "
        f"{'CONF':<6} | {'REASON':<25} | {'MASKED SUBJECT'}"
    )
    print("-" * 115)
    for it in items:
        print(
            f"{truncate(it['email_id'], 20):<20} | "
            f"{it['age']:<8} | "
            f"{truncate(it['category'], 18):<18} | "
            f"{it['priority']:<8} | "
            f"{it['confidence']:<6.2f} | "
            f"{truncate(it['reason'], 25):<25} | "
            f"{truncate(it['masked_subject'], 35)}"
        )
    sys.exit(0)


def cmd_show(args: argparse.Namespace) -> None:
    db = get_db_instance()
    row = db.get_record(args.email_id)
    if not row or row.get("hitl_status") != "pending":
        sys.stderr.write(
            f"Email '{args.email_id}' not found or not in pending review status.\n"
        )
        sys.exit(3)

    item = format_item_dict(row)
    print("=" * 60)
    print(f"  HITL PENDING REVIEW: {item['email_id']}")
    print("=" * 60)
    print(f"Age            : {item['age']}")
    print(f"Category       : {item['category']}")
    print(f"Priority       : {item['priority']}")
    print(f"Confidence     : {item['confidence']:.2f}")
    print(f"Reason         : {item['reason']}")
    print(f"Masked Subject : {item['masked_subject']}")
    print("-" * 60)
    print(f"Masked Body    :\n{item['masked_body']}")
    print("=" * 60)
    sys.exit(0)


def cmd_approve(args: argparse.Namespace) -> None:
    if not args.by or not args.by.strip():
        sys.stderr.write("Error: --by NAME is required and cannot be empty.\n")
        sys.exit(2)

    db = get_db_instance()
    try:
        db.resolve_hitl_review(
            email_id=args.email_id,
            decision="approved",
            reviewed_by=args.by,
            notes=args.notes or "",
            override_category=args.category,
            override_team=args.team,
        )
    except ValueError as ve:
        sys.stderr.write(f"Invalid input: {ve}\n")
        sys.exit(2)
    except HitlStateError as he:
        sys.stderr.write(f"Review error: {he}\n")
        sys.exit(3)
    except PersistenceError as pe:
        sys.stderr.write(f"Not found: {pe}\n")
        sys.exit(3)
    except Exception as exc:
        sys.stderr.write(f"Unexpected error: {type(exc).__name__}\n")
        sys.exit(2)

    print(f"Successfully approved email '{args.email_id}' by '{args.by.strip()}'.")
    sys.exit(0)


def cmd_reject(args: argparse.Namespace) -> None:
    if not args.by or not args.by.strip():
        sys.stderr.write("Error: --by NAME is required and cannot be empty.\n")
        sys.exit(2)
    if not args.notes or not args.notes.strip():
        sys.stderr.write("Error: --notes TEXT is required for rejection.\n")
        sys.exit(2)

    db = get_db_instance()
    try:
        db.resolve_hitl_review(
            email_id=args.email_id,
            decision="rejected",
            reviewed_by=args.by,
            notes=args.notes,
        )
    except ValueError as ve:
        sys.stderr.write(f"Invalid input: {ve}\n")
        sys.exit(2)
    except HitlStateError as he:
        sys.stderr.write(f"Review error: {he}\n")
        sys.exit(3)
    except PersistenceError as pe:
        sys.stderr.write(f"Not found: {pe}\n")
        sys.exit(3)
    except Exception as exc:
        sys.stderr.write(f"Unexpected error: {type(exc).__name__}\n")
        sys.exit(2)

    print(f"Successfully rejected email '{args.email_id}' by '{args.by.strip()}'.")
    sys.exit(0)


def cmd_reconcile(args: argparse.Namespace) -> None:
    if not args.by or not args.by.strip():
        sys.stderr.write("Error: --by NAME is required and cannot be empty.\n")
        sys.exit(2)

    clean_status = str(args.status).strip().lower()
    if clean_status not in ("confirmed", "failed"):
        sys.stderr.write("Error: --status must be either 'confirmed' or 'failed'.\n")
        sys.exit(2)

    if clean_status == "confirmed" and (not args.remote_id or not args.remote_id.strip()):
        sys.stderr.write("Error: --remote-id is required when --status is 'confirmed'.\n")
        sys.exit(2)

    db = get_db_instance()
    logs = db.get_dispatch_log(args.email_id)
    target_row = None
    for row in logs:
        if row["destination"] == args.destination and row["state"] == "unknown":
            target_row = row
            break

    if target_row is None:
        sys.stderr.write(
            f"Error: No 'unknown' outcome dispatch log was found for email '{args.email_id}' "
            f"and destination '{args.destination}' (not found or already resolved).\n"
        )
        sys.exit(3)

    outcome = "confirmed" if clean_status == "confirmed" else "not_sent"
    remote_id = args.remote_id.strip() if (args.remote_id and clean_status == "confirmed") else None

    try:
        db.resolve_unknown_dispatch(
            ledger_id=target_row["id"],
            outcome=outcome,
            resolved_by=args.by.strip(),
            remote_id=remote_id,
        )
    except ValueError as ve:
        sys.stderr.write(f"Invalid input: {ve}\n")
        sys.exit(2)
    except (PersistenceError, LedgerStateError) as le:
        sys.stderr.write(f"Ledger state error: {le}\n")
        sys.exit(3)
    except Exception as exc:
        sys.stderr.write(f"Unexpected error: {type(exc).__name__}\n")
        sys.exit(2)

    # Automatically unblock pending HITL review if email was diverted due to unknown dispatch
    record = db.get_record(args.email_id)
    if record and record.get("hitl_status") == "pending":
        with contextlib.suppress(Exception):
            notes = (
                f"Reconciled {args.destination} as {clean_status}"
                + (f" ({remote_id})" if remote_id else "")
            )
            db.resolve_hitl_review(
                email_id=args.email_id,
                decision="approved",
                reviewed_by=args.by.strip(),
                notes=notes,
            )

    print(
        f"Successfully reconciled dispatch #{target_row['id']} for email '{args.email_id}' "
        f"to destination '{args.destination}' as '{clean_status}'."
    )
    sys.exit(0)


def main():
    parser = HitlArgumentParser(
        prog="hitl_cli.py",
        description="Human-in-the-Loop review queue management CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = subparsers.add_parser("list", help="List pending HITL review items.")
    p_list.add_argument("--json", action="store_true", help="Output JSON array.")
    p_list.add_argument(
        "--limit", type=int, default=100, help="Maximum items to return (default: 100)."
    )

    # show
    p_show = subparsers.add_parser("show", help="Show details of a pending review item.")
    p_show.add_argument("email_id", help="Email identifier to display.")

    # approve
    p_app = subparsers.add_parser("approve", help="Approve an email for automated dispatch.")
    p_app.add_argument("email_id", help="Email identifier to approve.")
    p_app.add_argument("--by", required=True, help="Operator username/identity.")
    p_app.add_argument("--notes", default="", help="Optional approval notes.")
    p_app.add_argument("--category", default=None, help="Optional category override.")
    p_app.add_argument("--team", default=None, help="Optional team override.")

    # reject
    p_rej = subparsers.add_parser("reject", help="Reject an email without automated dispatch.")
    p_rej.add_argument("email_id", help="Email identifier to reject.")
    p_rej.add_argument("--by", required=True, help="Operator username/identity.")
    p_rej.add_argument("--notes", required=True, help="Mandatory rejection notes.")

    # reconcile
    p_rec = subparsers.add_parser(
        "reconcile",
        help="Reconcile an unknown-outcome outbox ledger row.",
    )
    p_rec.add_argument("email_id", help="Email identifier to reconcile.")
    p_rec.add_argument(
        "--destination",
        required=True,
        choices=["github", "freescout", "crm", "webhook"],
        help="Target destination name.",
    )
    p_rec.add_argument(
        "--status",
        required=True,
        choices=["confirmed", "failed"],
        help="Reconciliation outcome: 'confirmed' or 'failed'.",
    )
    p_rec.add_argument("--by", required=True, help="Operator username/identity.")
    p_rec.add_argument(
        "--remote-id",
        default=None,
        help="Remote identifier (required when --status is 'confirmed').",
    )

    args = parser.parse_args()

    if args.command == "list":
        cmd_list(args)
    elif args.command == "show":
        cmd_show(args)
    elif args.command == "approve":
        cmd_approve(args)
    elif args.command == "reject":
        cmd_reject(args)
    elif args.command == "reconcile":
        cmd_reconcile(args)


if __name__ == "__main__":
    main()
