"""Customer Email Triage Automation — Production Entry Point & Benchmark Runner.

Executes the LangGraph-based email triage pipeline up to Jev AI Decision Engine:
1. Ingestion & Idempotency Store (Node 01)
2. Signature & Quote Stripper (Node 02)
3. Local spaCy NER & Regex PII Masker (Node 03)
4. Sensitive-Skip Guardrail (Node 04)
5. Jev AI Decision Gatekeeper (Node 05)
"""

import argparse
import json
import logging
import os
import re
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

from db.database import TriageDatabase
from pipeline import create_triage_pipeline, run_triage_pipeline
from utils.config import load_config

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("triage.main")


def print_banner() -> None:
    """Prints application startup banner."""
    banner = r"""
========================================================================
   CUSTOMER EMAIL TRIAGE AUTOMATION — INGESTION TO JEV AI ENGINE
   LangGraph Pipeline | Local spaCy NER Redactor | 3-Tier Gatekeeper
========================================================================
"""
    print(banner)


def run_benchmark_suite(
    benchmark_path: Optional[str] = None,
    use_temp_db: bool = True,
    offline: bool = False,
) -> bool:
    """Executes the synthetic benchmark dataset through the complete triage pipeline.

    Args:
        benchmark_path: Optional path to benchmark JSON file.
        use_temp_db: Whether to use an isolated temporary database for benchmarking.
        offline: Whether to force offline deterministic mode (preserves API quotas).

    Returns:
        True if all benchmark scenarios pass matching assertions, False otherwise.
    """
    if benchmark_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        benchmark_path = os.path.join(base_dir, "data", "benchmark_emails.json")

    if not os.path.exists(benchmark_path):
        print(f"[-] Benchmark dataset not found at: {benchmark_path}")
        return False

    with open(benchmark_path, "r", encoding="utf-8") as f:
        benchmarks: List[Dict[str, Any]] = json.load(f)

    print(f"[*] Loaded {len(benchmarks)} synthetic benchmark scenarios from:\n    {benchmark_path}\n")

    # Set up database
    temp_dir = None
    if use_temp_db:
        temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(temp_dir.name, "benchmark_triage.db")
        db = TriageDatabase(db_path=db_path)
    else:
        db = TriageDatabase()

    from utils.jev_client import JevClient
    client = (
        JevClient(api_key="your_placeholder_key", groq_api_key="your_placeholder_key")
        if offline
        else None
    )
    pipeline = create_triage_pipeline(db=db, client=client, offline=offline)

    print(
        f"{'#':<3} | {'Scenario Name':<28} | {'Routing Status':<26} | {'Decision':<12} | {'Engine':<7} | {'Time (ms)':<9} | {'Status'}"
    )
    print("-" * 105)

    all_passed = True
    total_duration_ms = 0.0

    for idx, item in enumerate(benchmarks, start=1):
        scenario_id = item.get("id", f"case_{idx}")
        name = item.get("name", scenario_id)[:28]
        expected = item.get("expected", {})

        # If testing active thread scenario, seed prior approved email in DB with matching participant
        if item.get("category") == "active_thread" or expected.get("routing_status") == "active_thread_continuation":
            prior_email_id = f"prior_{item['email_id']}"
            db.check_and_acquire(
                email_id=prior_email_id,
                thread_id=item["thread_id"],
                message_id=f"<prior-{item['email_id']}@domain.com>",
                sender_email=item["sender_email"],
            )
            db.mark_done(prior_email_id, routing_status="gatekeeper_approved")

        # If testing duplicate delivery scenario, mark previous run done in DB first
        if expected.get("routing_status") == "duplicate_skipped":
            db.mark_done(item["email_id"], routing_status="completed")

        t0 = time.perf_counter()
        result = run_triage_pipeline(item, pipeline=pipeline, db=db, client=client)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        total_duration_ms += elapsed_ms

        routing_status = str(result.get("routing_status") or "unknown")
        gatekeeper_decision = str(result.get("gatekeeper_decision") or "—")
        classifier_used = str(result.get("classifier_used") or "—")

        # Verify against expected outcomes
        case_passed = True
        if "routing_status" in expected and result.get("routing_status") != expected["routing_status"]:
            case_passed = False
        if "routing_status_in" in expected and result.get("routing_status") not in expected["routing_status_in"]:
            case_passed = False
        if "gatekeeper_decision" in expected and result.get("gatekeeper_decision") != expected["gatekeeper_decision"]:
            case_passed = False
        if "is_sensitive" in expected and result.get("is_sensitive") != expected["is_sensitive"]:
            case_passed = False
        if "is_spam" in expected and result.get("is_spam") != expected["is_spam"]:
            case_passed = False

        if not case_passed:
            all_passed = False
            status_badge = "❌ FAIL"
        else:
            status_badge = "✅ PASS"

        print(
            f"{idx:<3} | {name:<28} | {routing_status:<26} | {gatekeeper_decision:<12} | {classifier_used:<7} | {elapsed_ms:>8.1f}  | {status_badge}"
        )

    print("-" * 105)
    avg_ms = total_duration_ms / len(benchmarks) if benchmarks else 0.0
    print(
        f"[*] Execution Summary: {len(benchmarks)} scenarios in {total_duration_ms:.1f}ms (Average: {avg_ms:.1f}ms/email)"
    )

    if all_passed:
        print("[+] All benchmark scenarios PASSED successfully! Pipeline is operational.\n")
    else:
        print("[-] Some benchmark scenarios failed assertion criteria.\n")

    if temp_dir is not None:
        temp_dir.cleanup()

    return all_passed


def count_pii_entities(token_map: Optional[Dict[str, str]]) -> Dict[str, int]:
    """Aggregates count of masked PII entities by category without revealing raw values.

    Args:
        token_map: Mapping of tokens like '[PERSON_1]' to raw values.

    Returns:
        Dictionary of entity counts by type, e.g. {'PERSON': 2, 'EMAIL': 1}.
    """
    counts: Dict[str, int] = {}
    if not token_map:
        return counts
    for token in token_map.keys():
        if token.startswith("__"):
            continue
        m = re.match(r"^\[([A-Z_]+)_\d+(?:_[0-9a-fA-F]+)?\]$", token)
        if m:
            etype = m.group(1)
            counts[etype] = counts.get(etype, 0) + 1
        else:
            counts["OTHER"] = counts.get("OTHER", 0) + 1
    return dict(sorted(counts.items()))


def process_single_email(json_path: str, offline: bool = False) -> None:
    """Processes a single email JSON file through the triage pipeline and prints output.

    Args:
        json_path: Path to the JSON payload file.
        offline: Whether to force offline deterministic mode.
    """
    if not os.path.exists(json_path):
        print(f"[-] Input file does not exist: {json_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        print(f"[*] Processing email payload: {json_path}")
        db = TriageDatabase()
        from utils.jev_client import JevClient

        client = (
            JevClient(
                api_key="your_placeholder_key", groq_api_key="your_placeholder_key"
            )
            if offline
            else None
        )
        result = run_triage_pipeline(payload, db=db, client=client, offline=offline)

        print("\n--- Pipeline Triage Result ---")
        output_summary = {
            "email_id": result.get("email_id"),
            "routing_status": result.get("routing_status"),
            "gatekeeper_decision": result.get("gatekeeper_decision"),
            "classifier_used": result.get("classifier_used"),
            "is_sensitive": result.get("is_sensitive"),
            "sensitive_reason": result.get("sensitive_reason"),
            "is_spam": result.get("is_spam"),
            "is_threat": result.get("is_threat"),
            "labels_to_apply": result.get("labels_to_apply"),
            "dispatch_target": result.get("dispatch_target"),
            "dispatch_status": result.get("dispatch_status"),
            "pii_entity_counts": count_pii_entities(result.get("token_map")),
            "masked_body_preview": (result.get("masked_body") or "")[:200],
        }
        print(json.dumps(output_summary, indent=2))
    except Exception as exc:
        # Crucial: Never echo payload contents, token_map, or sensitive values on error
        print(f"[-] Error processing email: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Customer Email Triage Automation — Ingestion to Gatekeeper Pipeline",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the synthetic benchmark test dataset across all pipeline stages.",
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Path to an email JSON file to process through the pipeline.",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Custom path to benchmark dataset JSON file.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run using offline deterministic heuristics (avoids external API quotas).",
    )

    args = parser.parse_args()

    print_banner()

    from nodes.pii_masker import validate_startup
    validate_startup(offline=args.offline)

    if args.input:
        process_single_email(args.input, offline=args.offline)
    else:
        # Default behavior: run benchmark verification suite
        success = run_benchmark_suite(
            benchmark_path=args.dataset,
            offline=args.offline,
        )
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    main()
