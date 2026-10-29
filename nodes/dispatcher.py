"""Node 08: Multi-Destination Dispatcher Router, Outbox Ledger, and Downstream Safety Rails.

This node performs final multi-destination dispatching of sanitized, gatekeeper-approved,
and human/auto-approved emails to external systems (GitHub, FreeScout, CRM, Webhook):
1. Eligibility: Verifies existence and approval in SQLite triage database (never relies on state).
2. Routing: Pure, deterministic mapping from category and priority to destination actions.
3. Outbox Ledger: Atomic check-and-acquire using `p2_dispatch_log` table with composite
   idempotency keys (`email_id:destination:action_type`).
4. Privacy: Downstream adapters receive ONLY `DispatchPayload` (clamped masked text, sender domain,
   zero customer PII, zero token maps, no raw email text).
5. Safety Rails (Live Mode):
   - Kill switch: global kill switch defers all actions.
   - Destination enabled flag: disabled destinations are deferred.
   - Adapter availability & config check: unconfigured adapters are deferred.
   - Daily rate caps: enforces destination daily limits in UTC.
   - Circuit breakers: tracks consecutive failure streaks and enforces cooldowns.
6. Execution & Retries:
   - Dry-run: records simulated ledger rows, makes zero external calls, logs hash and size.
   - Transient errors: retried up to `max_attempts` with backoff and jitter, then dead-lettered.
   - Permanent errors: marked failed immediately, retried across later runs up to `max_attempts`.
   - Unknown outcomes: verified via duplicate checks; unresolved outcomes divert to HITL review.
"""

import contextlib
import json
import logging
import secrets
import sqlite3
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from db.database import HitlStateError, LedgerStateError, PersistenceError, TriageDatabase
from state import TriageState
from utils.adapters import BaseDestinationAdapter, get_adapter, register_active_adapters
from utils.adapters.base import (
    AdapterError,
    AdapterPermanentError,
    AdapterTransientError,
    AdapterUnknownOutcomeError,
    DispatchPayload,
)
from utils.config import get_config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deterministic Taxonomy Routing Rules
# ---------------------------------------------------------------------------
ROUTING_RULES: dict[str, tuple[tuple[str, str], ...]] = {
    "Bug Report": (("github", "create_issue"),),
    "Feature Request": (("github", "create_issue"),),
    "Demo Request": (("crm", "create_lead"),),
    "Pricing Inquiry": (("crm", "create_lead"),),
    "General Query": (("freescout", "create_ticket"),),
    "Complaint": (("freescout", "create_ticket"),),
    "Billing Issue": (("freescout", "create_ticket"),),
    "Refund Request": (("freescout", "create_ticket"),),
    "Security/Account": (("webhook", "alert"),),
}


def route_actions(category: str, priority: str) -> list[tuple[str, str]]:
    """Determines destination actions based on classification category and priority.

    Pure and deterministic function.

    Routing Matrix (primary action first, then the alert):
    - Bug Report: (github, create_issue)
    - Feature Request: (github, create_issue)
    - Demo Request, Pricing Inquiry: (crm, create_lead)
    - General Query, Complaint: (freescout, create_ticket)
    - Billing Issue, Refund Request: (freescout, create_ticket) and,
      when priority is High or Critical, (webhook, alert)
    - Security/Account: only (webhook, alert) (reaches dispatcher only after human approval)
    - Additionally, priority Critical on Bug Report, General Query or Complaint
      adds (webhook, alert).
    - Other or any unmapped category: returns [] (diverted to HITL by dispatcher node).

    Args:
        category: Email classification category.
        priority: Urgency priority level ('Critical', 'High', 'Medium', 'Low').

    Returns:
        List of (destination, action_type) tuples in execution order.
    """
    if category not in ROUTING_RULES or category == "Other":
        return []

    actions: list[tuple[str, str]] = list(ROUTING_RULES[category])

    # Alerts:
    # 1. Billing Issue and Refund Request add Webhook alert on High or Critical priority
    # 2. Priority Critical on Bug Report, General Query or Complaint adds Webhook alert
    billing_alert = (
        category in ("Billing Issue", "Refund Request")
        and priority in ("High", "Critical")
    )
    critical_alert = (
        category in ("Bug Report", "General Query", "Complaint")
        and priority == "Critical"
    )
    if (billing_alert or critical_alert) and ("webhook", "alert") not in actions:
        actions.append(("webhook", "alert"))

    return actions


# ---------------------------------------------------------------------------
# Dispatcher Node Execution
# ---------------------------------------------------------------------------
def dispatcher_node(
    state: TriageState,
    db: TriageDatabase | None = None,
    config: dict[str, Any] | None = None,
    adapters: dict[str, BaseDestinationAdapter] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """LangGraph node executing outbox ledger claiming, safety rail validation, and dispatch.

    Args:
        state: TriageState used ONLY for email_id.
        db: Optional TriageDatabase instance.
        config: Optional configuration dictionary. Defaults to get_config().
        adapters: Optional mapping of destination names to adapter instances (overrides registry).
        sleep: Injected sleep callable for transient retry backoff.
        now: Optional callable returning aware UTC datetime for test timing control.

    Returns:
        Dictionary update with keys 'p2_status' and 'dispatch_results'.
    """
    if db is None:
        return {"p2_status": "persist_failed", "dispatch_results": []}

    if config is None:
        config = get_config()

    current_now = now() if callable(now) else datetime.now(UTC)
    if current_now.tzinfo is None:
        current_now = current_now.replace(tzinfo=UTC)

    # 1. Eligibility from DATABASE record
    email_id = str(state.get("email_id") or "")
    if not email_id:
        return {"p2_status": "not_eligible", "dispatch_results": []}

    try:
        record = db.get_record(email_id)
    except (sqlite3.Error, PersistenceError, LedgerStateError):
        return {"p2_status": "persist_failed", "dispatch_results": []}

    if (
        record is None
        or record.get("routing_status") != "gatekeeper_approved"
        or record.get("hitl_status") not in ("auto_approved", "approved")
        or not record.get("p2_category")
    ):
        return {"p2_status": "not_eligible", "dispatch_results": []}

    # Merge in-memory state fields (e.g. token_map for in-memory pipeline dispatch)
    if state.get("token_map") and "token_map" not in record:
        record["token_map"] = state.get("token_map")
    if state.get("sender_email") and not record.get("sender_email"):
        record["sender_email"] = state.get("sender_email")

    # 2. Determine actions
    category = str(record["p2_category"])
    priority = str(record.get("p2_priority") or "Medium")
    actions = route_actions(category, priority)

    if not actions:
        try:
            db.divert_to_hitl(email_id, "unmapped_category")
        except (sqlite3.Error, PersistenceError, LedgerStateError):
            return {"p2_status": "persist_failed", "dispatch_results": []}
        except HitlStateError:
            pass
        return {"p2_status": "hitl_pending", "dispatch_results": []}

    # 3. Mode, configuration, and stale pending resolution
    dispatch_cfg = config.get("dispatch", {}) if isinstance(config, dict) else {}
    dry_run = bool(dispatch_cfg.get("dry_run", True))
    mode = "dry_run" if dry_run else "live"
    pending_timeout_minutes = int(dispatch_cfg.get("pending_timeout_minutes", 10))
    max_attempts = int(dispatch_cfg.get("max_attempts", 3))
    backoff_base = float(dispatch_cfg.get("backoff_base_seconds", 1.0))
    backoff_max = float(dispatch_cfg.get("backoff_max_seconds", 20.0))

    diverted_to_hitl = False

    def resolve_adapter(dest_name: str) -> BaseDestinationAdapter | None:
        if adapters is not None:
            return adapters.get(dest_name)
        try:
            adapter = get_adapter(dest_name)
            if adapter is None:
                # PRR-02: Lazy auto-registration fallback if registry is empty
                register_active_adapters(config)
                adapter = get_adapter(dest_name)
            return adapter
        except ValueError:
            return None

    def verify_unknown_row(row_dict: dict[str, Any]) -> bool:
        """Verifies an unknown outcome row via check_duplicate."""
        nonlocal diverted_to_hitl
        row_id = row_dict["id"]
        dest = row_dict["destination"]
        act = row_dict["action_type"]
        key = row_dict["idempotency_key"]

        adapt = resolve_adapter(dest)
        remote_id: str | None = None
        if adapt is not None:
            try:
                payl = DispatchPayload.from_record(record, act, key)
                remote_id = adapt.check_duplicate(key, payl)
            except Exception:  # noqa: BLE001
                remote_id = None

        if remote_id and isinstance(remote_id, str) and remote_id.strip():
            db.resolve_unknown_dispatch(row_id, "confirmed", "auto_check", remote_id)
            row_dict["state"] = "confirmed"
            row_dict["remote_id"] = remote_id
            return True
        else:
            with contextlib.suppress(HitlStateError):
                db.divert_to_hitl(email_id, "dispatch_outcome_unknown")
            diverted_to_hitl = True
            return False

    try:
        db.expire_stale_pending(pending_timeout_minutes, current_now)
        existing_logs = db.get_dispatch_log(email_id)
        for log_row in existing_logs:
            if log_row["mode"] == "live" and log_row["state"] == "unknown":
                verify_unknown_row(log_row)
    except (sqlite3.Error, PersistenceError, LedgerStateError):
        return {"p2_status": "persist_failed", "dispatch_results": []}

    # 4. Action processing loop
    dispatch_results: list[dict[str, Any]] = []

    for destination, action_type in actions:
        idempotency_key = db.build_idempotency_key(email_id, destination, action_type)

        # Build payload with validation
        try:
            payload = DispatchPayload.from_record(record, action_type, idempotency_key)
            payload_sha256 = payload.sha256()
        except ValueError:
            try:
                row, acquired = db.begin_dispatch(
                    email_id,
                    destination,
                    action_type,
                    mode,
                    payload_sha256=None,
                    max_attempts=max_attempts,
                )
                if acquired:
                    db.finish_dispatch(row["id"], state="deferred", reason="missing_masked_text")
                    row["state"] = "deferred"
                    row["reason"] = "missing_masked_text"
                dispatch_results.append({
                    "destination": destination,
                    "action_type": action_type,
                    "mode": row["mode"],
                    "ledger_state": row["state"],
                    "reason": row.get("reason"),
                    "attempts": row.get("attempts", 0),
                    "remote_id": row.get("remote_id"),
                })
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
            continue

        # Atomically acquire ledger row
        try:
            row, acquired = db.begin_dispatch(
                email_id,
                destination,
                action_type,
                mode,
                payload_sha256=payload_sha256,
                max_attempts=max_attempts,
            )
        except (sqlite3.Error, PersistenceError, LedgerStateError):
            return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}

        if not acquired:
            dispatch_results.append({
                "destination": destination,
                "action_type": action_type,
                "mode": row["mode"],
                "ledger_state": row["state"],
                "reason": row.get("reason"),
                "attempts": row.get("attempts", 0),
                "remote_id": row.get("remote_id"),
            })
            continue

        ledger_id = row["id"]

        # 5. Dry run execution
        if mode == "dry_run":
            try:
                db.finish_dispatch(ledger_id, state="simulated")
                row["state"] = "simulated"
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}

            payload_bytes = len(json.dumps(payload.to_dict(), sort_keys=True).encode("utf-8"))
            logger.info(
                "[DRY_RUN_DISPATCH] email_id=%s destination=%s action=%s "
                "payload_sha256=%s payload_bytes=%d",
                email_id,
                destination,
                action_type,
                payload_sha256,
                payload_bytes,
            )
            dispatch_results.append({
                "destination": destination,
                "action_type": action_type,
                "mode": "dry_run",
                "ledger_state": "simulated",
                "reason": None,
                "attempts": 0,
                "remote_id": None,
            })
            continue

        # 6. Live Safety Rails Checks
        # Rail 1: Kill switch
        kill_switch = bool(dispatch_cfg.get("kill_switch", False))
        if kill_switch:
            try:
                db.finish_dispatch(ledger_id, state="deferred", reason="kill_switch")
                row["state"] = "deferred"
                row["reason"] = "kill_switch"
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
            dispatch_results.append({
                "destination": destination,
                "action_type": action_type,
                "mode": "live",
                "ledger_state": "deferred",
                "reason": "kill_switch",
                "attempts": row.get("attempts", 0),
                "remote_id": None,
            })
            continue

        # Rail 2: Destination not enabled
        dest_cfg = config.get("destinations", {}).get(destination, {})
        if not dest_cfg.get("enabled", False):
            try:
                db.finish_dispatch(ledger_id, state="deferred", reason="destination_disabled")
                row["state"] = "deferred"
                row["reason"] = "destination_disabled"
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
            dispatch_results.append({
                "destination": destination,
                "action_type": action_type,
                "mode": "live",
                "ledger_state": "deferred",
                "reason": "destination_disabled",
                "attempts": row.get("attempts", 0),
                "remote_id": None,
            })
            continue

        # Rail 3: Missing adapter
        adapter = resolve_adapter(destination)
        if adapter is None:
            try:
                db.finish_dispatch(ledger_id, state="deferred", reason="adapter_unavailable")
                row["state"] = "deferred"
                row["reason"] = "adapter_unavailable"
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
            dispatch_results.append({
                "destination": destination,
                "action_type": action_type,
                "mode": "live",
                "ledger_state": "deferred",
                "reason": "adapter_unavailable",
                "attempts": row.get("attempts", 0),
                "remote_id": None,
            })
            continue

        # Rail 4: Adapter config invalid
        is_valid = False
        try:
            is_valid = bool(adapter.validate_config())
        except AdapterError:
            is_valid = False
        except Exception:  # noqa: BLE001
            is_valid = False

        if not is_valid:
            try:
                db.finish_dispatch(ledger_id, state="deferred", reason="adapter_not_configured")
                row["state"] = "deferred"
                row["reason"] = "adapter_not_configured"
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
            dispatch_results.append({
                "destination": destination,
                "action_type": action_type,
                "mode": "live",
                "ledger_state": "deferred",
                "reason": "adapter_not_configured",
                "attempts": row.get("attempts", 0),
                "remote_id": None,
            })
            continue

        # Rail 5: Daily cap exceeded
        daily_cap = int(dest_cfg.get("daily_cap", 0))
        try:
            confirmed_today = db.count_confirmed_today(destination, current_now)
        except (sqlite3.Error, PersistenceError, LedgerStateError):
            return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}

        if confirmed_today >= daily_cap:
            try:
                db.finish_dispatch(ledger_id, state="deferred", reason="daily_cap")
                row["state"] = "deferred"
                row["reason"] = "daily_cap"
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
            dispatch_results.append({
                "destination": destination,
                "action_type": action_type,
                "mode": "live",
                "ledger_state": "deferred",
                "reason": "daily_cap",
                "attempts": row.get("attempts", 0),
                "remote_id": None,
            })
            continue

        # Rail 6: Circuit breaker open
        cb_cfg = dest_cfg.get("circuit_breaker", {})
        failure_threshold = int(cb_cfg.get("failure_threshold", 5))
        cooldown_seconds = float(cb_cfg.get("cooldown_seconds", 900))

        try:
            streak_count, newest_failure_iso = db.get_failure_streak(destination, current_now)
        except (sqlite3.Error, PersistenceError, LedgerStateError):
            return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}

        if streak_count >= failure_threshold and newest_failure_iso is not None:
            try:
                newest_dt = datetime.fromisoformat(newest_failure_iso)
                if newest_dt.tzinfo is None:
                    newest_dt = newest_dt.replace(tzinfo=UTC)
                elapsed = (current_now - newest_dt).total_seconds()
            except (ValueError, TypeError):
                elapsed = 0.0

            if elapsed < cooldown_seconds:
                # Circuit is open (trial allowed only after cooldown expires)
                try:
                    db.finish_dispatch(ledger_id, state="deferred", reason="circuit_open")
                    row["state"] = "deferred"
                    row["reason"] = "circuit_open"
                except (sqlite3.Error, PersistenceError, LedgerStateError):
                    return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
                dispatch_results.append({
                    "destination": destination,
                    "action_type": action_type,
                    "mode": "live",
                    "ledger_state": "deferred",
                    "reason": "circuit_open",
                    "attempts": row.get("attempts", 0),
                    "remote_id": None,
                })
                continue

        # 7. Live Attempt Loop
        while True:
            try:
                n = db.record_dispatch_attempt(ledger_id)
                row["attempts"] = n
            except (sqlite3.Error, PersistenceError, LedgerStateError):
                return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}

            try:
                result = adapter.dispatch(payload)
                # Success
                try:
                    db.finish_dispatch(ledger_id, state="confirmed", remote_id=result.remote_id)
                    row["state"] = "confirmed"
                    row["remote_id"] = result.remote_id
                except (sqlite3.Error, PersistenceError, LedgerStateError):
                    return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}

                logger.info(
                    f"[DISPATCH_CONFIRMED] email_id={email_id} destination={destination} "
                    f"action={action_type} attempts={n}"
                )
                break

            except AdapterTransientError as exc:
                err_cls = exc.__class__.__name__
                logger.warning(
                    f"[DISPATCH_TRANSIENT_ERROR] email_id={email_id} destination={destination} "
                    f"action={action_type} attempt={n} error_class={err_cls}"
                )
                if n >= max_attempts:
                    try:
                        db.finish_dispatch(
                            ledger_id,
                            state="dead_letter",
                            reason="retries_exhausted",
                            error_class=err_cls,
                        )
                        row["state"] = "dead_letter"
                        row["reason"] = "retries_exhausted"
                    except (sqlite3.Error, PersistenceError, LedgerStateError):
                        return {
                            "p2_status": "persist_failed",
                            "dispatch_results": dispatch_results,
                        }
                    break
                else:
                    base_delay = backoff_base * (2 ** (n - 1))
                    jitter = secrets.SystemRandom().uniform(0.0, backoff_base)
                    delay = min(backoff_max, base_delay + jitter)
                    sleep(delay)
                    continue

            except AdapterPermanentError as exc:
                err_cls = exc.__class__.__name__
                logger.error(
                    f"[DISPATCH_PERMANENT_ERROR] email_id={email_id} destination={destination} "
                    f"action={action_type} error_class={err_cls}"
                )
                try:
                    db.finish_dispatch(
                        ledger_id,
                        state="failed",
                        reason="permanent_error",
                        error_class=err_cls,
                    )
                    row["state"] = "failed"
                    row["reason"] = "permanent_error"
                except (sqlite3.Error, PersistenceError, LedgerStateError):
                    return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
                break

            except AdapterUnknownOutcomeError as exc:
                err_cls = exc.__class__.__name__
                logger.error(
                    f"[DISPATCH_UNKNOWN_ERROR] email_id={email_id} destination={destination} "
                    f"action={action_type} error_class={err_cls}"
                )
                try:
                    db.finish_dispatch(
                        ledger_id,
                        state="unknown",
                        reason="outcome_unknown",
                        error_class=err_cls,
                    )
                    row["state"] = "unknown"
                    row["reason"] = "outcome_unknown"
                    verify_unknown_row(row)
                except (sqlite3.Error, PersistenceError, LedgerStateError):
                    return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
                break

            except Exception as exc:  # noqa: BLE001
                # Any other unexpected Exception (it may have been delivered)
                err_cls = exc.__class__.__name__
                logger.error(
                    f"[DISPATCH_UNEXPECTED_ERROR] email_id={email_id} destination={destination} "
                    f"action={action_type} error_class={err_cls}"
                )
                try:
                    db.finish_dispatch(
                        ledger_id,
                        state="unknown",
                        reason="unexpected_error",
                        error_class=err_cls,
                    )
                    row["state"] = "unknown"
                    row["reason"] = "unexpected_error"
                    verify_unknown_row(row)
                except (sqlite3.Error, PersistenceError, LedgerStateError):
                    return {"p2_status": "persist_failed", "dispatch_results": dispatch_results}
                break

        dispatch_results.append({
            "destination": destination,
            "action_type": action_type,
            "mode": "live",
            "ledger_state": row["state"],
            "reason": row.get("reason"),
            "attempts": row.get("attempts", 0),
            "remote_id": row.get("remote_id"),
        })

    # 8. Compute final p2_status
    if dispatch_results and all(r["ledger_state"] == "confirmed" for r in dispatch_results):
        final_p2_status = "dispatched"
    elif dispatch_results and all(r["ledger_state"] == "simulated" for r in dispatch_results):
        final_p2_status = "simulated"
    elif diverted_to_hitl:
        final_p2_status = "hitl_pending"
    elif any(r["ledger_state"] == "dead_letter" for r in dispatch_results):
        final_p2_status = "dead_letter"
    elif any(r["ledger_state"] == "failed" for r in dispatch_results):
        final_p2_status = "failed"
    elif any(r["ledger_state"] == "deferred" for r in dispatch_results):
        final_p2_status = "deferred"
    else:
        final_p2_status = "failed"

    return {
        "p2_status": final_p2_status,
        "dispatch_results": dispatch_results,
    }


def should_route_after_dispatcher(state: TriageState) -> str:
    """Conditional edge router for dispatcher node (terminal in Phase 2).

    Args:
        state: Current LangGraph triage state.

    Returns:
        'end' unconditionally.
    """
    return "end"
