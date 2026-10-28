"""Configuration loader and environment secret resolver.

Follows the strict *_env pattern to ensure zero secrets are stored in
plaintext config files.
"""

import os
from pathlib import Path
import re
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import yaml
from dotenv import load_dotenv

from state import ALLOWED_CATEGORIES

# Automatically load environment variables from .env if present (preserve existing environment variables)
load_dotenv(override=False)

# Project-root anchor — always relative to THIS FILE's location, never the CWD.
BASE_DIR: Path = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH: Path = BASE_DIR / "config.yaml"


class ConfigError(ValueError):
    """Raised when configuration is invalid, missing a required section, or fails validation."""
    pass


# ---------------------------------------------------------------------------
# Known keys per section — any other key is a typo and raises ConfigError.
# ---------------------------------------------------------------------------
_KNOWN_KEYS: Dict[str, List[str]] = {
    "system": [
        "database_path", "idempotency_stale_minutes", "max_dispatch_retries",
        "audit_log_enabled", "persist_masked_text",
    ],
    "privacy": [
        "spacy_model", "tech_terms_file", "default_phone_region",
        "tech_context_words", "sensitive_keywords", "max_code_density",
    ],
    "security": [
        "regex_scan_head", "regex_scan_tail",
    ],
    "gatekeeper": [
        "timeout_seconds", "max_retries", "api_key_env", "fallback_model",
        "groq_api_key_env", "jev",
    ],
    "gatekeeper.jev": [
        "model", "api_url", "hi_threshold", "lo_threshold", "max_body_chars",
    ],
    "llm": [
        "model", "temperature", "confidence_threshold", "groq_api_key_env",
    ],
    "classification": [
        "primary", "fallback", "hitl_threshold", "always_review_categories",
        "max_subject_chars", "max_body_chars", "jev",
    ],
    "classification.jev": [
        "enabled", "model", "api_url", "router_question_id", "timeout_seconds",
    ],
    "dispatch": [
        "dry_run", "kill_switch", "max_attempts", "pending_timeout_minutes",
        "backoff_base_seconds", "backoff_max_seconds",
    ],
    "destinations": [
        "github", "freescout", "crm", "webhook",
    ],
    "destinations.item": [
        "enabled", "daily_cap", "use_masked_text_only", "circuit_breaker",
        "target", "token_env", "api_key_env", "target_env", "labels", "mailbox_id",
        "unmask_pii", "allowed_unmask_entities", "allowed_hosts", "request_timeout_seconds",
        "precheck_duplicates",
    ],
    "destinations.github": [
        "enabled", "daily_cap", "use_masked_text_only", "circuit_breaker",
        "target", "token_env", "labels", "api_base_url", "allowed_hosts",
        "request_timeout_seconds", "duplicate_lookback_hours", "duplicate_max_pages",
        "precheck_duplicates", "bot_login", "api_version", "unmask_pii",
    ],
    "destinations.freescout": [
        "enabled", "daily_cap", "use_masked_text_only", "circuit_breaker",
        "target", "api_key_env", "mailbox_id", "unmask_pii", "allowed_unmask_entities",
        "allowed_hosts", "request_timeout_seconds", "precheck_duplicates",
    ],
    "destinations.crm": [
        "enabled", "daily_cap", "use_masked_text_only", "circuit_breaker",
        "target", "target_env", "api_key_env", "unmask_pii", "allowed_unmask_entities",
        "allowed_hosts", "request_timeout_seconds", "precheck_duplicates",
    ],
    "destinations.webhook": [
        "enabled", "daily_cap", "use_masked_text_only", "circuit_breaker",
        "target", "target_env", "secret_env", "unmask_pii", "allowed_hosts",
        "request_timeout_seconds",
    ],
    "destinations.circuit_breaker": [
        "failure_threshold", "cooldown_seconds",
    ],
    "mailbox": [
        "provider", "enabled", "poll_interval_seconds", "gmail",
    ],
    "mailbox.gmail": [
        "user_id", "topic_name", "token_env", "refresh_token_env",
        "client_id_env", "client_secret_env", "api_base_url", "allowed_hosts",
        "request_timeout_seconds",
    ],
}


def _require_mapping(cfg: Dict[str, Any], section: str) -> Dict[str, Any]:
    """Returns sub-dict for section, raises ConfigError if missing or not a mapping."""
    val = cfg.get(section)
    if val is None:
        raise ConfigError(f"Missing required configuration section: '{section}'")
    if not isinstance(val, dict):
        raise ConfigError(
            f"Configuration section '{section}' must be a mapping, got {type(val).__name__}"
        )
    return val


def _check_unknown_keys(section_dict: Dict[str, Any], section_name: str) -> None:
    """Raises ConfigError for any key not in the known-keys list for that section."""
    allowed = _KNOWN_KEYS.get(section_name, [])
    for key in section_dict:
        if key not in allowed:
            raise ConfigError(
                f"Unknown key '{key}' in section '{section_name}' "
                f"(known keys: {', '.join(sorted(allowed))})"
            )


def _require_nonempty_str(val: Any, key: str) -> None:
    if isinstance(val, bool) or not isinstance(val, str) or not val.strip():
        raise ConfigError(f"'{key}' must be a non-empty string, got {type(val).__name__!r}")


def _require_int_gt(val: Any, key: str, minimum: int, strictly_greater: bool = True) -> None:
    """Require an int (not bool) that is > or >= minimum."""
    if isinstance(val, bool) or not isinstance(val, int):
        raise ConfigError(f"'{key}' must be an integer (not bool), got {type(val).__name__!r}")
    if strictly_greater and val <= minimum:
        raise ConfigError(f"'{key}' must be > {minimum}, got {val}")
    if not strictly_greater and val < minimum:
        raise ConfigError(f"'{key}' must be >= {minimum}, got {val}")


def _require_bool(val: Any, key: str) -> None:
    if not isinstance(val, bool):
        raise ConfigError(f"'{key}' must be a bool, got {type(val).__name__!r}")


def _require_number_gt(val: Any, key: str, minimum: float) -> None:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ConfigError(f"'{key}' must be a number, got {type(val).__name__!r}")
    if val <= minimum:
        raise ConfigError(f"'{key}' must be > {minimum}, got {val}")


def validate_config(config: Dict[str, Any]) -> None:
    """Validates configuration parameters.  Raises ConfigError on any violation.

    Every error message names the full dotted key path and the rule violated,
    and never echoes secrets or file content.
    """
    if not isinstance(config, dict):
        raise ConfigError(
            f"Configuration must be a mapping, got {type(config).__name__!r}"
        )

    # ── Required top-level sections ─────────────────────────────────────────
    system = _require_mapping(config, "system")
    privacy = _require_mapping(config, "privacy")
    security = _require_mapping(config, "security")
    gatekeeper = _require_mapping(config, "gatekeeper")
    llm = _require_mapping(config, "llm")

    # ── Unknown-key checks ───────────────────────────────────────────────────
    _check_unknown_keys(system, "system")
    _check_unknown_keys(privacy, "privacy")
    _check_unknown_keys(security, "security")
    _check_unknown_keys(gatekeeper, "gatekeeper")
    _check_unknown_keys(llm, "llm")

    jev_cfg = gatekeeper.get("jev", {})
    if isinstance(jev_cfg, dict):
        _check_unknown_keys(jev_cfg, "gatekeeper.jev")

    # ── system ───────────────────────────────────────────────────────────────
    db_path = system.get("database_path")
    if db_path is None:
        raise ConfigError("'system.database_path' is required")
    _require_nonempty_str(db_path, "system.database_path")

    stale = system.get("idempotency_stale_minutes")
    if stale is None:
        raise ConfigError("'system.idempotency_stale_minutes' is required")
    _require_int_gt(stale, "system.idempotency_stale_minutes", 0, strictly_greater=True)

    retries = system.get("max_dispatch_retries")
    if retries is None:
        raise ConfigError("'system.max_dispatch_retries' is required")
    _require_int_gt(retries, "system.max_dispatch_retries", 0, strictly_greater=False)

    audit = system.get("audit_log_enabled")
    if audit is None:
        raise ConfigError("'system.audit_log_enabled' is required")
    _require_bool(audit, "system.audit_log_enabled")

    persist = system.get("persist_masked_text")
    if persist is None:
        raise ConfigError("'system.persist_masked_text' is required")
    _require_bool(persist, "system.persist_masked_text")

    # ── privacy ──────────────────────────────────────────────────────────────
    spacy = privacy.get("spacy_model")
    if spacy is None:
        raise ConfigError("'privacy.spacy_model' is required")
    _require_nonempty_str(spacy, "privacy.spacy_model")

    tech_file = privacy.get("tech_terms_file")
    if tech_file is None:
        raise ConfigError("'privacy.tech_terms_file' is required")
    _require_nonempty_str(tech_file, "privacy.tech_terms_file")

    region = privacy.get("default_phone_region")
    if region is None:
        raise ConfigError("'privacy.default_phone_region' is required")
    if not isinstance(region, str) or len(region) != 2 or not region.isalpha():
        raise ConfigError(
            f"'privacy.default_phone_region' must be a 2-letter ISO country code, got {region!r}"
        )

    ctx_words = privacy.get("tech_context_words")
    if ctx_words is None:
        raise ConfigError("'privacy.tech_context_words' is required")
    if not isinstance(ctx_words, list) or len(ctx_words) == 0:
        raise ConfigError("'privacy.tech_context_words' must be a non-empty list of strings")
    if not all(isinstance(w, str) for w in ctx_words):
        raise ConfigError("'privacy.tech_context_words' must contain only strings")

    keywords = privacy.get("sensitive_keywords")
    if keywords is None:
        raise ConfigError("'privacy.sensitive_keywords' is required")
    if not isinstance(keywords, list) or len(keywords) == 0:
        raise ConfigError("'privacy.sensitive_keywords' must be a non-empty list of strings")
    if not all(isinstance(k, str) and k.strip() for k in keywords):
        raise ConfigError("'privacy.sensitive_keywords' must contain only non-empty strings")

    code_density = privacy.get("max_code_density")
    if code_density is None:
        raise ConfigError("'privacy.max_code_density' is required")
    _require_int_gt(code_density, "privacy.max_code_density", 0, strictly_greater=False)

    # ── security ─────────────────────────────────────────────────────────────
    scan_head = security.get("regex_scan_head")
    if scan_head is None:
        raise ConfigError("'security.regex_scan_head' is required")
    _require_int_gt(scan_head, "security.regex_scan_head", 0, strictly_greater=True)

    scan_tail = security.get("regex_scan_tail")
    if scan_tail is None:
        raise ConfigError("'security.regex_scan_tail' is required")
    _require_int_gt(scan_tail, "security.regex_scan_tail", 0, strictly_greater=False)

    # ── gatekeeper ───────────────────────────────────────────────────────────
    gk_timeout = gatekeeper.get("timeout_seconds")
    if gk_timeout is None:
        raise ConfigError("'gatekeeper.timeout_seconds' is required")
    _require_number_gt(gk_timeout, "gatekeeper.timeout_seconds", 0)

    gk_retries = gatekeeper.get("max_retries")
    if gk_retries is None:
        raise ConfigError("'gatekeeper.max_retries' is required")
    _require_int_gt(gk_retries, "gatekeeper.max_retries", 0, strictly_greater=False)

    gk_fallback = gatekeeper.get("fallback_model")
    if gk_fallback is None:
        raise ConfigError("'gatekeeper.fallback_model' is required")
    _require_nonempty_str(gk_fallback, "gatekeeper.fallback_model")

    # gatekeeper.jev — validate thresholds whether or not the block is present
    if not isinstance(jev_cfg, dict):
        raise ConfigError("'gatekeeper.jev' must be a mapping")

    jev_model = jev_cfg.get("model")
    if jev_model is None:
        raise ConfigError("'gatekeeper.jev.model' is required")
    _require_nonempty_str(jev_model, "gatekeeper.jev.model")

    jev_url = jev_cfg.get("api_url")
    if jev_url is None:
        raise ConfigError("'gatekeeper.jev.api_url' is required")
    _require_nonempty_str(jev_url, "gatekeeper.jev.api_url")

    jev_maxchars = jev_cfg.get("max_body_chars")
    if jev_maxchars is None:
        raise ConfigError("'gatekeeper.jev.max_body_chars' is required")
    _require_int_gt(jev_maxchars, "gatekeeper.jev.max_body_chars", 0, strictly_greater=True)

    lo = jev_cfg.get("lo_threshold", 0.15)
    hi = jev_cfg.get("hi_threshold", 0.85)
    try:
        lo_f = float(lo)
        hi_f = float(hi)
    except (TypeError, ValueError):
        raise ConfigError(
            f"'gatekeeper.jev.lo_threshold' and 'gatekeeper.jev.hi_threshold' must be numbers"
        )
    if not (0.0 < lo_f < hi_f < 1.0):
        raise ConfigError(
            f"Invalid Jev thresholds: expected 0 < lo_threshold < hi_threshold < 1.0, "
            f"got lo_threshold={lo_f}, hi_threshold={hi_f}"
        )

    # ── llm ──────────────────────────────────────────────────────────────────
    llm_model = llm.get("model")
    if llm_model is None:
        raise ConfigError("'llm.model' is required")
    _require_nonempty_str(llm_model, "llm.model")

    temp = llm.get("temperature")
    if temp is None:
        raise ConfigError("'llm.temperature' is required")
    if isinstance(temp, bool) or not isinstance(temp, (int, float)):
        raise ConfigError(f"'llm.temperature' must be a number, got {type(temp).__name__!r}")
    if not (0.0 <= float(temp) <= 2.0):
        raise ConfigError(f"'llm.temperature' must be between 0 and 2, got {temp}")

    conf = llm.get("confidence_threshold")
    if conf is None:
        raise ConfigError("'llm.confidence_threshold' is required")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        raise ConfigError(
            f"'llm.confidence_threshold' must be a number, got {type(conf).__name__!r}"
        )
    if not (0.0 < float(conf) <= 1.0):
        raise ConfigError(
            f"'llm.confidence_threshold' must satisfy 0 < value <= 1, got {conf}"
        )

    # ── classification (Phase 2 optional) ───────────────────────────────────
    classification = config.get("classification")
    if classification is not None:
        if not isinstance(classification, dict):
            raise ConfigError("'classification' section must be a mapping")
        _check_unknown_keys(classification, "classification")

        hitl_th = classification.get("hitl_threshold")
        if hitl_th is not None:
            if isinstance(hitl_th, bool) or not isinstance(hitl_th, (int, float)):
                raise ConfigError(
                    f"'classification.hitl_threshold' must be a number, got {type(hitl_th).__name__!r}"
                )
            if not (0.0 < float(hitl_th) <= 1.0):
                raise ConfigError(
                    f"'classification.hitl_threshold' must satisfy 0 < value <= 1, got {hitl_th}"
                )

        always_rev = classification.get("always_review_categories")
        if always_rev is not None:
            if isinstance(always_rev, (str, bool)) or not isinstance(always_rev, list):
                raise ConfigError(
                    f"'classification.always_review_categories' must be a list, got {type(always_rev).__name__!r}"
                )
            for item in always_rev:
                if not isinstance(item, str) or item not in ALLOWED_CATEGORIES:
                    raise ConfigError(
                        f"'classification.always_review_categories' items must be known categories, got {item!r}"
                    )

        max_sub = classification.get("max_subject_chars")
        if max_sub is not None:
            _require_int_gt(max_sub, "classification.max_subject_chars", 0, strictly_greater=True)

        max_b = classification.get("max_body_chars")
        if max_b is not None:
            _require_int_gt(max_b, "classification.max_body_chars", 0, strictly_greater=True)

        primary = classification.get("primary")
        if primary is not None:
            _require_nonempty_str(primary, "classification.primary")

        fallback = classification.get("fallback")
        if fallback is not None:
            _require_nonempty_str(fallback, "classification.fallback")

        class_jev = classification.get("jev")
        if class_jev is not None:
            if not isinstance(class_jev, dict):
                raise ConfigError("'classification.jev' must be a mapping")
            _check_unknown_keys(class_jev, "classification.jev")
            if "enabled" in class_jev:
                _require_bool(class_jev["enabled"], "classification.jev.enabled")
            if "model" in class_jev:
                _require_nonempty_str(class_jev["model"], "classification.jev.model")
            if "api_url" in class_jev:
                _require_nonempty_str(class_jev["api_url"], "classification.jev.api_url")
            if "router_question_id" in class_jev:
                _require_nonempty_str(
                    class_jev["router_question_id"], "classification.jev.router_question_id"
                )
            if "timeout_seconds" in class_jev:
                _require_number_gt(class_jev["timeout_seconds"], "classification.jev.timeout_seconds", 0)

    # ── dispatch (Phase 2 section) ──────────────────────────────────────────
    if "dispatch" in config:
        dispatch = _require_mapping(config, "dispatch")
        _check_unknown_keys(dispatch, "dispatch")

        dry_run = dispatch.get("dry_run")
        if dry_run is None:
            raise ConfigError("'dispatch.dry_run' is required")
        _require_bool(dry_run, "dispatch.dry_run")

        kill_switch = dispatch.get("kill_switch")
        if kill_switch is None:
            raise ConfigError("'dispatch.kill_switch' is required")
        _require_bool(kill_switch, "dispatch.kill_switch")

        max_attempts = dispatch.get("max_attempts")
        if max_attempts is None:
            raise ConfigError("'dispatch.max_attempts' is required")
        _require_int_gt(max_attempts, "dispatch.max_attempts", 0, strictly_greater=True)
        if max_attempts > 10:
            raise ConfigError(f"'dispatch.max_attempts' must be <= 10, got {max_attempts}")

        pending_timeout = dispatch.get("pending_timeout_minutes")
        if pending_timeout is None:
            raise ConfigError("'dispatch.pending_timeout_minutes' is required")
        _require_int_gt(
            pending_timeout, "dispatch.pending_timeout_minutes", 0, strictly_greater=True
        )

        backoff_base = dispatch.get("backoff_base_seconds")
        if backoff_base is None:
            raise ConfigError("'dispatch.backoff_base_seconds' is required")
        _require_number_gt(backoff_base, "dispatch.backoff_base_seconds", 0)

        backoff_max = dispatch.get("backoff_max_seconds")
        if backoff_max is None:
            raise ConfigError("'dispatch.backoff_max_seconds' is required")
        _require_number_gt(backoff_max, "dispatch.backoff_max_seconds", 0)

        if backoff_max < backoff_base:
            raise ConfigError(
                f"'dispatch.backoff_max_seconds' ({backoff_max}) must be >= "
                f"'dispatch.backoff_base_seconds' ({backoff_base})"
            )

    # ── destinations (Phase 2 section) ──────────────────────────────────────
    if "destinations" in config:
        destinations = _require_mapping(config, "destinations")
        _check_unknown_keys(destinations, "destinations")

        required_dests = ("github", "freescout", "crm", "webhook")
        for dest_name in required_dests:
            if dest_name not in destinations:
                raise ConfigError(
                    f"Missing required destination in 'destinations': '{dest_name}'"
                )

        for dest_name, dest_cfg in destinations.items():
            if not isinstance(dest_cfg, dict):
                raise ConfigError(f"'destinations.{dest_name}' must be a mapping")
            section_key = (
                f"destinations.{dest_name}"
                if f"destinations.{dest_name}" in _KNOWN_KEYS
                else "destinations.item"
            )
            _check_unknown_keys(dest_cfg, section_key)

            enabled = dest_cfg.get("enabled")
            if enabled is None:
                raise ConfigError(f"'destinations.{dest_name}.enabled' is required")
            _require_bool(enabled, f"destinations.{dest_name}.enabled")

            daily_cap = dest_cfg.get("daily_cap")
            if daily_cap is None:
                raise ConfigError(f"'destinations.{dest_name}.daily_cap' is required")
            _require_int_gt(
                daily_cap, f"destinations.{dest_name}.daily_cap", 0, strictly_greater=True
            )

            use_masked = dest_cfg.get("use_masked_text_only")
            if use_masked is None:
                raise ConfigError(
                    f"'destinations.{dest_name}.use_masked_text_only' is required"
                )
            _require_bool(use_masked, f"destinations.{dest_name}.use_masked_text_only")

            circuit_breaker = dest_cfg.get("circuit_breaker")
            if circuit_breaker is None:
                raise ConfigError(
                    f"'destinations.{dest_name}.circuit_breaker' is required"
                )
            if not isinstance(circuit_breaker, dict):
                raise ConfigError(
                    f"'destinations.{dest_name}.circuit_breaker' must be a mapping"
                )
            _check_unknown_keys(circuit_breaker, "destinations.circuit_breaker")

            f_thresh = circuit_breaker.get("failure_threshold")
            if f_thresh is None:
                raise ConfigError(
                    f"'destinations.{dest_name}.circuit_breaker.failure_threshold' is required"
                )
            _require_int_gt(
                f_thresh,
                f"destinations.{dest_name}.circuit_breaker.failure_threshold",
                0,
                strictly_greater=True,
            )

            cooldown = circuit_breaker.get("cooldown_seconds")
            if cooldown is None:
                raise ConfigError(
                    f"'destinations.{dest_name}.circuit_breaker.cooldown_seconds' is required"
                )
            _require_int_gt(
                cooldown,
                f"destinations.{dest_name}.circuit_breaker.cooldown_seconds",
                0,
                strictly_greater=True,
            )

            if "token_env" in dest_cfg:
                _require_nonempty_str(
                    dest_cfg["token_env"], f"destinations.{dest_name}.token_env"
                )
            if "api_key_env" in dest_cfg:
                _require_nonempty_str(
                    dest_cfg["api_key_env"], f"destinations.{dest_name}.api_key_env"
                )
            if "target_env" in dest_cfg:
                _require_nonempty_str(
                    dest_cfg["target_env"], f"destinations.{dest_name}.target_env"
                )
            if "mailbox_id" in dest_cfg:
                _require_int_gt(
                    dest_cfg["mailbox_id"],
                    f"destinations.{dest_name}.mailbox_id",
                    0,
                    strictly_greater=True,
                )

            if dest_name == "github":
                if "target" in dest_cfg:
                    _require_nonempty_str(dest_cfg["target"], "destinations.github.target")
                    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", dest_cfg["target"]):
                        raise ConfigError(
                            f"'destinations.github.target' must match owner/repo format "
                            f"(^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$), got {dest_cfg['target']!r}"
                        )
                if "labels" in dest_cfg:
                    labels = dest_cfg["labels"]
                    if not isinstance(labels, list):
                        raise ConfigError("'destinations.github.labels' must be a list of strings")
                    for lbl in labels:
                        if not isinstance(lbl, str) or not lbl or len(lbl) > 50 or "," in lbl:
                            raise ConfigError(
                                "'destinations.github.labels' items must be non-empty strings "
                                "<= 50 characters with no commas"
                            )
                if "api_base_url" in dest_cfg:
                    api_base_url = dest_cfg["api_base_url"]
                    if not isinstance(api_base_url, str) or not api_base_url.strip():
                        raise ConfigError("'destinations.github.api_base_url' must be a non-empty string")
                    parsed_url = urlparse(api_base_url)
                    if parsed_url.scheme != "https":
                        raise ConfigError(
                            f"'destinations.github.api_base_url' scheme must be https, got {parsed_url.scheme!r}"
                        )
                    if not parsed_url.netloc:
                        raise ConfigError("'destinations.github.api_base_url' netloc must not be empty")
                    if parsed_url.query:
                        raise ConfigError("'destinations.github.api_base_url' must not contain query parameters")
                    if parsed_url.fragment:
                        raise ConfigError("'destinations.github.api_base_url' must not contain a fragment")
                    if parsed_url.username or parsed_url.password:
                        raise ConfigError("'destinations.github.api_base_url' must not contain credentials")

                if "allowed_hosts" in dest_cfg:
                    allowed_hosts = dest_cfg["allowed_hosts"]
                    if not isinstance(allowed_hosts, list) or len(allowed_hosts) == 0:
                        raise ConfigError(
                            "'destinations.github.allowed_hosts' must be a non-empty list of hostnames"
                        )
                    for h in allowed_hosts:
                        if not isinstance(h, str) or not h:
                            raise ConfigError(
                                "'destinations.github.allowed_hosts' items must be non-empty strings"
                            )
                        if h != h.lower():
                            raise ConfigError(
                                f"'destinations.github.allowed_hosts' hostname {h!r} must be lowercase"
                            )
                        if ":" in h or "/" in h:
                            raise ConfigError(
                                f"'destinations.github.allowed_hosts' item {h!r} must be a bare hostname (no scheme, port, or path)"
                            )
                    if "api_base_url" in dest_cfg and isinstance(dest_cfg["api_base_url"], str):
                        parsed_base = urlparse(dest_cfg["api_base_url"])
                        base_host = (parsed_base.hostname or "").lower()
                        if base_host and base_host not in allowed_hosts:
                            raise ConfigError(
                                f"'destinations.github.allowed_hosts' must contain the hostname of 'api_base_url' ({base_host!r})"
                            )

                if "request_timeout_seconds" in dest_cfg:
                    timeout = dest_cfg["request_timeout_seconds"]
                    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
                        raise ConfigError(
                            "'destinations.github.request_timeout_seconds' must be a number > 0"
                        )

                if "duplicate_lookback_hours" in dest_cfg:
                    _require_int_gt(
                        dest_cfg["duplicate_lookback_hours"],
                        "destinations.github.duplicate_lookback_hours",
                        0,
                        strictly_greater=True,
                    )

                if "duplicate_max_pages" in dest_cfg:
                    _require_int_gt(
                        dest_cfg["duplicate_max_pages"],
                        "destinations.github.duplicate_max_pages",
                        0,
                        strictly_greater=True,
                    )

                if "precheck_duplicates" in dest_cfg:
                    _require_bool(
                        dest_cfg["precheck_duplicates"],
                        "destinations.github.precheck_duplicates",
                    )

                if "bot_login" in dest_cfg and dest_cfg["bot_login"] is not None:
                    b_login = dest_cfg["bot_login"]
                    if not isinstance(b_login, str) or not b_login.strip() or len(b_login.strip()) > 39:
                        raise ConfigError(
                            "'destinations.github.bot_login' must be a non-empty string of at most 39 characters or None"
                        )

                if "api_version" in dest_cfg and dest_cfg["api_version"] is not None:
                    a_ver = dest_cfg["api_version"]
                    if not isinstance(a_ver, str) or not a_ver.strip():
                        raise ConfigError(
                            "'destinations.github.api_version' must be a non-empty string or None"
                        )
            elif dest_name == "freescout":
                if "target" in dest_cfg:
                    _require_nonempty_str(dest_cfg["target"], "destinations.freescout.target")
                    target = dest_cfg["target"]
                    if not target.startswith("https://"):
                        raise ConfigError("'destinations.freescout.target' must start with 'https://'")
                if "mailbox_id" in dest_cfg:
                    _require_int_gt(
                        dest_cfg["mailbox_id"],
                        "destinations.freescout.mailbox_id",
                        0,
                        strictly_greater=True,
                    )
                if "unmask_pii" in dest_cfg:
                    _require_bool(dest_cfg["unmask_pii"], "destinations.freescout.unmask_pii")
                if "precheck_duplicates" in dest_cfg:
                    _require_bool(
                        dest_cfg["precheck_duplicates"],
                        "destinations.freescout.precheck_duplicates",
                    )
                if "request_timeout_seconds" in dest_cfg:
                    timeout = dest_cfg["request_timeout_seconds"]
                    if (
                        isinstance(timeout, bool)
                        or not isinstance(timeout, (int, float))
                        or timeout <= 0
                    ):
                        raise ConfigError(
                            "'destinations.freescout.request_timeout_seconds' must be a number > 0"
                        )
                if "allowed_hosts" in dest_cfg:
                    allowed_hosts = dest_cfg["allowed_hosts"]
                    if not isinstance(allowed_hosts, list) or not allowed_hosts:
                        raise ConfigError(
                            "'destinations.freescout.allowed_hosts' must be a non-empty list of strings"
                        )
                    for h in allowed_hosts:
                        if not isinstance(h, str) or not h:
                            raise ConfigError(
                                "'destinations.freescout.allowed_hosts' items must be non-empty strings"
                            )
                        if h != h.lower():
                            raise ConfigError(
                                f"'destinations.freescout.allowed_hosts' hostname {h!r} must be lowercase"
                            )
                        if ":" in h or "/" in h:
                            raise ConfigError(
                                f"'destinations.freescout.allowed_hosts' item {h!r} must be a bare hostname (no scheme, port, or path)"
                            )
            elif dest_name == "crm":
                if "target" in dest_cfg:
                    _require_nonempty_str(dest_cfg["target"], "destinations.crm.target")
                    target = dest_cfg["target"]
                    if not target.startswith("https://"):
                        raise ConfigError("'destinations.crm.target' must start with 'https://'")
                if "unmask_pii" in dest_cfg:
                    _require_bool(dest_cfg["unmask_pii"], "destinations.crm.unmask_pii")
                if "precheck_duplicates" in dest_cfg:
                    _require_bool(
                        dest_cfg["precheck_duplicates"],
                        "destinations.crm.precheck_duplicates",
                    )
                if "request_timeout_seconds" in dest_cfg:
                    timeout = dest_cfg["request_timeout_seconds"]
                    if (
                        isinstance(timeout, bool)
                        or not isinstance(timeout, (int, float))
                        or timeout <= 0
                    ):
                        raise ConfigError(
                            "'destinations.crm.request_timeout_seconds' must be a number > 0"
                        )
                if "allowed_hosts" in dest_cfg:
                    allowed_hosts = dest_cfg["allowed_hosts"]
                    if not isinstance(allowed_hosts, list) or not allowed_hosts:
                        raise ConfigError(
                            "'destinations.crm.allowed_hosts' must be a non-empty list of strings"
                        )
                    for h in allowed_hosts:
                        if not isinstance(h, str) or not h:
                            raise ConfigError(
                                "'destinations.crm.allowed_hosts' items must be non-empty strings"
                            )
                        if h != h.lower():
                            raise ConfigError(
                                f"'destinations.crm.allowed_hosts' hostname {h!r} must be lowercase"
                            )
                        if ":" in h or "/" in h:
                            raise ConfigError(
                                f"'destinations.crm.allowed_hosts' item {h!r} must be a bare hostname (no scheme, port, or path)"
                            )
            elif dest_name == "webhook":
                if "target" in dest_cfg:
                    _require_nonempty_str(dest_cfg["target"], "destinations.webhook.target")
                    target = dest_cfg["target"]
                    if not target.startswith("https://"):
                        raise ConfigError("'destinations.webhook.target' must start with 'https://'")
                if "unmask_pii" in dest_cfg:
                    _require_bool(dest_cfg["unmask_pii"], "destinations.webhook.unmask_pii")
                if "request_timeout_seconds" in dest_cfg:
                    timeout = dest_cfg["request_timeout_seconds"]
                    if (
                        isinstance(timeout, bool)
                        or not isinstance(timeout, (int, float))
                        or timeout <= 0
                    ):
                        raise ConfigError(
                            "'destinations.webhook.request_timeout_seconds' must be a number > 0"
                        )
                if "allowed_hosts" in dest_cfg:
                    allowed_hosts = dest_cfg["allowed_hosts"]
                    if not isinstance(allowed_hosts, list) or not allowed_hosts:
                        raise ConfigError(
                            "'destinations.webhook.allowed_hosts' must be a non-empty list of strings"
                        )
                    for h in allowed_hosts:
                        if not isinstance(h, str) or not h:
                            raise ConfigError(
                                "'destinations.webhook.allowed_hosts' items must be non-empty strings"
                            )
                        if h != h.lower():
                            raise ConfigError(
                                f"'destinations.webhook.allowed_hosts' hostname {h!r} must be lowercase"
                            )
                        if ":" in h or "/" in h:
                            raise ConfigError(
                                f"'destinations.webhook.allowed_hosts' item {h!r} must be a bare hostname (no scheme, port, or path)"
                            )
            else:
                if "target" in dest_cfg:
                    _require_nonempty_str(dest_cfg["target"], f"destinations.{dest_name}.target")
                if "labels" in dest_cfg:
                    labels = dest_cfg["labels"]
                    if not isinstance(labels, list) or not all(
                        isinstance(lbl, str) for lbl in labels
                    ):
                        raise ConfigError(
                            f"'destinations.{dest_name}.labels' must be a list of strings"
                        )

    # ── mailbox (P2-12) ───────────────────────────────────────────────────────
    mailbox = config.get("mailbox")
    if mailbox is not None:
        if not isinstance(mailbox, dict):
            raise ConfigError(f"'mailbox' must be a mapping, got {type(mailbox).__name__!r}")
        _check_unknown_keys(mailbox, "mailbox")
        if "enabled" in mailbox:
            _require_bool(mailbox["enabled"], "mailbox.enabled")
        if "provider" in mailbox:
            _require_nonempty_str(mailbox["provider"], "mailbox.provider")
        if "poll_interval_seconds" in mailbox:
            _require_int_gt(
                mailbox["poll_interval_seconds"],
                "mailbox.poll_interval_seconds",
                0,
                strictly_greater=True,
            )
        gmail = mailbox.get("gmail")
        if gmail is not None:
            if not isinstance(gmail, dict):
                raise ConfigError(f"'mailbox.gmail' must be a mapping, got {type(gmail).__name__!r}")
            _check_unknown_keys(gmail, "mailbox.gmail")
            if "allowed_hosts" in gmail:
                allowed_hosts = gmail["allowed_hosts"]
                if not isinstance(allowed_hosts, list) or not allowed_hosts:
                    raise ConfigError(
                        "'mailbox.gmail.allowed_hosts' must be a non-empty list of strings"
                    )


def _apply_env_overrides(cfg: Dict[str, Any]) -> None:
    """Applies DATABASE_PATH, IDEMPOTENCY_STALE_MINUTES, MAX_DISPATCH_RETRIES from env.

    Env > config.yaml precedence.  Empty-string env var means 'no override'.
    Raises ConfigError (naming the variable) for invalid values; never echoes values.
    """
    system = cfg.setdefault("system", {})

    db_path_env = os.environ.get("DATABASE_PATH", "")
    if db_path_env:
        system["database_path"] = db_path_env

    stale_env = os.environ.get("IDEMPOTENCY_STALE_MINUTES", "")
    if stale_env:
        try:
            stale_val = int(stale_env)
        except ValueError:
            raise ConfigError("IDEMPOTENCY_STALE_MINUTES: must be int > 0")
        if stale_val <= 0:
            raise ConfigError("IDEMPOTENCY_STALE_MINUTES: must be int > 0")
        system["idempotency_stale_minutes"] = stale_val

    retries_env = os.environ.get("MAX_DISPATCH_RETRIES", "")
    if retries_env:
        try:
            retries_val = int(retries_env)
        except ValueError:
            raise ConfigError("MAX_DISPATCH_RETRIES: must be int >= 0")
        if retries_val < 0:
            raise ConfigError("MAX_DISPATCH_RETRIES: must be int >= 0")
        system["max_dispatch_retries"] = retries_val


def _resolve_relative_paths(cfg: Dict[str, Any]) -> None:
    """Resolves relative file-paths in config against BASE_DIR (not CWD)."""
    system = cfg.get("system", {})
    db_path = system.get("database_path", "")
    if db_path and not Path(db_path).is_absolute():
        system["database_path"] = str(BASE_DIR / db_path)

    privacy = cfg.get("privacy", {})
    tech_file = privacy.get("tech_terms_file", "")
    if tech_file and not Path(tech_file).is_absolute():
        privacy["tech_terms_file"] = str(BASE_DIR / tech_file)


def load_config(config_path=None) -> Dict[str, Any]:
    """Loads, validates, and returns the YAML configuration.

    Args:
        config_path: Path to the YAML config file.  None → DEFAULT_CONFIG_PATH.
                     A relative path is resolved against BASE_DIR (not CWD).
                     An absolute path is used as given.

    Returns:
        Validated dict containing parsed configuration.

    Raises:
        FileNotFoundError: Config file does not exist.
        ConfigError: YAML syntax error, empty/non-mapping file, or invalid values.
    """
    if config_path is None:
        path = DEFAULT_CONFIG_PATH
    else:
        p = Path(config_path)
        path = p if p.is_absolute() else BASE_DIR / p

    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            raw = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            # Surface file name and position only — never file content.
            mark = getattr(exc, "problem_mark", None)
            location = ""
            if mark is not None:
                location = f": line {mark.line + 1}, column {mark.column + 1}"
            raise ConfigError(f"{path.name}{location}") from exc

    if raw is None or not isinstance(raw, dict):
        raise ConfigError(
            f"Configuration file must be a YAML mapping, got "
            f"{type(raw).__name__ if raw is not None else 'empty file'}"
        )

    # 1. Validate the file exactly as written (before applying environment overrides)
    validate_config(raw)

    # 2. Apply environment variable overrides (precedence env > config.yaml)
    _apply_env_overrides(raw)

    # 3. Resolve relative paths inside config against BASE_DIR
    _resolve_relative_paths(raw)

    # 4. Validate final values again after overrides and path resolution
    validate_config(raw)

    return raw


_CONFIG_CACHE: Optional[Dict[str, Any]] = None
_CONFIG_LOCK = threading.Lock()


def get_config(config_path=None) -> Dict[str, Any]:
    """Retrieves cached configuration, loading and validating it once per process.

    Thread-safe.

    Args:
        config_path: Path to configuration file. None uses DEFAULT_CONFIG_PATH.

    Returns:
        The validated configuration dictionary.
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None and config_path is None:
        return _CONFIG_CACHE

    with _CONFIG_LOCK:
        if _CONFIG_CACHE is not None and config_path is None:
            return _CONFIG_CACHE
        loaded = load_config(config_path)
        if config_path is None:
            _CONFIG_CACHE = loaded
        return loaded


def reset_config_cache() -> None:
    """Resets the process-wide cached configuration (used for tests)."""
    global _CONFIG_CACHE
    with _CONFIG_LOCK:
        _CONFIG_CACHE = None
    try:
        from nodes.sensitive_skip import reset_keyword_patterns_cache
        reset_keyword_patterns_cache()
    except ImportError:
        pass


def get_env_var(
    var_name: Optional[str], default: Optional[str] = None
) -> Optional[str]:
    """Retrieves an environment variable by name.

    Args:
        var_name: Name of the environment variable.
        default: Default value if the environment variable is not set.

    Returns:
        The environment variable value or the default.
    """
    if not var_name:
        return default
    return os.environ.get(var_name, default)


def resolve_destination_config(
    destination: str,
    config: Optional[Dict[str, Any]] = None,
    config_path=None,
) -> Optional[Dict[str, Any]]:
    """Retrieves and resolves credentials for a specific destination service.

    Replaces any `*_env` field with its corresponding live environment variable
    value. For example, if destination config contains `token_env: GITHUB_TOKEN`,
    the returned dict will include `resolved_token: <value_of_GITHUB_TOKEN>`.

    Args:
        destination: Name of the destination service ('github', 'freescout', 'crm', 'webhook').
        config: Optional pre-loaded config dict. If None, loaded from config_path.
        config_path: Path to config.yaml if config is None (None → DEFAULT_CONFIG_PATH).

    Returns:
        Resolved destination dict or None if destination is not configured.
    """
    if config is None:
        config = get_config(config_path)

    destinations = config.get("destinations", {})
    dest_config = destinations.get(destination)
    if not dest_config:
        return None

    resolved = dict(dest_config)
    # Automatically resolve any *_env fields to live environment secrets
    for key, value in dest_config.items():
        if key.endswith("_env") and isinstance(value, str):
            secret_key = key[:-4]  # e.g., 'token_env' -> 'token'
            resolved[f"resolved_{secret_key}"] = get_env_var(value)

    return resolved
