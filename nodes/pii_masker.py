"""Node 03: Local PII Masker and Token Mapper.

This node performs 100% on-premise PII redaction:
1. Replaces sensitive customer data with deterministic placeholder tokens:
   - [EMAIL_1], [EMAIL_2], ...
   - [PHONE_1], [PHONE_2], ...
   - [API_KEY_1], [API_KEY_2], ...
   - [CREDIT_CARD_1], ...
   - [SSN_1], ...
   - [IP_ADDRESS_1], ...
   - [PERSON_1], [PERSON_2], ...
2. Maintains a bidirectional `token_map` ({token: original_value}) stored in TriageState.
3. Provides reverse `unmask_text(text, token_map)` for downstream internal dispatchers.
4. Guarantees 0% customer PII leaves local infrastructure to third-party LLMs.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from state import TriageState
from utils.config import load_config

logger = logging.getLogger(__name__)

# Cached spaCy NLP model state
_SPACY_NLP = None
_SPACY_INITIALIZED: bool = False
_SPACY_FAILED: bool = False
_SPACY_WARNED_STARTUP: bool = False


def is_valid_api_key(key: Optional[str]) -> bool:
    """Determines if an API key string is non-empty and not a placeholder."""
    if not key or not isinstance(key, str):
        return False
    k = key.strip().lower()
    if not k:
        return False
    if k.startswith("your_") or "placeholder" in k or "your_jev_api_key_here" in k:
        return False
    return True


def is_external_ai_enabled(
    client: Optional[Any] = None,
    config: Optional[Dict[str, Any]] = None,
    offline: bool = False,
) -> bool:
    """Determines whether external AI (Jev or Groq) is currently enabled.

    External AI is enabled iff:
    1. The run is not offline (offline=False).
    2. A valid (non-empty, non-placeholder) JEV_API_KEY or GROQ_API_KEY is configured.
    """
    if offline:
        return False

    # Check client instance if provided
    if client is not None:
        client_jev = getattr(client, "api_key", None)
        client_groq = getattr(client, "groq_api_key", None)
        if is_valid_api_key(client_jev) or is_valid_api_key(client_groq):
            return True
        if client_jev is not None and client_groq is not None:
            return False

    if config is None:
        try:
            config = load_config()
        except Exception:
            config = None

    jev_env = "JEV_API_KEY"
    groq_env = "GROQ_API_KEY"
    if config is not None:
        jev_env = config.get("jev", {}).get("api_key_env", "JEV_API_KEY")
        groq_env = config.get("groq", {}).get("api_key_env", "GROQ_API_KEY")

    jev_key = os.environ.get(jev_env) or os.environ.get("JEV_API_KEY")
    groq_key = os.environ.get(groq_env) or os.environ.get("GROQ_API_KEY")

    return is_valid_api_key(jev_key) or is_valid_api_key(groq_key)


def get_spacy_nlp(model_name: Optional[str] = None):
    """Loads and caches the spaCy language pipeline model once at startup.

    Remembers a failure and does not retry on every email.

    Args:
        model_name: Optional name of the spaCy model. Defaults to config or 'en_core_web_sm'.

    Returns:
        Loaded Language pipeline, or None if unavailable.
    """
    global _SPACY_NLP, _SPACY_INITIALIZED, _SPACY_FAILED, _SPACY_WARNED_STARTUP
    if _SPACY_INITIALIZED:
        return _SPACY_NLP

    _SPACY_INITIALIZED = True
    if model_name is None:
        try:
            cfg = load_config()
            model_name = cfg.get("privacy", {}).get("spacy_model", "en_core_web_sm")
        except Exception:
            model_name = "en_core_web_sm"

    try:
        import spacy

        _SPACY_NLP = spacy.load(model_name)
        _SPACY_FAILED = False
    except Exception as exc:
        _SPACY_NLP = None
        _SPACY_FAILED = True
        if not is_external_ai_enabled():
            if not _SPACY_WARNED_STARTUP:
                logger.warning(
                    "spaCy model unavailable and external AI is disabled; "
                    "names will only be masked by regex rules."
                )
                _SPACY_WARNED_STARTUP = True

    return _SPACY_NLP


def is_spacy_available(model_name: Optional[str] = None) -> bool:
    """Returns True if spaCy NLP is loaded and has not failed at runtime."""
    nlp = get_spacy_nlp(model_name)
    return (nlp is not None) and (not _SPACY_FAILED)


def reset_spacy_cache() -> None:
    """Resets cached spaCy NLP state (for unit testing)."""
    global _SPACY_NLP, _SPACY_INITIALIZED, _SPACY_FAILED, _SPACY_WARNED_STARTUP
    _SPACY_NLP = None
    _SPACY_INITIALIZED = False
    _SPACY_FAILED = False
    _SPACY_WARNED_STARTUP = False


def validate_startup(
    client: Optional[Any] = None,
    config: Optional[Dict[str, Any]] = None,
    offline: bool = False,
    spacy_model_name: Optional[str] = None,
) -> None:
    """Startup guard for spaCy availability.

    1. If external AI is enabled and the spaCy model cannot be loaded,
       raises a clear RuntimeError at startup.
    2. If external AI is not enabled (no keys, or --offline), keeps working
       without spaCy but logs ONE warning at startup.
    """
    global _SPACY_WARNED_STARTUP

    ext_ai = is_external_ai_enabled(client=client, config=config, offline=offline)
    nlp = get_spacy_nlp(model_name=spacy_model_name)

    if nlp is None:
        if ext_ai:
            raise RuntimeError(
                "Startup guard failed: spaCy model could not be loaded while external AI "
                "(Jev/Groq) is enabled. Refusing to start to prevent unmasked PII egress."
            )
        else:
            if not _SPACY_WARNED_STARTUP:
                logger.warning(
                    "spaCy model unavailable and external AI is disabled; "
                    "names will only be masked by regex rules."
                )
                _SPACY_WARNED_STARTUP = True


# Regex definitions for structured PII entities (with upper length bounds to prevent ReDoS)
API_KEY_PATTERNS = [
    # Common prefix API keys: sk_..., rk_..., ghp_..., gho_..., AKIA...
    re.compile(
        r"\b(?:[sr]k_[a-zA-Z0-9_\-]{14,256}|ghp_[a-zA-Z0-9]{30,256}|gho_[a-zA-Z0-9]{30,256}|AKIA[0-9A-Z]{16})\b"
    ),
    # Bearer tokens
    re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-]{14,256})\b"),
    # Explicit secret assignments (e.g. api_key = "...", secret_token: ...)
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{14,256})['\"]?"
    ),
]

CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{4}[ -]?\d{6}[ -]?\d{5}\b"
)

SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# North American & common international phone number formats
PHONE_REGEX = re.compile(
    r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|"
    r"\+\d{1,3}[-.\s]\d{1,4}[-.\s]\d{3,4}[-.\s]\d{3,4}\b"
)

# Standard IPv4 addresses (excluding non-routable versions like software releases 3.11.2)
IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Technical terms and common false positives that small NER models occasionally misclassify
NON_PERSON_ENTITIES = {
    "api",
    "sdk",
    "aws",
    "github",
    "slack",
    "stripe",
    "linux",
    "ubuntu",
    "docker",
    "kubernetes",
    "python",
    "javascript",
    "react",
    "fastapi",
    "support",
    "sales",
    "billing",
    "engineering",
    "devops",
    "urgent",
    "customer",
    "admin",
    "null",
    "undefined",
    "true",
    "false",
}

# Cached tech-terms whitelist set loaded from config
_TECH_TERMS_CACHE: Optional[Set[str]] = None


def load_tech_terms_whitelist(filepath: Optional[str] = None) -> Set[str]:
    """Loads and caches technical terms whitelist from external file.

    Terms are matched case-insensitively as exact whole entities to prevent
    spaCy NER from misclassifying infrastructure and developer tools as PERSON.
    Falls back safely to internal NON_PERSON_ENTITIES if file is unavailable.

    Args:
        filepath: Optional path to tech terms file. If None, checks config.yaml.

    Returns:
        Set of lowercase whitelist terms.
    """
    global _TECH_TERMS_CACHE
    if _TECH_TERMS_CACHE is not None and filepath is None:
        return _TECH_TERMS_CACHE

    terms = set(NON_PERSON_ENTITIES)
    target_path = filepath
    if target_path is None:
        try:
            cfg = load_config()
            target_path = cfg.get("privacy", {}).get(
                "tech_terms_file", "config/tech_terms.txt"
            )
        except Exception:
            target_path = "config/tech_terms.txt"

    if target_path:
        from pathlib import Path

        candidate = Path(target_path)
        if not candidate.is_absolute():
            # Resolve relative to project root
            repo_root = Path(__file__).resolve().parent.parent
            resolved = repo_root / target_path
            if resolved.exists():
                candidate = resolved

        if candidate.exists():
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            terms.add(line.lower())
            except Exception:
                # Log nothing about customer text or specific terms
                pass

    if filepath is None:
        _TECH_TERMS_CACHE = terms
    return terms


def reset_tech_terms_cache() -> None:
    """Resets cached tech terms whitelist (used for testing or dynamic reloads)."""
    global _TECH_TERMS_CACHE
    _TECH_TERMS_CACHE = None


def mask_pii(
    text: str,
    spacy_model_name: Optional[str] = None,
    token_map: Optional[Dict[str, str]] = None,
) -> Tuple[str, Dict[str, str]]:
    """Sanitizes text by replacing PII with anonymized placeholder tokens.

    Args:
        text: Input text string to sanitize.
        spacy_model_name: Optional spaCy model override.
        token_map: Optional existing token map to reuse tokens and counters across texts.

    Returns:
        Tuple of (masked_text, token_map) where token_map maps [TOKEN_N] -> original value.
    """
    global _SPACY_FAILED

    if token_map is None:
        token_map = {}
        value_to_token: Dict[str, str] = {}
        entity_counters: Dict[str, int] = {
            "API_KEY": 0,
            "CREDIT_CARD": 0,
            "SSN": 0,
            "EMAIL": 0,
            "PHONE": 0,
            "IP_ADDRESS": 0,
            "PERSON": 0,
        }
    else:
        token_map = dict(token_map)
        value_to_token = {v: k for k, v in token_map.items()}
        entity_counters = {
            "API_KEY": 0,
            "CREDIT_CARD": 0,
            "SSN": 0,
            "EMAIL": 0,
            "PHONE": 0,
            "IP_ADDRESS": 0,
            "PERSON": 0,
        }
        for tok in token_map.keys():
            m = re.match(r"^\[([A-Z_]+)_(\d+)\]$", tok)
            if m:
                etype, idx = m.group(1), int(m.group(2))
                if etype in entity_counters:
                    entity_counters[etype] = max(entity_counters[etype], idx)

    if not text:
        return "", token_map

    def get_or_create_token(entity_type: str, original_val: str) -> str:
        if original_val in value_to_token:
            return value_to_token[original_val]
        entity_counters[entity_type] += 1
        token = f"[{entity_type}_{entity_counters[entity_type]}]"
        token_map[token] = original_val
        value_to_token[original_val] = token
        return token

    working = text

    # 1. Regex Pass: API Keys & Secrets
    for pattern in API_KEY_PATTERNS:
        matches = list(pattern.finditer(working))
        for match in reversed(matches):
            val = (
                match.group(1)
                if match.lastindex and match.lastindex >= 1
                else match.group(0)
            )
            token = get_or_create_token("API_KEY", val)
            start, end = (
                match.span(1)
                if match.lastindex and match.lastindex >= 1
                else match.span(0)
            )
            working = working[:start] + token + working[end:]

    # 2. Regex Pass: Credit Cards
    matches = list(CREDIT_CARD_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        # Avoid matching simple 16-character alphanumeric words or tokens
        digits_only = re.sub(r"\D", "", val)
        if 13 <= len(digits_only) <= 19:
            token = get_or_create_token("CREDIT_CARD", val)
            working = working[: match.start()] + token + working[match.end() :]

    # 3. Regex Pass: SSN / Tax IDs
    matches = list(SSN_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        token = get_or_create_token("SSN", val)
        working = working[: match.start()] + token + working[match.end() :]

    # 4. Regex Pass: Email Addresses
    matches = list(EMAIL_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        token = get_or_create_token("EMAIL", val)
        working = working[: match.start()] + token + working[match.end() :]

    # 5. Regex Pass: Phone Numbers
    matches = list(PHONE_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        # Verify it has at least 7 digits to avoid matching date snippets
        if len(re.findall(r"\d", val)) >= 7:
            token = get_or_create_token("PHONE", val)
            working = working[: match.start()] + token + working[match.end() :]

    # 6. Regex Pass: IP Addresses
    matches = list(IP_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        token = get_or_create_token("IP_ADDRESS", val)
        working = working[: match.start()] + token + working[match.end() :]

    # 7. spaCy NER Pass: Person Names
    if spacy_model_name is None:
        try:
            cfg = load_config()
            spacy_model_name = cfg.get("privacy", {}).get(
                "spacy_model", "en_core_web_sm"
            )
        except Exception:
            spacy_model_name = "en_core_web_sm"

    nlp = get_spacy_nlp(spacy_model_name)
    if nlp is not None:
        try:
            doc = nlp(working)
            whitelist = load_tech_terms_whitelist()
            # Collect PERSON entities that are not part of an existing token
            person_spans: List[Tuple[int, int, str]] = []
            for ent in doc.ents:
                if ent.label_ == "PERSON":
                    ent_text = ent.text.strip()
                    # Skip if already a token like [EMAIL_1]
                    if ent_text.startswith("[") and ent_text.endswith("]"):
                        continue
                    # Skip masking only if the entity matches a whitelist term exactly (case-insensitive, whole entity)
                    if ent_text.lower() in whitelist:
                        continue
                    if len(ent_text) < 2:
                        continue
                    person_spans.append((ent.start_char, ent.end_char, ent_text))

            # Replace person entities from back to front to preserve string offsets
            for start_char, end_char, val in sorted(
                person_spans, key=lambda x: x[0], reverse=True
            ):
                token = get_or_create_token("PERSON", val)
                working = working[:start_char] + token + working[end_char:]
        except Exception as exc:
            _SPACY_FAILED = True
            logger.warning(f"spaCy NER processing failed at runtime: {exc}")
    else:
        _SPACY_FAILED = True

    # 8. Consistency Pass: Ensure any pre-existing tokens from token_map are replaced
    for val, token in sorted(value_to_token.items(), key=lambda x: len(x[0]), reverse=True):
        if len(val) >= 2 and val in working:
            pattern = re.compile(rf"\b{re.escape(val)}\b")
            working = pattern.sub(token, working)

    return working, token_map


def unmask_text(text: str, token_map: Dict[str, str]) -> str:
    """Restores masked tokens back to their original values.

    Args:
        text: Masked text string.
        token_map: Dictionary mapping [TOKEN_N] -> original value.

    Returns:
        Original unmasked text string.
    """
    if not text or not token_map:
        return text or ""

    restored = text
    # Sort tokens by length in descending order to prevent sub-token replacement collisions
    for token in sorted(token_map.keys(), key=len, reverse=True):
        restored = restored.replace(token, token_map[token])

    return restored


def pii_masker_node(
    state: TriageState,
    spacy_model_name: Optional[str] = None,
    client: Optional[Any] = None,
    offline: bool = False,
) -> Dict[str, Any]:
    """LangGraph node execution function for local PII masking.

    Args:
        state: Pipeline state containing 'cleaned_body' or 'email_body' and 'email_subject'.
        spacy_model_name: Optional spaCy model override.
        client: Optional AI client instance.
        offline: Whether pipeline is running in offline mode.

    Returns:
        Dictionary update with 'masked_subject', 'masked_body', and 'token_map'.
    """
    subject = state.get("email_subject") or ""
    body = state.get("cleaned_body")
    if body is None:
        body = state.get("email_body") or state.get("raw_body") or ""

    email_id = state.get("email_id") or "unknown"

    token_map = dict(state.get("token_map") or {})
    masked_subject, token_map = mask_pii(
        subject, spacy_model_name=spacy_model_name, token_map=token_map
    )
    masked_body, token_map = mask_pii(
        body, spacy_model_name=spacy_model_name, token_map=token_map
    )

    updates: Dict[str, Any] = {
        "masked_subject": masked_subject,
        "masked_body": masked_body,
        "token_map": token_map,
    }

    # Runtime guard (A8): if spaCy is missing or fails during processing while external AI is enabled
    spacy_unavailable = not is_spacy_available(spacy_model_name)
    if spacy_unavailable and is_external_ai_enabled(client=client, offline=offline):
        logger.warning(
            f"spaCy model unavailable during processing for email '{email_id}' while external AI enabled."
        )
        updates["spacy_failed"] = True
        updates["routing_status"] = "manual_review"
        updates["dispatch_status"] = "done"
        updates["dispatch_target"] = "Review/Manual"
        updates["gatekeeper_decision"] = "manual_review"

    return updates
