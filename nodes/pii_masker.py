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

import re
from typing import Any, Dict, List, Optional, Set, Tuple
import logging

from state import TriageState
from utils.config import load_config

logger = logging.getLogger(__name__)

# Cached spaCy NLP model instance
_SPACY_NLP = None


def get_spacy_nlp(model_name: str = "en_core_web_sm"):
    """Loads and caches the spaCy language pipeline model.

    Args:
        model_name: Name of the spaCy model.

    Returns:
        Loaded Language pipeline, or None if unavailable.
    """
    global _SPACY_NLP
    if _SPACY_NLP is not None:
        return _SPACY_NLP

    try:
        import spacy

        _SPACY_NLP = spacy.load(model_name)
    except Exception as exc:
        logger.warning(
            f"Failed to load spaCy model '{model_name}': {exc}. "
            "Continuing with regex PII masking."
        )
        _SPACY_NLP = None

    return _SPACY_NLP


# Regex definitions for structured PII entities
API_KEY_PATTERNS = [
    # Common prefix API keys: sk_..., rk_..., ghp_..., gho_..., AKIA...
    re.compile(
        r"\b(?:[sr]k_[a-zA-Z0-9_\-]{14,}|ghp_[a-zA-Z0-9]{30,}|gho_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16})\b"
    ),
    # Bearer tokens
    re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-]{14,})\b"),
    # Explicit secret assignments (e.g. api_key = "...", secret_token: ...)
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{14,})['\"]?"
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
) -> Tuple[str, Dict[str, str]]:
    """Sanitizes text by replacing PII with anonymized placeholder tokens.

    Args:
        text: Input text string to sanitize.
        spacy_model_name: Optional spaCy model override.

    Returns:
        Tuple of (masked_text, token_map) where token_map maps [TOKEN_N] -> original value.
    """
    if not text:
        return "", {}

    token_map: Dict[str, str] = {}
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
) -> Dict[str, Any]:
    """LangGraph node execution function for local PII masking.

    Args:
        state: Pipeline state containing 'cleaned_body' or 'email_body'.
        spacy_model_name: Optional spaCy model override.

    Returns:
        Dictionary update with 'masked_body' and 'token_map'.
    """
    body = state.get("cleaned_body")
    if body is None:
        body = state.get("email_body") or state.get("raw_body") or ""

    masked_body, token_map = mask_pii(body, spacy_model_name=spacy_model_name)

    return {
        "masked_body": masked_body,
        "token_map": token_map,
    }
