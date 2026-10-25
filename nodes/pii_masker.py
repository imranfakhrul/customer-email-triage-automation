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

import ipaddress
import logging
import os
import re
import secrets
from typing import Any, Dict, List, Optional, Set, Tuple

import phonenumbers

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


def luhn_checksum(candidate: str) -> bool:
    """Validates credit card candidate string using ISO/IEC 7812 Luhn checksum algorithm."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    for i, d in enumerate(digits[::-1]):
        if i % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def iban_checksum(candidate: str) -> bool:
    """Validates an IBAN candidate string using ISO 7064 Mod 97-10 check."""
    clean = re.sub(r"[\s-]+", "", candidate).upper()
    if not re.match(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$", clean):
        return False
    rearranged = clean[4:] + clean[:4]
    num_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(num_str) % 97 == 1
    except (ValueError, ArithmeticError):
        return False


# Regex definitions for structured PII entities (with upper length bounds to prevent ReDoS)
# Keys & secrets: run BEFORE phone pass so parts of tokens are not eaten by the phone rule
JWT_REGEX = re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b")
GOOGLE_KEY_REGEX = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
OPENAI_KEY_REGEX = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")
SLACK_KEY_REGEX = re.compile(r"\bxox[abpr]-[A-Za-z0-9-]+\b")
AWS_KEY_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
GITHUB_KEY_REGEX = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
PASSWORD_REGEX = re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*(\S+)")

API_KEY_PATTERNS = [
    JWT_REGEX,
    GOOGLE_KEY_REGEX,
    OPENAI_KEY_REGEX,
    SLACK_KEY_REGEX,
    AWS_KEY_REGEX,
    GITHUB_KEY_REGEX,
    # Bearer tokens
    re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-]{14,256})\b"),
    # Common prefix API keys: sk_..., rk_..., ghp_..., gho_..., AKIA...
    re.compile(
        r"\b(?:[sr]k_[a-zA-Z0-9_\-]{14,256}|ghp_[a-zA-Z0-9]{30,256}|gho_[a-zA-Z0-9]{30,256})\b"
    ),
    # Explicit secret assignments (e.g. api_key = "...", secret_token: ...)
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{14,256})['\"]?"
    ),
    PASSWORD_REGEX,
]

CREDIT_CARD_CANDIDATE_REGEX = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
# Backward-compatibility alias
CREDIT_CARD_REGEX = CREDIT_CARD_CANDIDATE_REGEX

IBAN_CANDIDATE_REGEX = re.compile(
    r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,4})?\b|\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b"
)

SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Negative lookbehind / prefix indicator words for national-format phone numbers
PHONE_INDICATOR_REGEX = re.compile(
    r"(?i)(?:\b(?:invoice|order|ticket|ref|id|no|tracking)\b|#)"
)
# Backward-compatibility alias for phone regex tests
PHONE_REGEX = re.compile(
    r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|"
    r"\+\d{1,3}[-.\s]\d{1,4}[-.\s]\d{3,4}[-.\s]\d{3,4}\b"
)

# Standard IPv6 candidate addresses
IPV6_REGEX = re.compile(
    r"(?:::)?\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){1,7}(?:::)?\b|::[0-9a-fA-F]{1,4}\b|::1\b"
)

# Standard IPv4 addresses (excluding non-routable versions like software releases 3.11.2)
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
# Backward-compatibility alias
IP_REGEX = IPV4_REGEX

# Prefix words for software version / build / release tags that must stay unmasked
VERSION_PREFIX_REGEX = re.compile(
    r"(?i)(?:\b(?:version|build|release|ver)\b|v)\s*[:=]?\s*$"
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

# Default technical context words for disambiguating ambiguous tools (A10)
DEFAULT_TECH_CONTEXT_WORDS: Set[str] = {
    "pipeline",
    "job",
    "jobs",
    "build",
    "builds",
    "cluster",
    "broker",
    "brokers",
    "topic",
    "topics",
    "server",
    "node",
    "nodes",
    "version",
    "release",
    "error",
    "app",
    "chart",
    "deployment",
    "container",
    "plugin",
    "agent",
    "queue",
    "consumer",
    "producer",
    "instance",
}

# Regex to detect greetings, salutations, sign-offs, and honorific prefixes (A10)
GREETING_SIGNOFF_REGEX = re.compile(
    r"(?i)(?:"
    r"\b(?:thanks|thank\s+you|many\s+thanks|regards|best\s+regards|warm\s+regards|kind\s+regards|best|sincerely|cheers|yours(?:\s+truly|\s+sincerely|\s+faithfully)?)\b"
    r"|"
    r"\b(?:hi|hello|hey|dear|greetings)\b(?:\s+(?:mr|mrs|ms|dr|prof)\.?)?"
    r"|"
    r"\b(?:mr|mrs|ms|dr|prof)\.?"
    r")\s*[,:\-\s]*$"
)

# Cached tech-terms sets loaded from config
_TECH_TERMS_CACHE: Optional[Set[str]] = None
_UNAMBIGUOUS_CACHE: Optional[Set[str]] = None
_AMBIGUOUS_CACHE: Optional[Set[str]] = None
_TECH_CONTEXT_WORDS_CACHE: Optional[Set[str]] = None


def load_tech_terms_tiers(
    filepath: Optional[str] = None,
) -> Tuple[Set[str], Set[str]]:
    """Loads and caches technical terms in two tiers: (unambiguous, ambiguous).

    [unambiguous]: Tools/libraries that are never used as human names (e.g. Postgres, Kubernetes, Docker).
    [ambiguous]: Names like Jenkins, Kafka, Helm, Apollo, Flask, Django that can be either tools or persons.

    Args:
        filepath: Optional path to tech terms file. If None, checks config.yaml.

    Returns:
        Tuple of (unambiguous_terms_set, ambiguous_terms_set), all lowercased.
    """
    global _UNAMBIGUOUS_CACHE, _AMBIGUOUS_CACHE, _TECH_TERMS_CACHE
    if _UNAMBIGUOUS_CACHE is not None and _AMBIGUOUS_CACHE is not None and filepath is None:
        return _UNAMBIGUOUS_CACHE, _AMBIGUOUS_CACHE

    unambiguous: Set[str] = set(NON_PERSON_ENTITIES)
    ambiguous: Set[str] = set()

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
            repo_root = Path(__file__).resolve().parent.parent
            resolved = repo_root / target_path
            if resolved.exists():
                candidate = resolved

        if candidate.exists():
            current_section = "unambiguous"
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("[") and line.endswith("]"):
                            sec = line[1:-1].strip().lower()
                            if sec in ("unambiguous", "ambiguous"):
                                current_section = sec
                            continue
                        if current_section == "ambiguous":
                            ambiguous.add(line.lower())
                        else:
                            unambiguous.add(line.lower())
            except Exception:
                pass

    if filepath is None:
        _UNAMBIGUOUS_CACHE = unambiguous
        _AMBIGUOUS_CACHE = ambiguous
        _TECH_TERMS_CACHE = unambiguous | ambiguous

    return unambiguous, ambiguous


def load_tech_terms_whitelist(filepath: Optional[str] = None) -> Set[str]:
    """Loads and caches technical terms whitelist from external file.

    Maintains backward compatibility by returning the union of both tiers.
    """
    global _TECH_TERMS_CACHE
    if _TECH_TERMS_CACHE is not None and filepath is None:
        return _TECH_TERMS_CACHE
    unambiguous, ambiguous = load_tech_terms_tiers(filepath=filepath)
    combined = unambiguous | ambiguous
    if filepath is None:
        _TECH_TERMS_CACHE = combined
    return combined


def reset_tech_terms_cache() -> None:
    """Resets cached tech terms whitelist (used for testing or dynamic reloads)."""
    global _TECH_TERMS_CACHE, _UNAMBIGUOUS_CACHE, _AMBIGUOUS_CACHE, _TECH_CONTEXT_WORDS_CACHE
    _TECH_TERMS_CACHE = None
    _UNAMBIGUOUS_CACHE = None
    _AMBIGUOUS_CACHE = None
    _TECH_CONTEXT_WORDS_CACHE = None


def load_tech_context_words(config: Optional[Dict[str, Any]] = None) -> Set[str]:
    """Loads technical context words from config or defaults."""
    global _TECH_CONTEXT_WORDS_CACHE
    if _TECH_CONTEXT_WORDS_CACHE is not None and config is None:
        return _TECH_CONTEXT_WORDS_CACHE

    words = set(DEFAULT_TECH_CONTEXT_WORDS)
    cfg = config
    if cfg is None:
        try:
            cfg = load_config()
        except Exception:
            cfg = None

    if cfg:
        custom_words = cfg.get("privacy", {}).get("tech_context_words")
        if custom_words and isinstance(custom_words, (list, set, tuple)):
            words = {str(w).strip().lower() for w in custom_words if w}

    if config is None:
        _TECH_CONTEXT_WORDS_CACHE = words
    return words


def is_greeting_or_signoff(text: str, start_char: int) -> bool:
    """Checks if the span starting at start_char is directly preceded by a greeting or sign-off."""
    prefix = text[:start_char]
    return bool(GREETING_SIGNOFF_REGEX.search(prefix))


def has_adjacent_tech_context(
    text: str,
    start_char: int,
    end_char: int,
    context_words: Set[str],
) -> bool:
    """Determines if a technical context word is directly adjacent (within 2 words before or after in the same sentence).

    Args:
        text: Full working text string.
        start_char: Start index of the ambiguous entity in text.
        end_char: End index of the ambiguous entity in text.
        context_words: Set of lowercase technical context words.

    Returns:
        True if an adjacent technical context word is found within 2 words in the same sentence.
    """
    before_text = text[:start_char]
    sentence_start = 0
    boundary_matches_before = list(re.finditer(r"[\r\n]+|[.!?](?:\s+|$)", before_text))
    if boundary_matches_before:
        sentence_start = boundary_matches_before[-1].end()

    after_text = text[end_char:]
    sentence_end = len(text)
    boundary_match_after = re.search(r"[\r\n]+|[.!?](?:\s+|$)", after_text)
    if boundary_match_after:
        sentence_end = end_char + boundary_match_after.start()

    same_sentence_before = text[sentence_start:start_char]
    same_sentence_after = text[end_char:sentence_end]

    words_before = re.findall(r"\b[A-Za-z0-9_-]+\b", same_sentence_before)
    words_after = re.findall(r"\b[A-Za-z0-9_-]+\b", same_sentence_after)

    adjacent_before = [w.lower() for w in words_before[-2:]]
    adjacent_after = [w.lower() for w in words_after[:2]]

    adjacent_words = set(adjacent_before + adjacent_after)
    return bool(adjacent_words & context_words)


def mask_pii(
    text: str,
    spacy_model_name: Optional[str] = None,
    token_map: Optional[Dict[str, str]] = None,
    default_phone_region: Optional[str] = None,
    nlp_override: Optional[Any] = None,
) -> Tuple[str, Dict[str, str]]:
    """Sanitizes text by replacing PII with anonymized placeholder tokens.

    Args:
        text: Input text string to sanitize.
        spacy_model_name: Optional spaCy model override.
        token_map: Optional existing token map to reuse tokens and counters across texts.
        default_phone_region: Optional default region code for parsing national phone numbers.

    Returns:
        Tuple of (masked_text, token_map) where token_map maps [TOKEN_N_nonce] -> original value.
    """
    global _SPACY_FAILED

    if not text:
        return "", {} if token_map is None else token_map

    if token_map is None:
        token_map = {}
        value_to_token: Dict[str, str] = {}
        entity_counters: Dict[str, int] = {
            "API_KEY": 0,
            "CREDIT_CARD": 0,
            "IBAN": 0,
            "SSN": 0,
            "EMAIL": 0,
            "PHONE": 0,
            "IP_ADDRESS": 0,
            "PERSON": 0,
        }
    else:
        token_map = dict(token_map)
        value_to_token = {v: k for k, v in token_map.items() if not k.startswith("__")}
        entity_counters = {
            "API_KEY": 0,
            "CREDIT_CARD": 0,
            "IBAN": 0,
            "SSN": 0,
            "EMAIL": 0,
            "PHONE": 0,
            "IP_ADDRESS": 0,
            "PERSON": 0,
        }
        for tok in token_map.keys():
            if tok.startswith("__"):
                continue
            m = re.match(r"^\[([A-Z_]+)_(\d+)(?:_[0-9a-fA-F]+)?\]$", tok)
            if m:
                etype, idx = m.group(1), int(m.group(2))
                if etype in entity_counters:
                    entity_counters[etype] = max(entity_counters[etype], idx)

    # Per-email nonce (4 hex chars)
    nonce = token_map.get("__nonce__")
    if not nonce:
        nonce = secrets.token_hex(2)
        token_map["__nonce__"] = nonce

    if not text:
        return "", token_map

    def get_or_create_token(entity_type: str, original_val: str) -> str:
        if original_val in value_to_token:
            return value_to_token[original_val]
        entity_counters[entity_type] += 1
        token = f"[{entity_type}_{entity_counters[entity_type]}_{nonce}]"
        token_map[token] = original_val
        value_to_token[original_val] = token
        return token

    working = text

    # 1. Regex Pass: API Keys & Secrets (executed BEFORE phone pass)
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

    # 2. Regex Pass: Credit Cards (Luhn validated)
    matches = list(CREDIT_CARD_CANDIDATE_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        if luhn_checksum(val):
            token = get_or_create_token("CREDIT_CARD", val)
            working = working[: match.start()] + token + working[match.end() :]

    # 3. Regex Pass: IBAN (ISO mod-97 validated)
    matches = list(IBAN_CANDIDATE_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        if iban_checksum(val):
            token = get_or_create_token("IBAN", val)
            working = working[: match.start()] + token + working[match.end() :]

    # 4. Regex Pass: SSN / Tax IDs
    matches = list(SSN_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        token = get_or_create_token("SSN", val)
        working = working[: match.start()] + token + working[match.end() :]

    # 5. Regex Pass: Email Addresses
    matches = list(EMAIL_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        token = get_or_create_token("EMAIL", val)
        working = working[: match.start()] + token + working[match.end() :]

    # 6. Library Pass: Phone Numbers (phonenumbers library)
    if default_phone_region is None:
        try:
            cfg = load_config()
            default_phone_region = cfg.get("privacy", {}).get(
                "default_phone_region", "US"
            )
        except Exception:
            default_phone_region = "US"

    phone_spans: List[Tuple[int, int, str]] = []
    for m in phonenumbers.PhoneNumberMatcher(working, default_phone_region):
        start, end = m.start, m.end
        raw = m.raw_string
        if raw.startswith("(") and ")" not in raw:
            start += 1
            raw = raw[1:]
        is_intl = raw.strip().startswith("+")
        num = m.number
        if is_intl:
            if phonenumbers.is_valid_number(num):
                phone_spans.append((start, end, raw))
        else:
            if phonenumbers.is_valid_number(num):
                prefix = working[max(0, start - 18) : start]
                if not PHONE_INDICATOR_REGEX.search(prefix):
                    phone_spans.append((start, end, raw))

    for start, end, val in sorted(phone_spans, key=lambda x: x[0], reverse=True):
        token = get_or_create_token("PHONE", val)
        working = working[:start] + token + working[end:]

    # 7. Regex Pass: IP Addresses (IPv6 + IPv4 with version exclusion)
    # 7a. IPv6
    matches = list(IPV6_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        try:
            ip = ipaddress.ip_address(val)
            if ip.version == 6:
                token = get_or_create_token("IP_ADDRESS", val)
                working = working[: match.start()] + token + working[match.end() :]
        except ValueError:
            pass

    # 7b. IPv4 (excluding preceding software version/build/release tags)
    matches = list(IPV4_REGEX.finditer(working))
    for match in reversed(matches):
        val = match.group(0)
        prefix = working[max(0, match.start() - 15) : match.start()]
        if VERSION_PREFIX_REGEX.search(prefix):
            continue
        token = get_or_create_token("IP_ADDRESS", val)
        working = working[: match.start()] + token + working[match.end() :]

    # 8. spaCy NER Pass: Person Names
    if nlp_override is not None:
        nlp = nlp_override
    else:
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
            unambiguous_terms, ambiguous_terms = load_tech_terms_tiers()
            context_words = load_tech_context_words()
            # Collect PERSON entities that are not part of an existing token
            person_spans: List[Tuple[int, int, str]] = []
            for ent in doc.ents:
                if ent.label_ == "PERSON":
                    ent_text = ent.text.strip()
                    # Skip if already a token like [EMAIL_1] or inside brackets like [EMAIL_1_b9a9]
                    if ent_text.startswith("[") and ent_text.endswith("]"):
                        continue
                    if (
                        ent.start_char > 0
                        and working[ent.start_char - 1] == "["
                        and ent.end_char < len(working)
                        and working[ent.end_char] == "]"
                    ):
                        continue
                    if re.match(r"^[A-Z_]+_\d+(?:_[0-9a-fA-F]+)?$", ent_text):
                        continue
                    if len(ent_text) < 2:
                        continue

                    ent_lower = ent_text.lower()
                    # Tier 1: Unambiguous tools are always kept unmasked (exact whole-entity match)
                    if ent_lower in unambiguous_terms:
                        continue

                    # Tier 2: Ambiguous terms (Jenkins, Kafka, Helm, Apollo, Flask, Django)
                    if ent_lower in ambiguous_terms:
                        # Rule 3: Direct greeting/sign-off must ALWAYS be masked
                        if is_greeting_or_signoff(working, ent.start_char):
                            pass
                        # Rule 2: Keep unmasked ONLY if a technical context word is directly adjacent (<=2 words, same sentence)
                        elif has_adjacent_tech_context(
                            working, ent.start_char, ent.end_char, context_words
                        ):
                            continue

                    # Multi-word entities (Apollo Chen, Grafana Smith) or unrecognized names are masked
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

    # 9. Consistency Pass: Ensure any pre-existing tokens from token_map are replaced
    unambiguous_terms, ambiguous_terms = load_tech_terms_tiers()
    context_words = load_tech_context_words()
    for val, token in sorted(value_to_token.items(), key=lambda x: len(x[0]), reverse=True):
        if len(val) >= 2 and val in working:
            val_lower = val.lower()
            if val_lower in unambiguous_terms:
                continue
            pattern = re.compile(rf"\b{re.escape(val)}\b")
            if val_lower in ambiguous_terms:
                for m in reversed(list(pattern.finditer(working))):
                    start, end = m.start(), m.end()
                    if not is_greeting_or_signoff(working, start) and has_adjacent_tech_context(
                        working, start, end, context_words
                    ):
                        continue
                    working = working[:start] + token + working[end:]
            else:
                working = pattern.sub(token, working)

    return working, token_map


def unmask_text(text: str, token_map: Dict[str, str]) -> str:
    """Restores masked tokens back to their original values.

    Args:
        text: Masked text string.
        token_map: Dictionary mapping [TOKEN_N_nonce] -> original value.

    Returns:
        Original unmasked text string.
    """
    if not text or not token_map:
        return text or ""

    restored = text
    # Sort tokens by length in descending order to prevent sub-token replacement collisions
    for token in sorted(token_map.keys(), key=len, reverse=True):
        if token.startswith("__"):
            continue
        restored = restored.replace(token, token_map[token])

    return restored


def pii_masker_node(
    state: TriageState,
    spacy_model_name: Optional[str] = None,
    client: Optional[Any] = None,
    offline: bool = False,
    config: Optional[Dict[str, Any]] = None,
    nlp_override: Optional[Any] = None,
) -> Dict[str, Any]:
    """LangGraph node execution function for local PII masking.

    Args:
        state: Pipeline state containing 'cleaned_body' or 'email_body' and 'email_subject'.
        spacy_model_name: Optional spaCy model override.
        client: Optional AI client instance.
        offline: Whether pipeline is running in offline mode.
        config: Optional configuration dictionary.
        nlp_override: Optional spaCy model or mock override for testing.

    Returns:
        Dictionary update with 'masked_subject', 'masked_body', and 'token_map'.
    """
    subject = state.get("email_subject") or ""
    body = state.get("cleaned_body")
    if body is None:
        body = state.get("email_body") or state.get("raw_body") or ""

    email_id = state.get("email_id") or "unknown"

    if config is None:
        try:
            config = load_config()
        except Exception:
            config = {}
    default_region = config.get("privacy", {}).get("default_phone_region", "US")

    token_map = dict(state.get("token_map") or {})
    masked_subject, token_map = mask_pii(
        subject,
        spacy_model_name=spacy_model_name,
        token_map=token_map,
        default_phone_region=default_region,
        nlp_override=nlp_override,
    )
    masked_body, token_map = mask_pii(
        body,
        spacy_model_name=spacy_model_name,
        token_map=token_map,
        default_phone_region=default_region,
        nlp_override=nlp_override,
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
