"""Client wrapper for TypeSafe System One (Jev) Gatekeeper with Groq Fallback.

This module provides high-availability spam and security classification:
1. Primary Layer: TypeSafe System One (Jev model `jev-1.13.0`) sub-second decision scoring.
2. Secondary Layer: Groq LLM fallback ('openai/gpt-oss-20b') if Jev is disabled or errors.
3. Tertiary Layer: Local deterministic heuristic rules ensuring zero crash policy when offline.
"""

import json
import logging
import math
import os
import re
from typing import Any, Dict, Optional

import requests
from prompts import GATEKEEPER_SYSTEM_PROMPT
from utils.config import get_env_var, load_config

logger = logging.getLogger(__name__)

# Heuristic patterns for local fallback
SPAM_REGEX = re.compile(
    r"\b(?:viagra|cialis|crypto\s+investment|guaranteed\s+returns|lottery\s+winner|"
    r"claim\s+your\s+prize|wire\s+transfer\s+millions|seo\s+backlinks|guest\s+post|do-follow\s+backlinks|"
    r"casino|betting|adult\s+dating|earn\s+[\$]?\d{3,}\s+daily|act\s+now\s+limited\s+time|"
    r"congratulations|geek\s*squad|norton|lifelock|renew(?:ed|al)\s+for\s+[\$]?\d+|"
    r"abandoned\s+[\$]?[\d.,]+M|next\s+of\s+kin|beneficiary\s+to\s+claim|transfer\s+of\s+[\$]?[\d.,]+|prince\s+\w+|"
    r"customs\s+clearance|receipt\.zip|belly\s+fat|slimming\s+drops|lose\s+weight\s+effortlessly|"
    r"docusign|document\s+ready\s+for\s+signature|pump\s+and\s+dump|telegram\s+signals|100x\s+gem|"
    r"account\s+has\s+been\s+restricted|verify\s+your\s+identity.*login|reset\s+your\s+password.*http|"
    r"password\s+reset\s+for\s+your\s+account|password\s+expires|mailbox\s+deactivation|portal-verify|paypa[l1]|"
    r"icloud\s+storage\s+is\s+full|storage\s+limit\s+has\s+been\s+exceeded|mailbox\s+is\s+\d+%\s+full|"
    r"office\s+suites\s+available|luxury\s+class\s+a\s+office|commercial\s+spaces\s+realty|"
    r"redesign\s+your\s+website\s+for|cheap.*developers|cheap\s+meds|without\s+prescription|"
    r"apple\s+gift\s+cards?|purchase.*gift\s+cards?|"
    r"get\s+#1\s+on\s+google|page\s+1.*satisfied\s+clients|"
    r"parcel.*could\s+not\s+be\s+delivered|redelivery\s+fee|reschedule\s+your\s+package|"
    r"earn\s+[\$]?\d+.*working\s+from\s+home|whatsapp\s+number|"
    r"scraped\s+your\s+email|database\s+of.*contacts\s+available\s+for\s+purchase|"
    r"verified\s+decision\s+maker\s+emails|verified\s+database\s+of.*emails)\b",
    flags=re.IGNORECASE | re.DOTALL,
)

PROMPT_INJECTION_REGEX = re.compile(
    r"(?:---\s*END\s+OF\s+USER\s+MESSAGE\s*---|\b(?:ignore\s+all\s+previous\s+instructions|system\s+override|"
    r"disregard\s+all\s+prior|from\s+now\s+on\s+you\s+are\s+DAN|you\s+are\s+DAN|DAN\s+mode|Do\s+Anything\s+Now|"
    r"output\s+the\s+system\s+prompt|print\s+your\s+system\s+prompt|new\s+system\s+directive|"
    r"system\s+instruction\s+override|\[SYSTEM\]:\s*New\s+instruction|"
    r"decode\s+this\s+base64|decode\s+and\s+execute|"
    r"</email>|<system>|you\s+are\s+now\s+the\s+administrator|"
    r"disregard\s+the\s+above|output\s+the\s+contents\s+of\s+your\s+configuration|"
    r"FreeBot|AI\s+with\s+no\s+filters|secret\s+instructions\s+it\s+was\s+given|"
    r"notice\s+to\s+the\s+ai\s+assistant|your\s+policies\s+have\s+been\s+updated|"
    r"must\s+bypass\s+all\s+filters|ignore\s+any\s+safety\s+checks|"
    r"pretend\s+you\s+are.*grandmother|grandma.*read\s+me.*system\s+prompt)\b)",
    flags=re.IGNORECASE | re.DOTALL,
)


def normalize_result(
    raw: Any, config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Normalizes and validates a classifier output dictionary to fail closed.

    Enforces strict safety invariants:
    1. Result must be a dictionary.
    2. Jev probability values (e.g. p_spam, p_threat) outside [0.0, 1.0] invalidate the result -> manual_review.
    3. Decision must be stripped and lowercased; unknown or missing decisions default to 'manual_review'.
    4. Confidence is clamped to [0.0, 1.0]; None, NaN, or non-numeric values default to 0.0.
    5. If is_threat is True, decision is forced to at least 'manual_review'.
    6. If decision is 'legitimate' but confidence < llm.confidence_threshold (default 0.70), diverts to 'manual_review'.

    Args:
        raw: Raw classifier output dictionary from Jev, Groq, or regex heuristics.
        config: Optional configuration dictionary containing llm.confidence_threshold.

    Returns:
        Standardized dictionary containing:
            - decision: 'legitimate', 'spam', or 'manual_review'
            - confidence: float clamped to [0.0, 1.0]
            - is_spam: bool
            - is_threat: bool
            - threat_details: Optional[str]
            - classifier_used: str
    """
    if not isinstance(raw, dict):
        return {
            "decision": "manual_review",
            "confidence": 0.0,
            "is_spam": False,
            "is_threat": False,
            "threat_details": None,
            "classifier_used": "unknown",
        }

    classifier_used = str(raw.get("classifier_used") or "unknown")

    # 1. Jev probabilities validation: probabilities outside 0..1 invalidate the entire result
    for key in ("p_spam", "p_threat"):
        if key in raw and raw[key] is not None:
            try:
                p_val = float(raw[key])
                if not (0.0 <= p_val <= 1.0) or math.isnan(p_val) or math.isinf(p_val):
                    return {
                        "decision": "manual_review",
                        "confidence": 0.0,
                        "is_spam": False,
                        "is_threat": False,
                        "threat_details": f"Invalid {key} probability range: {raw[key]}",
                        "classifier_used": classifier_used if classifier_used != "unknown" else "jev",
                    }
            except (ValueError, TypeError):
                return {
                    "decision": "manual_review",
                    "confidence": 0.0,
                    "is_spam": False,
                    "is_threat": False,
                    "threat_details": f"Invalid {key} probability value: {raw[key]}",
                    "classifier_used": classifier_used if classifier_used != "unknown" else "jev",
                }

    if isinstance(raw.get("answers"), dict):
        answers = raw["answers"]
        for q in ("is_spam", "is_threat"):
            if isinstance(answers.get(q), dict) and "noul" in answers[q]:
                try:
                    p_val = float(answers[q]["noul"])
                    if not (0.0 <= p_val <= 1.0) or math.isnan(p_val) or math.isinf(p_val):
                        return {
                            "decision": "manual_review",
                            "confidence": 0.0,
                            "is_spam": False,
                            "is_threat": False,
                            "threat_details": f"Invalid Jev answers.{q}.noul probability range: {answers[q]['noul']}",
                            "classifier_used": classifier_used if classifier_used != "unknown" else "jev",
                        }
                except (ValueError, TypeError):
                    return {
                        "decision": "manual_review",
                        "confidence": 0.0,
                        "is_spam": False,
                        "is_threat": False,
                        "threat_details": f"Invalid Jev answers.{q}.noul probability value: {answers[q]['noul']}",
                        "classifier_used": classifier_used if classifier_used != "unknown" else "jev",
                    }

    # 2. Decision parsing: lowercase & strip; anything other than legitimate/spam/manual_review -> manual_review
    raw_decision = raw.get("decision")
    if raw_decision is None or not isinstance(raw_decision, str):
        decision = "manual_review"
    else:
        decision = raw_decision.strip().lower()
        if decision not in ("legitimate", "spam", "manual_review"):
            decision = "manual_review"

    # 3. Confidence parsing: clamp to 0.0..1.0; None, NaN or non-number -> 0.0
    raw_confidence = raw.get("confidence")
    if raw_confidence is None or isinstance(raw_confidence, bool):
        confidence = 0.0
    else:
        try:
            c_float = float(raw_confidence)
            if math.isnan(c_float) or math.isinf(c_float):
                confidence = 0.0
            elif c_float < 0.0:
                confidence = 0.0
            elif c_float > 1.0:
                confidence = 1.0
            else:
                confidence = round(c_float, 2)
        except (ValueError, TypeError):
            confidence = 0.0

    # 4. Threat parsing & enforcement: is_threat true -> decision becomes at least manual_review
    raw_threat = raw.get("is_threat")
    if isinstance(raw_threat, str):
        is_threat = raw_threat.strip().lower() in ("true", "1", "yes")
    else:
        is_threat = bool(raw_threat)

    threat_details = raw.get("threat_details")
    if is_threat:
        if decision == "legitimate":
            decision = "manual_review"
        if not threat_details:
            threat_details = "Adversarial threat detected"

    # 5. Threshold enforcement: legitimate with confidence < threshold -> manual_review
    threshold = 0.70
    if isinstance(config, dict):
        llm_cfg = config.get("llm")
        if isinstance(llm_cfg, dict):
            try:
                threshold = float(llm_cfg.get("confidence_threshold", 0.70))
            except (ValueError, TypeError):
                threshold = 0.70
        elif "confidence_threshold" in config:
            try:
                threshold = float(config.get("confidence_threshold", 0.70))
            except (ValueError, TypeError):
                threshold = 0.70

    if decision == "legitimate" and confidence < threshold:
        decision = "manual_review"

    # 6. Spam flag consistency
    is_spam = (decision == "spam")

    return {
        "decision": decision,
        "confidence": confidence,
        "is_spam": is_spam,
        "is_threat": is_threat,
        "threat_details": threat_details,
        "classifier_used": classifier_used,
    }


class JevClientError(Exception):
    """Base exception for Jev client errors."""


class JevClient:
    """Gatekeeper client with TypeSafe System One (Jev), Groq, and heuristic fallback."""

    # Track startup warning across instances so we log exactly once
    _startup_warned: bool = False

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        api_key: Optional[str] = None,
        groq_api_key: Optional[str] = None,
        api_url: Optional[str] = None,
    ):
        """Initializes the Jev AI client with configured fallback parameters.

        Args:
            config: Optional system configuration dictionary.
            api_key: Optional direct override for Jev AI API key.
            groq_api_key: Optional direct override for Groq API key.
            api_url: Optional URL override for Jev AI endpoint.
        """
        if config is None:
            try:
                config = load_config()
            except Exception:
                config = {}

        self.config = config
        gatekeeper_cfg = config.get("gatekeeper", {})
        jev_cfg = gatekeeper_cfg.get("jev", {})

        self.timeout_seconds = float(
            jev_cfg.get("timeout_seconds")
            or gatekeeper_cfg.get("timeout_seconds", 5.0)
        )
        self.max_retries = int(gatekeeper_cfg.get("max_retries", 2))
        self.fallback_model = (
            os.environ.get("GROQ_FALLBACK_MODEL")
            or gatekeeper_cfg.get("fallback_model")
            or "openai/gpt-oss-20b"
        )

        # TypeSafe System One (Jev) specific configuration
        self.jev_model = jev_cfg.get("model", "jev-1.13.0")
        self.api_url = (
            api_url
            or os.environ.get("JEV_API_URL")
            or jev_cfg.get("api_url", "https://api.typesafe.ai/v1/systemone")
        )
        self.hi_threshold = float(jev_cfg.get("hi_threshold", 0.85))
        self.lo_threshold = float(jev_cfg.get("lo_threshold", 0.15))
        self.max_body_chars = int(jev_cfg.get("max_body_chars", 20000))

        # Resolve credentials securely via environment variables
        api_key_env = gatekeeper_cfg.get("api_key_env", "JEV_API_KEY")
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = get_env_var(api_key_env, default="") or os.environ.get(
                "JEV_API_KEY", ""
            )

        groq_key_env = gatekeeper_cfg.get("groq_api_key_env", "GROQ_API_KEY")
        if groq_api_key is not None:
            self.groq_api_key = groq_api_key
        else:
            self.groq_api_key = get_env_var(groq_key_env, default="") or os.environ.get(
                "GROQ_API_KEY", ""
            )

        # Session-wide disable flag (e.g. after HTTP 401 Unauthorized)
        self._jev_disabled: bool = False

        # One-time startup check for Jev key validity
        if not self._is_valid_key(self.api_key):
            if not JevClient._startup_warned:
                logger.warning(
                    "Jev disabled: no valid key found. Pipeline will use Groq/heuristic fallbacks."
                )
                JevClient._startup_warned = True

    @staticmethod
    def _extract_domain(sender: str) -> str:
        """Extracts the domain portion of an email address or sender string.

        Args:
            sender: Email address, sender string, or domain.

        Returns:
            Domain string (e.g., 'example.com'), or empty string if empty.
        """
        if not sender:
            return ""
        s = sender.strip()
        if "@" in s:
            s = s.split("@")[-1].strip().rstrip(">")
        return s.lower()

    @staticmethod
    def _is_valid_key(key: Optional[str]) -> bool:
        """Determines if a key string is non-empty and not a placeholder."""
        if not key or not isinstance(key, str):
            return False
        k = key.strip().lower()
        if not k:
            return False
        if k.startswith("your_") or "placeholder" in k or "your_jev_api_key_here" in k:
            return False
        return True

    def classify(self, subject: str, body: str, sender: str = "") -> Dict[str, Any]:
        """Classifies incoming email using Jev AI with automatic fallbacks.

        Args:
            subject: Email subject line.
            body: Email body (masked or cleaned).
            sender: Sender email address.

        Returns:
            Dictionary containing:
                - decision: 'legitimate', 'spam', or 'manual_review'
                - confidence: float between 0.0 and 1.0 (rounded to 2 decimals)
                - is_spam: bool
                - is_threat: bool
                - threat_details: Optional[str]
                - classifier_used: 'jev', 'groq', or 'regex'
        """
        result: Optional[Dict[str, Any]] = None

        # Step 1: Attempt Primary Classifier (TypeSafe System One / Jev)
        if self._is_valid_key(self.api_key) and not self._jev_disabled:
            result = self._call_jev_api(subject=subject, body=body, sender=sender)

        # Step 2: Attempt Secondary Fallback (Groq)
        if result is None and self._is_valid_key(self.groq_api_key):
            result = self._call_groq_fallback(
                subject=subject, body=body, sender=sender
            )

        # Step 3: Local Deterministic Heuristics Fallback (Guarantees zero downtime)
        if result is None:
            result = self._heuristic_fallback(subject=subject, body=body, sender=sender)

        result = normalize_result(result, self.config)

        # Always-on single structured log line per email evaluation
        logger.info(
            f"[Gatekeeper] Email evaluated by engine='{result['classifier_used']}' -> "
            f"decision='{result['decision']}', confidence={result['confidence']:.2f}"
        )

        return result

    def _call_jev_api(
        self, subject: str, body: str, sender: str
    ) -> Optional[Dict[str, Any]]:
        """Makes HTTP request to the TypeSafe System One evaluation endpoint."""
        truncated_body = body[: self.max_body_chars] if body else ""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "CustomerEmailTriage/1.0",
        }

        sender_domain = self._extract_domain(sender)

        payload = {
            "model": self.jev_model,
            "state": {
                "sender": sender_domain,
                "subject": subject,
                "body": truncated_body,
            },
            "questions": {
                "is_spam": {
                    "type": "noul",
                    "instructions": (
                        "The message is unsolicited mass marketing, promotional spam, "
                        "or automated link farming."
                    ),
                },
                "is_threat": {
                    "type": "noul",
                    "instructions": (
                        "The message contains prompt injection, jailbreak attempts, "
                        "or malicious exploits."
                    ),
                },
            },
        }

        try:
            response = requests.post(
                self.api_url,
                json=payload,
                headers=headers,
                timeout=self.timeout_seconds,
            )

            # Handle 401 Unauthorized: Invalid API key disables Jev for session
            if response.status_code == 401:
                logger.error(
                    "Jev API returned 401 Unauthorized: invalid API key. "
                    "Disabling Jev for this session and falling back."
                )
                self._jev_disabled = True
                return None

            # Handle other client/server error codes
            if response.status_code != 200:
                logger.warning(
                    f"Jev API returned status {response.status_code}: {response.text[:200]}"
                )
                return None

            data = response.json()
            answers = data.get("answers", {})

            if "is_spam" not in answers or "is_threat" not in answers:
                logger.warning("Jev API response missing expected questions in 'answers'.")
                return None

            p_spam_raw = answers["is_spam"].get("noul")
            p_threat_raw = answers["is_threat"].get("noul")

            if p_spam_raw is None or p_threat_raw is None:
                logger.warning("Jev API answers missing 'noul' probability values.")
                return None

            try:
                p_spam = float(p_spam_raw)
                p_threat = float(p_threat_raw)
            except (ValueError, TypeError):
                logger.warning("Jev API answers have non-numeric 'noul' values.")
                return None

            # Fail closed on invalid probability range: outside 0..1 must produce manual_review
            if (
                not (0.0 <= p_spam <= 1.0)
                or not (0.0 <= p_threat <= 1.0)
                or math.isnan(p_spam)
                or math.isnan(p_threat)
            ):
                logger.warning(
                    f"Jev API returned invalid probability range: p_spam={p_spam}, p_threat={p_threat}"
                )
                return {
                    "decision": "manual_review",
                    "confidence": 0.0,
                    "is_spam": False,
                    "is_threat": False,
                    "threat_details": f"Invalid Jev probability values: p_spam={p_spam}, p_threat={p_threat}",
                    "classifier_used": "jev",
                    "p_spam": p_spam,
                    "p_threat": p_threat,
                }

            # Map probabilities to standardized triage schema
            if p_threat >= 0.5:
                decision = "manual_review"
                confidence = p_threat
            elif p_spam >= self.hi_threshold:
                decision = "spam"
                confidence = p_spam
            elif p_spam <= self.lo_threshold:
                decision = "legitimate"
                confidence = 1.0 - p_spam
            else:
                decision = "manual_review"
                confidence = max(p_spam, 1.0 - p_spam)

            is_spam = p_spam >= 0.5
            is_threat = p_threat >= 0.5
            threat_details = (
                "Adversarial threat detected by Jev System One" if is_threat else None
            )

            return {
                "decision": decision,
                "confidence": round(confidence, 2),
                "is_spam": is_spam,
                "is_threat": is_threat,
                "threat_details": threat_details,
                "classifier_used": "jev",
                "p_spam": p_spam,
                "p_threat": p_threat,
            }

        except Exception as exc:
            logger.warning(f"Jev API request failed: {exc}")
            return None

    def _call_groq_fallback(
        self, subject: str, body: str, sender: str
    ) -> Optional[Dict[str, Any]]:
        """Invokes Groq fast model as fallback classifier."""
        try:
            from langchain_groq import ChatGroq
            from langchain_core.messages import HumanMessage, SystemMessage

            llm = ChatGroq(
                model=self.fallback_model,
                groq_api_key=self.groq_api_key,
                temperature=0.0,
                max_retries=1,
                timeout=5.0,
            )

            sender_domain = self._extract_domain(sender)
            prompt_content = f"Sender: {sender_domain}\nSubject: {subject}\n\nBody:\n{body}"
            messages = [
                SystemMessage(content=GATEKEEPER_SYSTEM_PROMPT),
                HumanMessage(content=prompt_content),
            ]

            response = llm.invoke(messages)
            content = str(response.content).strip()

            # Extract JSON block if wrapped in markdown formatting
            if "```json" in content:
                content = content.split("```json")[-1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[-1].split("```")[0].strip()

            data = json.loads(content)
            data["classifier_used"] = "groq"
            return normalize_result(data, self.config)
        except Exception as exc:
            logger.warning(f"Groq fallback classifier failed: {exc}")
            return None

    def _heuristic_fallback(
        self, subject: str, body: str, sender: str
    ) -> Dict[str, Any]:
        """Deterministic rule-based classification when all external APIs are unreachable."""
        text = f"{subject}\n{body}"

        # 1. Prompt Injection / Malicious Payloads
        if PROMPT_INJECTION_REGEX.search(text):
            return {
                "decision": "spam",
                "confidence": 0.99,
                "is_spam": True,
                "is_threat": True,
                "threat_details": "Adversarial prompt injection pattern detected",
                "classifier_used": "regex",
            }

        # 2. Known Spam & Phishing Patterns
        if SPAM_REGEX.search(text):
            return {
                "decision": "spam",
                "confidence": 0.95,
                "is_spam": True,
                "is_threat": False,
                "threat_details": "Unsolicited spam pattern detected",
                "classifier_used": "regex",
            }

        # 3. Legitimate by default for typical inquiries
        return {
            "decision": "legitimate",
            "confidence": 0.85,
            "is_spam": False,
            "is_threat": False,
            "threat_details": None,
            "classifier_used": "regex",
        }


# Convenient alias for architectural consistency
JevAIClient = JevClient
