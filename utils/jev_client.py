"""Client wrapper for Jev AI Spam Gatekeeper with Groq Fallback.

This module provides high-availability spam and security classification:
1. Primary Layer: Jev AI classification API (fast sub-second spam/threat scoring).
2. Secondary Layer: Groq LLM fallback ('llama-3.1-8b-instant') if Jev AI times out or errors.
3. Tertiary Layer: Local deterministic heuristic rules ensuring zero crash policy when offline.
"""

import json
import logging
import os
import re
from typing import Any, Dict, Optional

import requests
from prompts import GATEKEEPER_SYSTEM_PROMPT
from utils.config import get_env_var, load_config

logger = logging.getLogger(__name__)

# Heuristic patterns for local fallback
SPAM_REGEX = re.compile(
    r"(?i)\b(?:viagra|cialis|crypto\s+investment|guaranteed\s+returns|lottery\s+winner|"
    r"claim\s+your\s+prize|wire\s+transfer\s+millions|seo\s+backlinks|casino|betting|"
    r"adult\s+dating|earn\s+\$?\d{3,}\s+daily|act\s+now\s+limited\s+time|congratulations\s+you\s+won)\b"
)

PROMPT_INJECTION_REGEX = re.compile(
    r"(?i)\b(?:ignore\s+all\s+previous\s+instructions|system\s+override|disregard\s+all\s+prior|"
    r"you\s+are\s+now\s+DAN|output\s+the\s+system\s+prompt|new\s+system\s+directive)\b"
)


class JevClient:
    """Gatekeeper client with automatic Groq and heuristic fallback."""

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

        self.timeout_seconds = gatekeeper_cfg.get("timeout_seconds", 3)
        self.max_retries = gatekeeper_cfg.get("max_retries", 2)
        self.fallback_model = gatekeeper_cfg.get(
            "fallback_model", "llama-3.1-8b-instant"
        )

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

        self.api_url = api_url or os.environ.get(
            "JEV_API_URL", "https://api.jev.ai/v1/classify"
        )

    def classify(self, subject: str, body: str, sender: str = "") -> Dict[str, Any]:
        """Classifies incoming email using Jev AI with automatic fallbacks.

        Args:
            subject: Email subject line.
            body: Email body (masked or cleaned).
            sender: Sender email address.

        Returns:
            Dictionary containing:
                - decision: 'legitimate', 'spam', or 'manual_review'
                - is_spam: bool
                - confidence: float between 0.0 and 1.0
                - is_threat: bool
                - threat_details: Optional[str]
                - classifier_used: 'jev_ai', 'groq_fallback', or 'heuristic_fallback'
        """
        # Step 1: Attempt Primary Classifier (Jev AI)
        if self.api_key:
            jev_result = self._call_jev_api(subject=subject, body=body, sender=sender)
            if jev_result is not None:
                return jev_result

        # Step 2: Attempt Secondary Fallback (Groq)
        if self.groq_api_key:
            groq_result = self._call_groq_fallback(
                subject=subject, body=body, sender=sender
            )
            if groq_result is not None:
                return groq_result

        # Step 3: Local Deterministic Heuristics Fallback (Guarantees zero downtime)
        return self._heuristic_fallback(subject=subject, body=body, sender=sender)

    def _call_jev_api(
        self, subject: str, body: str, sender: str
    ) -> Optional[Dict[str, Any]]:
        """Makes HTTP request to the Jev AI classification endpoint."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "CustomerEmailTriage/1.0",
        }
        payload = {
            "subject": subject,
            "body": body,
            "sender": sender,
        }

        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(
                    self.api_url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                if response.status_code == 200:
                    data = response.json()
                    decision = data.get("decision", "legitimate")
                    is_spam = bool(data.get("is_spam", decision == "spam"))
                    confidence = float(data.get("confidence", 0.95))
                    is_threat = bool(data.get("is_threat", False))
                    threat_details = data.get("threat_details")
                    return {
                        "decision": decision,
                        "is_spam": is_spam,
                        "confidence": confidence,
                        "is_threat": is_threat,
                        "threat_details": threat_details,
                        "classifier_used": "jev_ai",
                    }
                else:
                    logger.warning(
                        f"Jev AI returned status {response.status_code} on attempt {attempt}: {response.text[:200]}"
                    )
            except Exception as exc:
                logger.warning(f"Jev AI request failed on attempt {attempt}: {exc}")

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

            prompt_content = f"Sender: {sender}\nSubject: {subject}\n\nBody:\n{body}"
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
            decision = data.get("decision", "legitimate")
            if decision not in ("legitimate", "spam", "manual_review"):
                decision = "legitimate"

            return {
                "decision": decision,
                "is_spam": bool(data.get("is_spam", decision == "spam")),
                "confidence": float(data.get("confidence", 0.85)),
                "is_threat": bool(data.get("is_threat", False)),
                "threat_details": data.get("threat_details"),
                "classifier_used": "groq_fallback",
            }
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
                "is_spam": True,
                "confidence": 0.99,
                "is_threat": True,
                "threat_details": "Adversarial prompt injection pattern detected",
                "classifier_used": "heuristic_fallback",
            }

        # 2. Known Spam & Phishing Patterns
        if SPAM_REGEX.search(text):
            return {
                "decision": "spam",
                "is_spam": True,
                "confidence": 0.95,
                "is_threat": False,
                "threat_details": "Unsolicited spam pattern detected",
                "classifier_used": "heuristic_fallback",
            }

        # 3. Legitimate by default for typical inquiries
        return {
            "decision": "legitimate",
            "is_spam": False,
            "confidence": 0.85,
            "is_threat": False,
            "threat_details": None,
            "classifier_used": "heuristic_fallback",
        }
