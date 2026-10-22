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
        self.fallback_model = (
            os.environ.get("GROQ_FALLBACK_MODEL")
            or gatekeeper_cfg.get("fallback_model")
            or "openai/gpt-oss-20b"
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
        if (
            not self.api_key
            or self.api_key.startswith("your_")
            or "placeholder" in self.api_key.lower()
        ):
            return None

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
        if (
            not self.groq_api_key
            or self.groq_api_key.startswith("your_")
            or "placeholder" in self.groq_api_key.lower()
        ):
            return None

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


# Convenient alias for architectural consistency
JevAIClient = JevClient

