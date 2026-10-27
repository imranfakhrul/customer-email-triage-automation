"""Classifier client for deep intent, category, and sentiment routing.

Multi-tiered architecture:
1. Primary Layer: TypeSafe System One (Jev) choice-based routing ('gmail_router').
2. Secondary Layer: Groq LLM fallback ('openai/gpt-oss-120b') if Jev is unavailable or errors.
3. Tertiary Layer: Local deterministic heuristic rules fail-closed to HITL review.
"""

import json
import logging
import math
import os
import re
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from prompts import build_classifier_system_prompt
from state import ALLOWED_CATEGORIES, ALLOWED_TEAMS, EmailClassification
from utils.config import get_config, get_env_var
from utils.text_tools import bounded_scan_text

logger = logging.getLogger(__name__)

ALLOWED_PRIORITIES = ["Critical", "High", "Medium", "Low"]
ALLOWED_SENTIMENTS = ["Positive", "Neutral", "Negative"]
ALLOWED_EMOTIONS = ["Calm", "Frustrated", "Angry"]

# Action key mapping from Jev AI choice question to standard category & team
JEV_ACTION_MAP = {
    "github_issue_create": {
        "category": "Bug Report",
        "suggested_team": "Engineering",
        "priority": "Medium",
    },
    "freescout": {
        "category": "General Query",
        "suggested_team": "Support",
        "priority": "Medium",
    },
    "crm": {
        "category": "Demo Request",
        "suggested_team": "Sales",
        "priority": "High",
    },
    "webhook_node": {
        "category": "Billing Issue",
        "suggested_team": "Billing",
        "priority": "Critical",
    },
}

# Prompt injection regex (reusing Phase 1 A3 defense)
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
    r"must\s+(?:circumvent|evade|ignore)\s+all\s+filters|ignore\s+any\s+safety\s+checks|"
    r"pretend\s+you\s+are.{0,200}grandmother|grandma.{0,200}read\s+me.{0,200}system\s+prompt)\b)",
    flags=re.IGNORECASE | re.DOTALL,
)

# ReDoS-safe patterns for local heuristic fallback
BUG_REGEX = re.compile(
    r"\b(?:500\s+error|404\s+error|exception|traceback|stacktrace|crash|crashes|crashing|bug|broken|"
    r"glitch|not\s+working|fails\s+to\s+load|syntax\s+error|segmentation\s+fault|null\s+pointer)\b",
    re.IGNORECASE,
)
FEATURE_REGEX = re.compile(
    r"\b(?:feature\s+request|would\s+love\s+to\s+see|can\s+you\s+add|suggestion|please\s+support|"
    r"support\s+for|feature\s+idea|enhancement)\b",
    re.IGNORECASE,
)
DEMO_REGEX = re.compile(
    r"\b(?:schedule\s+a\s+demo|request\s+a\s+demo|live\s+demo|product\s+walkthrough|"
    r"sales\s+call|hop\s+on\s+a\s+call|upgrade\s+our\s+team|enterprise\s+plan)\b",
    re.IGNORECASE,
)
PRICING_REGEX = re.compile(
    r"\b(?:pricing|how\s+much\s+does\s+it\s+cost|price\s+quote|volume\s+discount|annual\s+discount|"
    r"cost\s+per\s+seat|seat\s+pricing)\b",
    re.IGNORECASE,
)
BILLING_REGEX = re.compile(
    r"\b(?:invoice|invoices|charged\s+twice|double\s+charg(?:ed|ing)|payment\s+failed|credit\s+card\s+declined|"
    r"billing\s+statement|unauthorized\s+charge|payment\s+alert|subscription\s+renewal)\b",
    re.IGNORECASE,
)
REFUND_REGEX = re.compile(
    r"\b(?:refund|money\s+back|reimburse|reimbursement|credit\s+my\s+account)\b",
    re.IGNORECASE,
)
SECURITY_REGEX = re.compile(
    r"\b(?:password\s+reset|reset\s+my\s+password|account\s+locked|locked\s+out|2fa|two-factor|"
    r"mfa|unauthorized\s+access|security\s+vulnerability|security\s+issue|compromised)\b",
    re.IGNORECASE,
)
COMPLAINT_REGEX = re.compile(
    r"\b(?:unacceptable|terrible\s+service|horrible\s+experience|file\s+a\s+complaint|breach\s+of\s+sla|"
    r"extremely\s+disappointed|unprofessional|worst\s+support)\b",
    re.IGNORECASE,
)
EMOTION_ANGRY_REGEX = re.compile(
    r"\b(?:furious|outraged|lawyer|legal\s+action|sue\s+you|scam|fraud|unacceptable)\b",
    re.IGNORECASE,
)
EMOTION_FRUSTRATED_REGEX = re.compile(
    r"\b(?:frustrated|annoyed|ridiculous|waste\s+of\s+time|tired\s+of|again\s+and\s+again|still\s+not\s+working)\b",
    re.IGNORECASE,
)
SENTIMENT_POSITIVE_REGEX = re.compile(
    r"\b(?:thank\s+you|thanks|great|awesome|excellent|love\s+the\s+product|appreciate|wonderful)\b",
    re.IGNORECASE,
)


def normalize_classification(
    raw: Any, config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Normalizes and validates a classification output dictionary to fail closed.

    Enforces strict safety invariants:
    1. Result must be a dictionary.
    2. Category must be in the approved 10-category taxonomy; unknown defaults to 'Other'.
    3. Priority must be in ['Critical', 'High', 'Medium', 'Low']; unknown defaults to 'Medium'.
    4. Sentiment must be in ['Positive', 'Neutral', 'Negative']; unknown defaults to 'Neutral'.
    5. Emotion must be in ['Calm', 'Frustrated', 'Angry']; unknown defaults to 'Calm'.
    6. Suggested team must be in ['Engineering', 'Sales', 'Billing', 'Support', 'Security'].
    7. Confidence is clamped to [0.0, 1.0]; None, NaN, or non-numeric values default to 0.0.
    """
    if not isinstance(raw, dict):
        raw = {}

    # Category normalization
    raw_cat = raw.get("category")
    category = "Other"
    if isinstance(raw_cat, str):
        cleaned_cat = raw_cat.strip()
        for cat in ALLOWED_CATEGORIES:
            if cleaned_cat.lower() == cat.lower():
                category = cat
                break

    # Priority normalization
    raw_prio = raw.get("priority")
    priority = "Medium"
    if isinstance(raw_prio, str):
        cleaned_prio = raw_prio.strip().capitalize()
        if cleaned_prio in ALLOWED_PRIORITIES:
            priority = cleaned_prio

    # Sentiment normalization
    raw_sent = raw.get("sentiment")
    sentiment = "Neutral"
    if isinstance(raw_sent, str):
        cleaned_sent = raw_sent.strip().capitalize()
        if cleaned_sent in ALLOWED_SENTIMENTS:
            sentiment = cleaned_sent

    # Customer emotion normalization
    raw_emotion = raw.get("customer_emotion")
    customer_emotion = "Calm"
    if isinstance(raw_emotion, str):
        cleaned_emotion = raw_emotion.strip().capitalize()
        if cleaned_emotion in ALLOWED_EMOTIONS:
            customer_emotion = cleaned_emotion

    # Suggested team normalization
    raw_team = raw.get("suggested_team")
    suggested_team = "Support"
    if isinstance(raw_team, str):
        cleaned_team = raw_team.strip().capitalize()
        if cleaned_team in ALLOWED_TEAMS:
            suggested_team = cleaned_team

    # Summary normalization
    raw_summary = raw.get("summary")
    summary = str(raw_summary).strip() if raw_summary else "Customer email requiring review"

    # Confidence clamping
    raw_conf = raw.get("confidence")
    try:
        if raw_conf is None or (isinstance(raw_conf, float) and math.isnan(raw_conf)):
            confidence = 0.0
        else:
            confidence = float(raw_conf)
            if math.isnan(confidence) or math.isinf(confidence):
                confidence = 0.0
            else:
                confidence = max(0.0, min(1.0, round(confidence, 2)))
    except (ValueError, TypeError):
        confidence = 0.0

    raw_engine = raw.get("p2_classifier_used")
    if raw_engine in ("jev", "groq", "offline_heuristic", "fail_closed"):
        p2_classifier_used = raw_engine
    else:
        p2_classifier_used = "offline_heuristic"

    return {
        "category": category,
        "priority": priority,
        "sentiment": sentiment,
        "customer_emotion": customer_emotion,
        "summary": summary,
        "suggested_team": suggested_team,
        "confidence": confidence,
        "p2_classifier_used": p2_classifier_used,
    }


class ClassifierClient:
    """Client for semantic classification with Jev AI primary, Groq fallback, and offline heuristics."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config if config is not None else get_config()

        # Classification config
        class_cfg = self.config.get("classification", {})
        self.hitl_threshold = float(class_cfg.get("hitl_threshold", 0.85))
        self.max_subject_chars = int(class_cfg.get("max_subject_chars", 2000))
        self.max_body_chars = int(class_cfg.get("max_body_chars", 10000))

        # Jev AI config
        jev_cfg = class_cfg.get("jev", {})
        self.jev_enabled = bool(jev_cfg.get("enabled", False))
        self.jev_model = jev_cfg.get("model", "jev-1.13.0")
        self.jev_api_url = jev_cfg.get("api_url", "https://api.typesafe.ai/v1/systemone")
        self.router_question_id = jev_cfg.get("router_question_id", "gmail_router")
        self.timeout_seconds = float(jev_cfg.get("timeout_seconds", 5.0))

        gatekeeper_cfg = self.config.get("gatekeeper", {})
        api_key_env = gatekeeper_cfg.get("api_key_env", "JEV_API_KEY")
        self.jev_api_key = get_env_var(api_key_env)

        # Groq config
        llm_cfg = self.config.get("llm", {})
        self.groq_model = llm_cfg.get("model", "openai/gpt-oss-120b")
        self.groq_temperature = float(llm_cfg.get("temperature", 0.1))
        groq_key_env = llm_cfg.get("groq_api_key_env", "GROQ_API_KEY")
        self.groq_api_key = get_env_var(groq_key_env)
        self.groq_api_url = "https://api.groq.com/openai/v1/chat/completions"

    @staticmethod
    def _is_valid_key(key: Optional[str]) -> bool:
        if not key or not isinstance(key, str):
            return False
        k = key.strip().lower()
        if not k or k.startswith("your_") or "placeholder" in k:
            return False
        return True

    @staticmethod
    def _is_allowed_url(url: Optional[str], allowed_hosts: List[str]) -> bool:
        """Validates that destination URL strictly points to allowed hosts (A13 security pattern)."""
        if not url or not isinstance(url, str):
            return False
        try:
            parsed = urlparse(url.strip())
            if not parsed.scheme or not parsed.hostname:
                return False
            hostname = parsed.hostname.lower()
            scheme = parsed.scheme.lower()
            if hostname in ("localhost", "127.0.0.1"):
                return scheme in ("http", "https")
            if hostname in allowed_hosts:
                return scheme == "https"
            return False
        except Exception:
            return False

    def classify(self, subject: str, body: str) -> Dict[str, Any]:
        """Classifies incoming email using Jev AI with Groq and heuristic fallbacks.

        Args:
            subject: Precision-masked subject line.
            body: Cleaned, PII-masked email body.

        Returns:
            Normalized dictionary satisfying EmailClassification schema.
        """
        # Step 0: Input Clamping (A6 bounded scans)
        clamped_subject = subject[: self.max_subject_chars] if subject else ""
        clamped_body = body[: self.max_body_chars] if body else ""

        # Step 1: Prompt Injection Pre-Filter (A3 Defense)
        eval_text = f"{clamped_subject}\n{clamped_body}"
        scan_text = bounded_scan_text(eval_text, config=self.config)
        if PROMPT_INJECTION_REGEX.search(scan_text):
            logger.warning("[Classifier] Prompt injection detected by pre-filter regex -> Routing to Security HITL")
            result = {
                "category": "Security/Account",
                "priority": "High",
                "sentiment": "Neutral",
                "customer_emotion": "Calm",
                "summary": "Adversarial prompt injection pattern detected in message",
                "suggested_team": "Security",
                "confidence": 1.0,
                "p2_classifier_used": "offline_heuristic",
            }
            return normalize_classification(result, self.config)

        # Step 1.5: spaCy Model Availability Safeguard (A8 invariant)
        from nodes.pii_masker import is_spacy_available
        if (self._is_valid_key(self.jev_api_key) or self._is_valid_key(self.groq_api_key)) and not is_spacy_available():
            logger.warning(
                "[Classifier] spaCy unavailable while external AI enabled; "
                "refusing external AI dispatch and failing closed."
            )
            result = {
                "category": "Other",
                "priority": "High",
                "sentiment": "Neutral",
                "customer_emotion": "Calm",
                "summary": "spaCy unavailable safeguard triggered",
                "suggested_team": "Support",
                "confidence": 0.0,
                "p2_classifier_used": "fail_closed",
            }
            return normalize_classification(result, self.config)

        # Step 2: Tier 1 - TypeSafe Jev AI Choice Router (if enabled)
        result = None
        if self.jev_enabled and self._is_valid_key(self.jev_api_key):
            try:
                result = self._call_jev_api(clamped_subject, clamped_body)
            except Exception as e:
                logger.warning(
                    f"[Classifier] Jev AI classification failed: {type(e).__name__}. Falling back to Groq."
                )
                result = None

        # Step 3: Tier 2 - Groq LLM Fallback
        if result is None and self._is_valid_key(self.groq_api_key):
            try:
                result = self._call_groq_api(clamped_subject, clamped_body)
            except Exception as e:
                logger.warning(
                    f"[Classifier] Groq LLM fallback failed: {type(e).__name__}. Falling back to heuristics."
                )
                result = None

        # Step 4: Tier 3 - Local Heuristic Fallback
        if result is None:
            result = self._heuristic_fallback(clamped_subject, clamped_body)

        norm_result = normalize_classification(result, self.config)
        logger.info(
            f"[Classifier] Evaluated by engine='{norm_result['p2_classifier_used']}' -> "
            f"category='{norm_result['category']}', priority='{norm_result['priority']}', "
            f"confidence={norm_result['confidence']:.2f}"
        )
        return norm_result

    def _call_jev_api(self, subject: str, body: str) -> Optional[Dict[str, Any]]:
        """Invokes TypeSafe Jev AI choice question router."""
        if not self._is_allowed_url(self.jev_api_url, ["api.typesafe.ai"]):
            logger.warning("[Classifier] Disallowed Jev API URL.")
            return None

        headers = {
            "Authorization": f"Bearer {self.jev_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "CustomerEmailTriage/2.0",
        }

        state_text = f"Subject: {subject}\nBody: {body}"
        payload = {
            "model": self.jev_model,
            "state": state_text,
            "questions": {
                self.router_question_id: {
                    "type": "choice",
                    "instructions": "Which department action should handle this customer email?",
                    "criteria": {
                        "github_issue_create": "Technical bugs, code defects, crashes, or 500 errors requiring engineering attention",
                        "freescout": "Standard customer support questions, helpdesk queries, or general assistance",
                        "crm": "Sales leads, demo requests, enterprise plan upgrades, or contract inquiries",
                        "webhook_node": "Automated system alerts, payment webhook triggers, or urgent billing disputes",
                    },
                }
            },
        }

        response = requests.post(
            self.jev_api_url,
            json=payload,
            headers=headers,
            timeout=self.timeout_seconds,
            allow_redirects=False,
        )

        if response.status_code != 200:
            logger.warning(f"[Classifier] Jev API returned HTTP {response.status_code}.")
            return None

        try:
            data = response.json()
        except Exception as e:
            logger.warning(f"[Classifier] Jev JSON decode failed: {type(e).__name__}.")
            return None

        if not isinstance(data, dict):
            logger.warning("[Classifier] Jev response is not a mapping.")
            return None

        answers = data.get("answers")
        if not isinstance(answers, dict):
            logger.warning("[Classifier] Jev response missing 'answers' mapping.")
            return None

        router_data = answers.get(self.router_question_id)
        if not isinstance(router_data, dict):
            logger.warning("[Classifier] Jev response missing router question answer.")
            return None

        winning_key = router_data.get("choice") or router_data.get("winning_key")
        if not winning_key or winning_key not in JEV_ACTION_MAP:
            logger.warning("[Classifier] Unrecognized or missing winning key in Jev choice answer.")
            return None

        raw_conf = router_data.get("confidence")
        if raw_conf is None:
            confidence = 0.0
        else:
            try:
                confidence = float(raw_conf)
                if math.isnan(confidence) or math.isinf(confidence):
                    confidence = 0.0
                else:
                    confidence = max(0.0, min(1.0, round(confidence, 2)))
            except (ValueError, TypeError):
                confidence = 0.0

        mapped = JEV_ACTION_MAP[winning_key]

        # Extract sentiment and emotion using fast text heuristics
        sentiment = "Neutral"
        if SENTIMENT_POSITIVE_REGEX.search(body) or SENTIMENT_POSITIVE_REGEX.search(subject):
            sentiment = "Positive"
        elif EMOTION_ANGRY_REGEX.search(body) or EMOTION_FRUSTRATED_REGEX.search(body):
            sentiment = "Negative"

        customer_emotion = "Calm"
        if EMOTION_ANGRY_REGEX.search(body) or EMOTION_ANGRY_REGEX.search(subject):
            customer_emotion = "Angry"
        elif EMOTION_FRUSTRATED_REGEX.search(body) or EMOTION_FRUSTRATED_REGEX.search(subject):
            customer_emotion = "Frustrated"

        summary = subject if subject else (body[:100] + "...")

        return {
            "category": mapped["category"],
            "priority": mapped["priority"],
            "sentiment": sentiment,
            "customer_emotion": customer_emotion,
            "summary": summary,
            "suggested_team": mapped["suggested_team"],
            "confidence": confidence,
            "p2_classifier_used": "jev",
        }

    def _call_groq_api(self, subject: str, body: str) -> Optional[Dict[str, Any]]:
        """Invokes Groq LLM fallback using JSON mode and dynamic boundary tags."""
        if not self._is_allowed_url(self.groq_api_url, ["api.groq.com"]):
            logger.warning("[Classifier] Disallowed Groq API URL.")
            return None

        boundary = f"p2-classify-{secrets.token_hex(4)}"
        system_prompt = build_classifier_system_prompt(marker_tag=boundary)
        user_message = f"<{boundary}>\nSubject: {subject}\n\nBody:\n{body}\n</{boundary}>"

        headers = {
            "Authorization": f"Bearer {self.groq_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "CustomerEmailTriage/2.0",
        }

        payload = {
            "model": self.groq_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "temperature": self.groq_temperature,
            "response_format": {"type": "json_object"},
        }

        response = requests.post(
            self.groq_api_url,
            json=payload,
            headers=headers,
            timeout=self.timeout_seconds,
            allow_redirects=False,
        )

        if response.status_code != 200:
            logger.warning(f"[Classifier] Groq API returned HTTP {response.status_code}.")
            return None

        try:
            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                parsed["p2_classifier_used"] = "groq"
                return parsed
            logger.warning("[Classifier] Groq returned non-mapping JSON content.")
            return None
        except Exception as e:
            logger.warning(f"[Classifier] Groq JSON parsing failed: {type(e).__name__}.")
            return None

    def _heuristic_fallback(self, subject: str, body: str) -> Dict[str, Any]:
        """Local rule-based heuristic classifier failing closed to HITL review."""
        full_text = f"{subject}\n{body}"

        category = "Other"
        suggested_team = "Support"
        priority = "Medium"

        if BUG_REGEX.search(full_text):
            category = "Bug Report"
            suggested_team = "Engineering"
            priority = "High" if "500" in full_text or "crash" in full_text.lower() else "Medium"
        elif REFUND_REGEX.search(full_text):
            category = "Refund Request"
            suggested_team = "Billing"
            priority = "High"
        elif BILLING_REGEX.search(full_text):
            category = "Billing Issue"
            suggested_team = "Billing"
            priority = "Critical" if "twice" in full_text.lower() or "unauthorized" in full_text.lower() else "High"
        elif DEMO_REGEX.search(full_text):
            category = "Demo Request"
            suggested_team = "Sales"
            priority = "High"
        elif PRICING_REGEX.search(full_text):
            category = "Pricing Inquiry"
            suggested_team = "Sales"
            priority = "Medium"
        elif SECURITY_REGEX.search(full_text):
            category = "Security/Account"
            suggested_team = "Security"
            priority = "High"
        elif COMPLAINT_REGEX.search(full_text):
            category = "Complaint"
            suggested_team = "Support"
            priority = "High"
        elif FEATURE_REGEX.search(full_text):
            category = "Feature Request"
            suggested_team = "Engineering"
            priority = "Low"
        elif "?" in full_text or "how" in full_text.lower():
            category = "General Query"
            suggested_team = "Support"
            priority = "Medium"

        sentiment = "Neutral"
        if SENTIMENT_POSITIVE_REGEX.search(full_text):
            sentiment = "Positive"
        elif EMOTION_ANGRY_REGEX.search(full_text) or EMOTION_FRUSTRATED_REGEX.search(full_text):
            sentiment = "Negative"

        customer_emotion = "Calm"
        if EMOTION_ANGRY_REGEX.search(full_text):
            customer_emotion = "Angry"
        elif EMOTION_FRUSTRATED_REGEX.search(full_text):
            customer_emotion = "Frustrated"

        # Bounded confidence: 0.55 - 0.60 ensures it strictly fails closed to HITL (< 0.85)
        confidence = 0.60 if category != "Other" else 0.50
        summary = subject if subject else (body[:100] + "...")

        return {
            "category": category,
            "priority": priority,
            "sentiment": sentiment,
            "customer_emotion": customer_emotion,
            "summary": summary,
            "suggested_team": suggested_team,
            "confidence": confidence,
            "p2_classifier_used": "offline_heuristic",
        }
