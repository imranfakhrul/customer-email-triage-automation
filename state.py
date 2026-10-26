from typing import Dict, List, Literal, Optional, TypedDict
from pydantic import BaseModel, Field


# 1. Pydantic Model for Structured LLM Output (Email Classification & Priority)
class EmailClassification(BaseModel):
    category: Literal[
        "Bug Report",
        "Demo Request",
        "Pricing Inquiry",
        "Billing Issue",
        "Refund Request",
        "General Query",
    ] = Field(description="The primary category of the customer email.")
    priority: Literal["Critical", "High", "Medium", "Low"] = Field(
        description="The priority level based on customer tone and urgency."
    )
    sentiment: Literal["Positive", "Neutral", "Negative", "Frustrated"] = Field(
        description="The emotional tone of the customer email."
    )
    summary: str = Field(
        description="A brief 1-2 sentence summary of the customer issue."
    )
    suggested_team: Literal[
        "Engineering",
        "Sales",
        "Billing",
        "Support",
    ] = Field(
        description="The internal team to route this email to (e.g., Engineering, Sales, Billing, Support)."
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0 (used for HITL fallback when < 0.70).",
    )


# 2. Pydantic Model for Security & Guardrail Assessment
class SecurityAssessment(BaseModel):
    is_threat: bool = Field(
        default=False,
        description="Whether a prompt injection, jailbreak, or malicious payload was detected.",
    )
    threat_type: Optional[str] = Field(
        default=None,
        description="Type of threat detected (e.g., 'prompt_injection', 'jailbreak', 'system_override').",
    )
    threat_details: Optional[str] = Field(
        default=None,
        description="Details or matched patterns regarding the detected threat.",
    )


# 3. LangGraph State Definition for passing data across nodes
class TriageState(TypedDict):
    # Ingestion & Threading identifiers
    email_id: str
    message_id: str
    thread_id: str
    sender_email: str
    sender_domain: str
    email_subject: str
    email_body: str
    raw_body: str
    has_attachments: bool
    is_active_thread: Optional[bool]

    # Local Privacy & Masking (Nodes 02, 03 & 10)
    cleaned_body: Optional[str]
    masked_body: Optional[str]
    masked_subject: Optional[str]
    token_map: Dict[str, str]
    spacy_failed: Optional[bool]

    # Sensitive-Skip Guardrail (Node 04)
    is_sensitive: bool
    sensitive_reason: Optional[str]

    # Gatekeeper & Security (Nodes 05 & 06)
    is_spam: Optional[bool]
    gatekeeper_decision: Optional[str]  # 'legitimate', 'spam', 'manual_review'
    gatekeeper_confidence: Optional[float]
    is_threat: Optional[bool]
    threat_details: Optional[str]
    classifier_used: Optional[str]  # 'jev', 'groq', or 'regex'

    # Enrichment & Main Triage (Nodes 07, 08 & 09)
    customer_tier: Optional[str]  # 'Enterprise', 'Free', etc.
    sla_target: Optional[str]
    classification: Optional[EmailClassification]
    p2_classifier_used: Optional[str]  # 'groq' or 'offline_heuristic'

    # Labeling & Dispatch (Nodes 11 & 12)
    labels_to_apply: List[str]
    is_starred: bool
    dispatch_target: Optional[str]  # 'github', 'freescout', 'crm', 'webhook'
    dispatch_status: Optional[str]  # 'processing', 'done', 'failed'
    retry_count: int
    error_message: Optional[str]
    routing_status: Optional[str]
