from typing import List, Literal, Optional, TypedDict
from pydantic import BaseModel, Field

# 1. Pydantic Model for Structured LLM Output (Email Classification & Priority)
class EmailClassification(BaseModel):
    category: Literal["Bug Report", "Demo Request", "Pricing Inquiry", "Refund Request", "General Query"] = Field(
        description="The primary category of the customer email."
    )
    priority: Literal["High", "Medium", "Low"] = Field(
        description="The priority level based on customer tone and urgency."
    )
    sentiment: Literal["Positive", "Neutral", "Negative"] = Field(
        description="The emotional tone of the customer email."
    )
    summary: str = Field(description="A brief 1-2 sentence summary of the customer issue.")
    suggested_team: str = Field(description="The internal team to route this email to (e.g., Engineering, Sales, Billing, Support).")


# 2. LangGraph State Definition for passing data across nodes
class TriageState(TypedDict):
    email_id: str
    sender_email: str
    email_subject: str
    email_body: str
    classification: Optional[EmailClassification]
    routing_status: Optional[str]