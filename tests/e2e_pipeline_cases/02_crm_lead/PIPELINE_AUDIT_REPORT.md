# 📑 End-to-End Pipeline Trace Report: HubSpot CRM Enterprise Sales Lead (350-Seat Demo)

**Case ID:** `02_crm_lead`  
**Email ID:** `case_02_crm_lead`  
**Sender:** `marcus.vance@fintechglobal.com`  
**Subject:** `Enterprise Demo Request for 350-Seat Security Automation`  

---

## 🧭 Executive Summary
* **Routing Decision:** `gatekeeper_approved`
* **Gatekeeper Decision:** `legitimate` (Confidence: `0.95`, Engine: `groq`)
* **Semantic Category:** `Demo Request` (Priority: `High`, Suggested Team: `Sales`)
* **HITL Review Status:** `auto_approved` (Reason: `Auto-approved`)
* **Phase 2 Status:** `simulated`
* **Downstream Dispatches:** `1 action(s) scheduled`

```mermaid
flowchart LR
    A["Raw Inbound Email"] --> B["Node 01: Ingestion & Idempotency"]
    B --> C["Node 02: Signature Stripper"]
    C --> D["Node 03: spaCy NER PII Masker"]
    D --> E["Node 04: Sensitive Keyword Check"]
    E --> F["Node 05: Gatekeeper (Groq/Regex)"]
    F --> G["Node 06: Classifier (Groq LLM)"]
    G --> H["Node 07: HITL Review Queue"]
    H --> I["Node 08: Multi-Adapter Dispatcher"]
    I --> J["Outbox Ledger / Live Destination"]
```

---

## 🔍 Stage-by-Stage Verification Breakdown

### 1. Ingestion & Thread Context (Node 01)
* **Message ID / Email ID:** `case_02_crm_lead`
* **Sender Domain Isolated:** `fintechglobal.com`
* **Active Thread Flag:** `False`
* **Database Ledger:** Atomic registration performed with idempotent check-and-claim.

### 2. Signature & Quoted Reply Stripper (Node 02)
* **RFC 3676 / Mobile Cut:** Removed disclaimers, sign-offs, and quote headers.
* **Preserved Core Content:** Kept technical context, stack traces, and customer queries intact without truncation.

### 3. On-Premise PII Redaction & Token Mapping (Node 03)
* **Redacted Entity Breakdown:**
```json
{
  "PERSON": 1
}
```
* **Masked Preview:**
> Hi Sales Team,

My name is Marcus Vance, VP of Technology at FinTech Global.
We are currently evaluating platforms for automated customer inquiry triage across our 350-seat compliance and risk operations.
We would like to schedule a private product d...
* **Zero Leakage Invariant:** Customer names, phone numbers, and raw identifiers were redacted locally on CPU. Zero raw PII was sent to external LLMs.

### 4. Sensitive-Skip Guardrails (Node 04)
* **Is Sensitive:** `False`
* **Sensitive Reason:** `None (Clean)`

### 5. Gatekeeper Spam & Threat Inspection (Node 05)
* **Decision:** `legitimate`
* **Confidence:** `0.95`
* **Engine Used:** `groq`
* **Threat Flag:** `False` (Details: `None`)
* **Spam Flag:** `False`

### 6. Deep Semantic Classification (Node 06)
* **Category:** `Demo Request`
* **Priority:** `High`
* **Sentiment:** `Positive`
* **Customer Emotion:** `Calm`
* **Suggested Team:** `Sales`
* **Confidence Score:** `0.98`
* **Executive Summary:** *VP requests a private product demo and discusses enterprise pricing and compliance terms.*

### 7. Human-in-the-Loop Gating (Node 07)
* **HITL Status:** `auto_approved`
* **Gating Reason:** `Confidence passed threshold; safe category and calm emotion.`
* **Reviewer Action Required:** None — Automatically passed

### 8. Multi-Destination Dispatcher & Outbox Ledger (Node 08)
* **Outbox Ledger Execution:**
```json
[
  {
    "destination": "crm",
    "action_type": "create_lead",
    "mode": "dry_run",
    "ledger_state": "simulated",
    "reason": null,
    "attempts": 0,
    "remote_id": null
  }
]
```
* **Universal Selective Unmasking:** Active (Restores customer contact email for authorized helpdesk/CRM)

---

## 🚀 How to Reproduce This Case Manually

Run the pipeline directly from the repository root:

```bash
# 1. Offline Deterministic Verification
./venv/bin/python main.py --input tests/e2e_pipeline_cases/02_crm_lead/email.json --phase2 --offline

# 2. Live Groq Verification (requires GROQ_API_KEY in .env)
./venv/bin/python main.py --input tests/e2e_pipeline_cases/02_crm_lead/email.json --phase2 --live
```
