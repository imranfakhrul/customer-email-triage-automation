# 📑 End-to-End Pipeline Trace Report: Urgent Billing Alert & HITL Gating (Duplicate Invoice Charge)

**Case ID:** `04_webhook_alert`  
**Email ID:** `case_04_webhook_alert`  
**Sender:** `cfo.billing@nexuslogistics.com`  
**Subject:** `Urgent: Duplicate charge of $4,850 on our corporate invoice`  

---

## 🧭 Executive Summary
* **Routing Decision:** `gatekeeper_approved`
* **Gatekeeper Decision:** `legitimate` (Confidence: `0.95`, Engine: `groq`)
* **Semantic Category:** `Billing Issue` (Priority: `High`, Suggested Team: `Billing`)
* **HITL Review Status:** `pending` (Reason: `Escalated customer emotion (Frustrated) with High priority`)
* **Phase 2 Status:** `hitl_pending`
* **Downstream Dispatches:** `0 action(s) scheduled`

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
* **Message ID / Email ID:** `case_04_webhook_alert`
* **Sender Domain Isolated:** `nexuslogistics.com`
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
> Hello [PERSON_1_944d],

Our finance department discovered that invoice INV-2026-8819 for $4,850.00 was charged twice to our corporate account on October 28th.
Our account shows two identical pending transactions within 4 minutes of each other.
Please...
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
* **Category:** `Billing Issue`
* **Priority:** `High`
* **Sentiment:** `Negative`
* **Customer Emotion:** `Frustrated`
* **Suggested Team:** `Billing`
* **Confidence Score:** `0.99`
* **Executive Summary:** *Customer reports a duplicate $4,850 charge on invoice INV-2026-8819 and requests reversal and corrected receipt.*

### 7. Human-in-the-Loop Gating (Node 07)
* **HITL Status:** `pending`
* **Gating Reason:** `Escalated customer emotion (Frustrated) with High priority`
* **Reviewer Action Required:** Yes — Reviewer intervention via scripts/hitl_cli.py

### 8. Multi-Destination Dispatcher & Outbox Ledger (Node 08)
* **Outbox Ledger Execution:**
```json
[]
```
* **Universal Selective Unmasking:** Disabled (Strict tokenized non-PII payload)

---

## 🚀 How to Reproduce This Case Manually

Run the pipeline directly from the repository root:

```bash
# 1. Offline Deterministic Verification
./venv/bin/python main.py --input tests/e2e_pipeline_cases/04_webhook_alert/email.json --phase2 --offline

# 2. Live Groq Verification (requires GROQ_API_KEY in .env)
./venv/bin/python main.py --input tests/e2e_pipeline_cases/04_webhook_alert/email.json --phase2 --live
```
