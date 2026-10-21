# 🎯 Project Roadmap — Ingestion to Jev AI Decision Pipeline

> **Scope:** Inbound Email Ingestion ➔ Privacy Redaction ➔ Sensitive Diversion ➔ **Jev AI Decision Engine**  
> **Last Updated:** October 21, 2026  
> **Overall Progress:** **6 of 9 Milestones Completed** (~66%)

---

## 📊 Milestone Tracking Table

| # | Milestone | Status | Deliverables & Scope |
|:---:|:---|:---:|:---|
| **1** | **Pipeline State & Data Schemas** | ✅ Completed | LangGraph `TriageState`, Pydantic models for triage, confidence scoring, and threat assessment. |
| **2** | **Configuration & Secret Loader** | ✅ Completed | Central `config.yaml`, `.env.example`, and secure loader (`utils/config.py`). Zero hardcoded secrets. |
| **3** | **Containerization Environment** | ✅ Completed | Production `Dockerfile` and `docker-compose.yml` for isolated container execution. |
| **4** | **SQLite Idempotency Engine (Node 01)** | ✅ Completed | Crash-resilient 3-state tracking (`processing`, `done`, `failed`), 10-min stale lock recovery, and active thread continuity bypass. |
| **5** | **Signature & Quote Stripper (Node 02)** | ✅ Completed | Strips RFC reply headers, Outlook/Exchange headers, mobile signatures (`Sent from my iPhone`), and legal disclaimers. |
| **6** | **Local spaCy NER & PII Masker (Node 03)** | ✅ Completed | 100% on-premise PII redactor. Masks names, emails, phone numbers, and credentials with reversible tokens before external AI calls. |
| **7** | **Sensitive-Skip Diversion Rules (Node 04)** | ⏳ Pending | Rule-based security diversion. Immediately quarantines legal threats, regulatory notices, and sensitive customer data to human review. |
| **8** | **Jev AI Decision Gatekeeper (Node 05)** | ⏳ Pending | **Final Decision Engine:** Evaluates inbound emails via Jev AI (with Groq fallback) to decide `legitimate`, `spam`, or `manual_review`. |
| **9** | **Automated Pipeline Verification Suite** | ⏳ Pending | End-to-end integration tests and synthetic benchmark verifying pipeline execution and decision accuracy up to Jev AI. |

---

## 🟢 Completed Works

### 1. Architectural Foundations
* Defined structured `TriageState` representing email context, metadata, token mappings, and routing state across pipeline nodes.
* Enforced security configuration using strict environment variable bindings with zero hardcoded API keys.
* Established standardized Docker runtime environment.

### 2. Node 01: Ingestion & Idempotency Store
* Built persistent SQLite state machine protecting against duplicate message deliveries and worker crashes.
* Implemented automatic stale lock recovery after 10 minutes.
* Enabled thread continuity detection so replies to active tickets bypass redundant gatekeeping.
* Tested with 11 automated unit test cases.

### 3. Node 02: Signature & Quoted Reply Stripper
* Implemented intelligent boundary parser removing email thread history (`On ... wrote:`, `-----Original Message-----`, Outlook divider headers).
* Stripped mobile signatures and legal disclaimers while preserving blockquoted error logs.
* Tested with 14 automated unit test cases.

### 4. Node 03: Local spaCy NER & PII Masker
* Built 100% on-premise PII redaction engine replacing customer names, emails, phone numbers, API keys/Bearer tokens, credit cards, SSNs, and IP addresses with reversible tokens (`[PERSON_1]`, `[EMAIL_1]`, etc.).
* Implemented bidirectional `unmask_text` for authorized downstream internal delivery.
* Tested with 10 dedicated unit test cases.

---

## ⏳ Remaining Works (Path to Jev AI Decision)

### 1. Node 04: Sensitive-Skip Rules
* Add pattern and keyword matcher to intercept high-liability emails (subpoenas, bank routing, chargebacks) and divert them directly to `Review/Sensitive`.

### 2. Node 05: Jev AI Decision Gatekeeper
* Build the primary gatekeeper client integrating Jev AI for spam and threat classification.
* Implement automatic fallback to Groq (`llama-3.1-8b-instant`) for high availability.
* Output conclusive triage decisions: `legitimate`, `spam`, or `manual_review`.

### 3. Verification & Testing
* Build integration tests running the full pipeline from raw email input to final Jev AI decision in Docker.
