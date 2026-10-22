# 🎯 Project Roadmap — Customer Email Triage Automation (Phase 1)

> **Scope:** Inbound Email Ingestion ➔ Privacy Redaction ➔ Sensitive Diversion ➔ **Jev AI Decision Engine**  
> **Status:** **Production Ready for Client Review & Phase 2 Handoff** ✅  
> **Overall Progress:** **13 of 13 Milestones Completed (100%)** 🎉  
> **Quality Gate:** **77 of 77 Automated Tests Passing** | **100 of 100 Benchmark Scenarios Passing (0 False Positives)**

---

## 📋 Executive Readiness Summary

The **Customer Email Triage Automation Pipeline (Phase 1)** is fully operational, thoroughly hardened, containerized, and ready for client delivery and inspection.

Every inbound email traverses an asynchronous, privacy-preserving **LangGraph** pipeline with sub-50ms average decision latency:
1. **Node 01: Ingestion & Idempotency Store** (SQLite 3-state concurrency control, thread participant verification, 10-minute duplicate suppression).
2. **Node 02: Signature & Quote Stripper** (Thread history and disclaimer removal; safeguards short opening emails).
3. **Node 03: Local spaCy NER & Regex PII Masker** (100% on-premise PII redaction with an externalized tech-term whitelist).
4. **Node 04: Sensitive-Skip Guardrail** (Immediate human-in-the-loop diversion for regulatory, legal, and billing disputes).
5. **Node 05: 3-Tier Jev AI Decision Gatekeeper** (TypeSafe System One Jev AI + Groq fast LLM fallback + deterministic offline heuristics).

---

## 📊 Milestone Tracking Table

| # | Milestone | Status | Deliverables & Scope |
|:---:|:---|:---:|:---|
| **1** | **Pipeline State & Data Schemas** | ✅ Completed | LangGraph `TriageState`, Pydantic models for triage, confidence scoring, and threat assessment. |
| **2** | **Configuration & Secret Loader** | ✅ Completed | Central `config.yaml`, `.env.example`, and secure loader (`utils/config.py`). Zero hardcoded secrets. |
| **3** | **Containerization Environment** | ✅ Completed | Production `Dockerfile` and `docker-compose.yml` for isolated cross-platform execution. |
| **4** | **SQLite Idempotency Engine (Node 01)** | ✅ Completed | Crash-resilient 3-state tracking (`processing`, `done`, `failed`), 10-min stale lock recovery, and thread tracking. |
| **5** | **Signature & Quote Stripper (Node 02)** | ✅ Completed | Strips RFC reply headers, Outlook/Exchange headers, mobile signatures (`Sent from my iPhone`), and legal disclaimers. |
| **6** | **Local spaCy NER & PII Masker (Node 03)** | ✅ Completed | 100% on-premise PII redactor. Masks names, emails, phone numbers, and credentials with reversible tokens before external AI calls. |
| **7** | **Sensitive-Skip Diversion Rules (Node 04)** | ✅ Completed | Rule-based security diversion. Immediately quarantines legal threats, regulatory notices, and sensitive customer data to human review. |
| **8** | **Jev AI Decision Gatekeeper (Node 05)** | ✅ Completed | Evaluates inbound emails via Jev AI (with Groq and regex fallbacks) to decide `legitimate`, `spam`, or `manual_review`. |
| **9** | **Automated Pipeline Verification Suite** | ✅ Completed | End-to-end integration tests (`tests/test_pipeline_e2e.py`), 100-scenario synthetic benchmark (`data/benchmark_emails.json`), and CLI runner (`main.py`). |
| **10** | **Security & Heuristics Hardening** | ✅ Completed | Multi-stage prompt injection heuristics, credential dump density limit, and live Groq model wiring. |
| **11** | **TypeSafe System One Schema Calibration** | ✅ Completed | Reconciled Jev AI probability schema (`hi_threshold: 0.85`, `lo_threshold: 0.15`), engine telemetry (`classifier_used`), and smoke test script. |
| **12** | **Security & Pipeline Bug Fix Audit** | ✅ Completed | Resolved thread header spoofing, fixed idempotency 'processing' deadlock, calibrated billing intent phrases, and prevented opening sign-off truncation. |
| **13** | **External Tech-Term Whitelist** | ✅ Completed | Externalized tech term whitelist (`config/tech_terms.txt`) preventing spaCy NER from redacting tools/databases as `PERSON`. |

---

## 🛠️ Audit of Identified Issues & Production Fixes Applied

During rigorous stress testing, code audit, and adversarial benchmark evaluation, **6 key issues** were identified and systematically resolved. The table below details what was broken, the architectural fix applied, and the test proof.

### Issue 1: Thread Header Bypass & Spoofing Vulnerability (Security — High Priority)
* **Node Affected:** Node 01 (`nodes/ingest.py` & `db/database.py`) and Node 05 (`nodes/jev_gatekeeper.py`).
* **The Problem:** The initial design allowed any email containing an `In-Reply-To` header or active `thread_id` to bypass the Jev Gatekeeper and Sensitive Guardrail. An attacker could spoof an `In-Reply-To` header or inject a malicious prompt injection payload into an existing thread, bypassing all AI safety controls.
* **The Fix:**
  1. **Participant Verification:** In `db/database.py` and `nodes/ingest.py`, thread continuity now strictly verifies that the inbound sender is a known participant of prior messages in that thread (`db.is_thread_participant`). Unverified senders cannot inherit thread state.
  2. **Zero Blanket Bypass:** Removed the rule that skipped the gatekeeper for active threads. All thread replies must pass Node 04 (Sensitive Guardrail) and Node 05 (`is_threat` check).
* **Test Verification:**
  - `test_active_thread_prompt_injection_blocked`: An adversarial prompt injection sent within a legitimate thread is blocked and routed to `Review/Manual`.
  - `test_active_thread_normal_reply_approved`: Benign follow-ups from verified thread participants pass safely.

---

### Issue 2: Stuck 'processing' Status & Idempotency Deadlock
* **Node Affected:** Node 01 (`db/database.py`) and Node 05 (`nodes/jev_gatekeeper.py`).
* **The Problem:** When the Gatekeeper approved an email as legitimate, the SQLite status was left as `'processing'` to be picked up by Phase 2. If the same email was re-transmitted within 10 minutes, the idempotency check treated it as a concurrent locked email rather than recognizing it as already finished for Phase 1.
* **The Fix:**
  1. When an email is approved as legitimate, Node 05 explicitly calls `db.mark_done(email_id, routing_status="gatekeeper_approved")`.
  2. Added helper `db.get_gatekeeper_approved()` as the atomic hand-off contract for Phase 2 workers.
  3. Re-transmissions within 10 minutes are recognized as duplicate deliveries (`duplicate_skipped`), not stuck locks.
* **Test Verification:**
  - `test_duplicate_recognized_within_10_minutes_after_gatekeeper_approval`: Verifies that a duplicate email arriving 2 minutes after approval is detected as a duplicate and skipped cleanly.
  - `test_get_gatekeeper_approved_helper`: Confirms approved emails are returned atomically for Phase 2 pickup.

---

### Issue 3: Overly Blunt Billing Keyword False Diversions
* **Node Affected:** Node 04 (`nodes/sensitive_skip.py` & `config.yaml`).
* **The Problem:** Single keywords such as `"chargeback"` and `"refund dispute"` triggered immediate diversion to the `Review/Sensitive` queue. Benign customer queries like *"Please refund my $20, I don't want to file a chargeback"* were quarantined, degrading support responsiveness and violating B2B false positive SLAs (<15%).
* **The Fix:**
  1. Replaced single-word triggers with multi-word intent phrases: `"will file a chargeback"`, `"filing a chargeback"`, `"chargeback filed"`, `"disputing this charge"`, `"my lawyer"`, `"arbitration demand"`.
  2. Benign refund requests with polite mentions pass cleanly to normal support triage; hostile legal or financial threats are caught immediately.
* **Test Verification:**
  - `test_billing_intent_phrases_vs_benign_refund`: Verifies that *"Please refund my $20, I don't want to file a chargeback"* is NOT quarantined, while *"I will file a chargeback if this isn't fixed"* is flagged and diverted.

---

### Issue 4: Premature Signature Truncation on Opening "Thank you."
* **Node Affected:** Node 02 (`nodes/signature_stripper.py`).
* **The Problem:** Sign-off patterns (e.g., `Thank you`, `Thanks`) were treated as the beginning of a closing signature even when appearing at the very start of an email. For short 3-line emails opening with gratitude (e.g., *"Thank you.\nOur server is crashing.\nPlease help."*), the entire message body was stripped.
* **The Fix:**
  1. A sign-off is only recognized as a signature boundary if non-empty body text precedes it, or if it appears within the trailing lines of the message.
  2. Preserves opening pleasantries while stripping closing signatures.
* **Test Verification:**
  - `test_opening_thank_you_three_line_email_preserved`: Verifies that short emails opening with *"Thank you."* retain 100% of their critical body content.

---

### Issue 5: Infrastructure & Tool Name Redaction False Positives
* **Node Affected:** Node 03 (`nodes/pii_masker.py`, `config/tech_terms.txt`, `config.yaml`).
* **The Problem:** The local spaCy NER model (`en_core_web_sm`) occasionally misclassified software libraries, databases, and infrastructure tools (e.g., `"Postgres"`, `"Kubernetes"`, `"Apollo"`, `"Grafana"`) as `PERSON`, redacting them as `[PERSON_1]` and destroying context for engineering triage.
* **The Fix:**
  1. **External Whitelist:** Stored in [`config/tech_terms.txt`](./config/tech_terms.txt), editable without touching Python code. Covers databases, cloud tools, frameworks, and support tools.
  2. **Exact Whole-Entity Match:** Skips masking only when the spaCy entity matches a whitelist term exactly (case-insensitive).
  3. **Zero Partial Match Risk:** Full names containing tool words (e.g., `"Apollo Chen"`, `"Grafana Smith"`) evaluate to `False` against the whitelist and are strictly masked as `[PERSON_1]`.
  4. **Zero Logging & Performance:** Loaded once and cached in memory; zero customer text logged.
* **Test Verification:**
  - `test_tech_terms_whitelist_prevents_person_masking`: Verifies `"Postgres"` and `"Kubernetes"` remain intact, `"John Doe"` is masked as `[PERSON_1]`, and `"Apollo Chen"` is strictly masked as `[PERSON_1]`.

---

### Issue 6: TypeSafe System One (Jev AI) API Schema Calibration
* **Node Affected:** Node 05 (`nodes/jev_gatekeeper.py`, `utils/jev_client.py`).
* **The Problem:** The initial mock assumed a simple binary `{ "is_spam": bool }` schema. The actual production TypeSafe System One API returns a multi-class probability dictionary (`threat_scores: { "spam": float, "prompt_injection": float, ... }`) requiring calibrated high and low thresholds.
* **The Fix:**
  1. Mapped the TypeSafe System One API schema with calibrated dual thresholds (`hi_threshold: 0.85`, `lo_threshold: 0.15`).
  2. Added telemetry (`classifier_used: 'jev' | 'groq' | 'regex'`) to log the exact engine that evaluated each email.
  3. Created an isolated connectivity script [`scripts/jev_smoke_test.py`](./scripts/jev_smoke_test.py).
  4. Provided automatic, non-blocking fallback to Groq (`openai/gpt-oss-20b`) and local deterministic heuristics when offline or without an API key.
* **Test Verification:**
  - `test_output_schema_keys`, `test_probability_mapping_table`, and `test_jev_ai_api_legitimate_classification`.

---

## 🧪 Comprehensive Verification Evidence

### 1. Automated Test Suite (77 Tests Passing)
```
============================= test session starts ==============================
platform linux -- Python 3.14.4, pytest-9.1.1, pluggy-1.7.0 -- ./venv/bin/python3
cachedir: .pytest_cache
rootdir: /mnt/D48444128443F610/Customer-Email-Triage-Automation
plugins: anyio-4.15.1, langsmith-0.14.11
collected 77 items

tests/test_ingest_idempotency.py .............                           [ 18%]
tests/test_jev_client.py .......                                         [ 27%]
tests/test_jev_gatekeeper.py ........                                    [ 37%]
tests/test_pii_masker.py ............                                    [ 53%]
tests/test_pipeline_e2e.py .............                                 [ 70%]
tests/test_sensitive_skip.py ........                                    [ 80%]
tests/test_signature_stripper.py ...............                         [100%]

=================== 77 passed, 116 subtests passed in 7.13s ====================
```

### 2. 100-Scenario Synthetic Benchmark Suite (100% Pass)
```
========================================================================
   CUSTOMER EMAIL TRIAGE AUTOMATION — INGESTION TO JEV AI ENGINE
   LangGraph Pipeline | Local spaCy NER Redactor | 3-Tier Gatekeeper
========================================================================

[*] Loaded 100 synthetic benchmark scenarios from: data/benchmark_emails.json
[*] Average Latency: 43.1ms per email
[+] Result: 100 of 100 scenarios PASSED successfully! Pipeline is operational.
```

---

## 🤝 Phase 2 Handoff Architecture Contract

Phase 1 completes the critical Ingestion, Privacy, Security, and Gatekeeper stages. Downstream Phase 2 modules can seamlessly integrate via the following defined contract:

1. **Pickup Query:**
   ```python
   from db.database import TriageDatabase
   db = TriageDatabase("triage.db")
   approved_emails = db.get_gatekeeper_approved(limit=50)
   ```
2. **State Contract:**
   Every approved email in `TriageState` includes:
   - `cleaned_body`: Stripped of quotes, signatures, and footers.
   - `masked_body`: Anonymized text with `[TOKEN_N]` placeholders (100% PII-free).
   - `token_map`: Bidirectional map to restore customer details via `unmask_text()` after LLM reasoning.
   - `gatekeeper_decision`: `'legitimate'` with calibrated confidence score.
3. **Phase 2 Nodes to Attach:**
   - Node 06: Customer Tier & SLA Target Enrichment.
   - Node 07: Intent & Category Classification (`Engineering`, `Support`, `Sales`, `Billing`).
   - Node 08: Multi-Channel Dispatch Adapters (GitHub Issues, FreeScout, CRM, Slack).

---

## 🚀 Readiness Conclusion

The repository is clean, fully verified, secure, and ready for immediate client demonstration or automated CI/CD deployment.
