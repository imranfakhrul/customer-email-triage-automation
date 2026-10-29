# Phase 2 Architectural Decisions, Data Governance & Client Alignment

**Document Version:** 1.0.0  
**Status:** Approved Architectural Baseline  
**Related Milestone:** Phase 2 (P2-00 through P2-12)  
**Tracking Issue / Task:** `[P2-00]` in [`ROADMAP.md`](../ROADMAP.md)

---

## Executive Summary

Phase 2 introduces automated semantic categorization and multi-destination dispatching (GitHub Issues, FreeScout Helpdesk, CRM Leads, Webhook Alerts) with Human-in-the-Loop (HITL) review.

Before implementing downstream destination adapters, this document formally records:
1. **Destination Egress & Data Privacy Invariants:** How customer data is handled per destination.
2. **Masked Text Retention & Purge Lifecycle:** Data storage duration and privacy guarantees in SQLite.
3. **Safe-by-Default Dry-Run & Staging Policy:** Operational rules for testing and gradual promotion to live dispatch.
4. **Daily Rate Limits, Caps & Circuit Breakers:** Volume controls preventing API exhaustion and alert storms.
5. **Classifier Model Configuration:** Groq LLM model selection, temperature settings, and fail-closed heuristic fallback.
6. **Client Alignment Questionnaire:** 6 prerequisite questions for stakeholders to finalize integration credentials and destination routing rules.

---

## 1. Destination Data Privacy & Egress Policy

### 1.1 Core Privacy Invariant
* **`token_map` is strictly ephemeral:** Under no circumstances is `token_map` (which maps entity placeholders like `{{EMAIL_1}}`, `{{PERSON_1}}` to raw customer PII) ever written to SQLite or transmitted over external network connections.
* **SQLite Persistence Contract:** The `email_triage` table persists ONLY `masked_subject` and `masked_body`. Raw, unmasked email text is never persisted to disk by the triage worker.

### 1.2 Destination-Specific Egress Policies

`config.yaml` configures destination behaviors under `destinations:` keyed by canonical service names: `github`, `freescout`, `crm`, and `webhook` (replacing legacy team-named keys `Engineering`, `Support`, `Sales`, and `Billing`; see mapping note below). Adapters receive only an immutable `DispatchPayload`, never the raw state.

> [!NOTE]
> **Destination Key Mapping:**
> - `github` (formerly `Engineering`): Engineering bug reports and feature requests.
> - `freescout` (formerly `Support`): Customer support tickets and routine billing inquiries.
> - `crm` (formerly `Sales`): Sales demo requests and enterprise pricing leads.
> - `webhook` (formerly `Billing`): Urgent billing disputes and critical outage alerts.

| Destination Key | Target Service | `unmask_pii` / `use_masked_text_only` in `config.yaml` | Permitted Data Egress | Architectural Rationale & Privacy Guarantee |
|:---|:---|:---:|:---|:---|
| `github` | GitHub Issues (`github`) | `unmask_pii: false`<br>`use_masked_text_only: true` | **Masked Text Only** (`masked_subject`, `masked_body`) | Software bug reports are posted to public or team-shared GitHub repositories. Under zero circumstances should customer PII (real email, phone, name) appear in GitHub issues or commit logs. |
| `freescout` | FreeScout Helpdesk (`freescout`) | `unmask_pii: true`<br>`use_masked_text_only: false` | **Selectively Unmasked Contact Data + Real Sender Email** | Support agents need customer contact details (`PERSON`, `EMAIL`, `PHONE`, `IP_ADDRESS`) and real `sender_email` (with `type: "email"`) to receive notifications and reply directly to the customer. High-risk secrets (`CREDIT_CARD`, `SSN`, `IBAN`, `API_KEY`) remain permanently masked. Fallback to `bot_customer_id` / `type: "phone"` occurs only when `unmask_pii: false` or `sender_email` is missing. |
| `crm` | CRM Ingestion (`crm`) | `unmask_pii: true`<br>`use_masked_text_only: false` | **Selectively Unmasked Contact Info + Real Sender Email** | CRM leads need customer work email, phone, and name for sales follow-up. Restores contact info and company domain while sanitizing customer notes against formula injection (`=`, `+`, `-`, `@`). High-risk secrets remain permanently masked. |
| `webhook` | Webhook Alerts (`webhook`) | `unmask_pii: false`<br>(configurable `true`) | **Structured Metadata + Masked Context** | High-urgency billing disputes and outage alerts are pushed to notification channels (e.g., Slack, PagerDuty). To prevent PII exposure in shared chat channels, alerts default to structured metadata (`email_id`, `category`, `priority`, `amount_detected`, `masked_summary`) signed with HMAC-SHA256, omitting raw customer bodies unless explicitly unmasked for secure finance endpoints. |

---

### 1.3 Universal Selective Unmasking Architecture (`resolve_dispatch_content`)

To support role-based data requirements across downstream services without compromising customer privacy or security invariants, the downstream pipeline incorporates a centralized selective unmasking architecture:

1. **Central Unmasking Helper (`utils/unmasker.py`):**
   - Implements `resolve_dispatch_content(state: TriageState, unmask_pii: bool = False, allowed_entity_types: Optional[Set[str]] = None, mailbox_fetcher: Optional[Callable[[str], Optional[str]]] = None) -> Dict[str, Any]`.
   - **`unmask_pii=False` (Strict Masking):** Returns strictly `masked_subject`, `masked_body`, and `sender_domain`. Raw `sender_email` is omitted (`None`), and zero unmasked PII is returned.
   - **`unmask_pii=True` (Selective Contact Restoration):**
     - Selectively restores allowed entity placeholders in `masked_subject` and `masked_body` using `state.get("token_map")` via `nodes.pii_masker.unmask_text`.
     - **Safe Default Allowed Entities:** `{"PERSON", "EMAIL", "PHONE", "IP_ADDRESS"}`.
     - **Permanently Blocked Secrets:** High-risk secrets (`{"CREDIT_CARD", "SSN", "IBAN", "API_KEY"}`) are strictly retained as masked tokens and never restored, even for FreeScout or CRM.
     - **Lifecycle & Persistence Fallback:** If `token_map` is empty or absent (such as in standalone Phase 2 worker mode where `token_map` was not persisted to SQLite), the helper provides `customer_email: sender_email` (from SQLite audit metadata), supports an optional `mailbox_fetcher(message_id)` callback (via P2-12 Mailbox Connector), and safely falls back to `masked_body` if raw text cannot be re-fetched.

2. **Destination-Specific Configuration Policy (`config.yaml` & `utils/config.py`):**
   - `destinations.github.unmask_pii: false` (Engineering only sees masked bug reports).
   - `destinations.freescout.unmask_pii: true` (Support tickets bind to customer's real `sender_email` with `type: "email"` and unmask contact details; `bot_customer_id` / `type: "phone"` used only when unmasking is disabled).
   - `destinations.crm.unmask_pii: true` (Sales leads receive real contact email and name with formula injection protection).
   - `destinations.webhook.unmask_pii: false` (Alerts default to masked context; configurable if delivered to secure internal endpoints).

3. **Egress Test Compatibility (`./check.sh egress`):**
   - Offline benchmark and test suites enforce that when destinations are disabled or running offline, zero unmasked customer PII ever leaves the host over network sockets. Phase 1 classification egress invariants remain 100% intact.

---

## 2. Masked Text Retention & Purge Schedule

### 2.1 SQLite Data Lifecycle in `email_triage`
To reconcile operational thread history tracking with data privacy regulations (GDPR, CCPA), SQLite records follow a tiered retention model:

1. **Permanent Audit Metadata:**
   - Columns: `email_id`, `message_id`, `thread_id`, `sender_email`, `status`, `routing_status`, `dispatch_target`, `gatekeeper_decision`, `created_at`, `updated_at`.
   - **Retention:** Permanent (or until account decommissioning).
   - **Purpose:** Thread continuity detection (A5 security) and intake duplicate detection (`claim_processing`) require historical thread IDs and routing statuses to remain queryable indefinitely.

2. **Rolling Purge for Masked Text Bodies:**
   - Columns: `masked_subject`, `masked_body`.
   - **Retention:** 90 calendar days from `created_at`.
   - **Automated Purge Routine:**
     ```sql
     -- Scheduled weekly maintenance routine
     UPDATE email_triage
     SET masked_subject = '[PURGED_RETENTION_EXPIRED]',
         masked_body = '[PURGED_RETENTION_EXPIRED]'
     WHERE created_at < datetime('now', '-90 days')
       AND status = 'done';
     ```
   - This ensures that even masked text does not accumulate indefinitely in local database storage.

---

## 3. Safe-by-Default Dry-Run & Staging Policy

### 3.1 Default Dry-Run State
To prevent accidental creation of live issues, tickets, CRM contacts, or webhook alerts during development, staging, or testing:

* `dispatch.dry_run: true` is enforced by default in `config.yaml`.
* In Dry-Run mode:
  1. Full classification, HITL gating, and routing decisions execute identically to production.
  2. The Outbox ledger (`p2_dispatch_log`) creates a row with `state = 'simulated'` and `mode = 'dry_run'` (never `'sent'`). Real dispatches use `mode = 'live'`. A simulated row never blocks a subsequent live dispatch.
  3. The adapter formats the full outgoing payload and emits a structured audit log entry (`[DRY_RUN_DISPATCH] email_id={id} destination={dest} action_type={act} payload_sha256={hash} payload_bytes={len}`). Dry-run logs carry zero customer text or response bodies.
  4. **Zero external HTTP requests are emitted.** Network isolation is 100% maintained.

### 3.2 Production Promotion Protocol
Before flipping `dispatch.dry_run: false` in production:
- [ ] Sandbox smoke test scripts (`scripts/*_smoke_test.py`) have executed successfully against test accounts.
- [ ] Destination credentials (`GITHUB_TOKEN`, `FREESCOUT_API_KEY`, `CRM_API_KEY`, `WEBHOOK_SECRET_KEY`) are verified in the host environment.
- [ ] Daily dispatch caps are configured and confirmed.
- [ ] Operators are trained on `scripts/hitl_cli.py` for review queue management.

---

## 4. Daily Rate Limits, Caps & Circuit Breakers

To protect downstream APIs from rate limits, unexpected billing charges, or alert floods caused by misconfigured mailboxes or denial-of-service attempts, Phase 2 implements per-destination daily dispatch limits.

### 4.1 Daily Caps Configuration (`config.yaml`)

| Destination Key | Service Adapter | Default Daily Cap | Reset Interval | Action When Cap Exceeded |
|:---|:---|:---:|:---:|:---|
| `github` | GitHub Issues | **200 issues / day** | 00:00 UTC | Trips circuit breaker, alerts operators, defers subsequent attempts (`state = 'deferred'`, `reason = 'daily_cap_exceeded'`). |
| `freescout` | FreeScout Helpdesk | **1,000 tickets / day** | 00:00 UTC | Trips circuit breaker, defers excess tickets (`state = 'deferred'`, `reason = 'daily_cap_exceeded'`). |
| `crm` | CRM Ingestion | **500 leads / day** | 00:00 UTC | Trips circuit breaker, halts new lead creation, defers attempts (`state = 'deferred'`, `reason = 'daily_cap_exceeded'`). |
| `webhook` | Webhook Alerts | **200 alerts / day** | 00:00 UTC | Trips circuit breaker, defers subsequent alerts (`state = 'deferred'`, `reason = 'daily_cap_exceeded'`). |

### 4.2 Circuit Breaker Behavior
* When an adapter encounters 5 consecutive network failures or exceeds its daily cap:
  1. The circuit breaker flips to `OPEN`.
  2. An operational alert is logged.
  3. All subsequent dispatch attempts for that destination are deferred (`state = 'deferred'`, `reason = 'circuit_breaker_open'`). They do not divert to HITL.
  4. The circuit half-opens after 15 minutes, attempting 1 trial request before resuming full automated dispatch.

---

## 5. Classifier Architecture: Jev AI Primary with Groq Fallback

Phase 2 classification utilizes a multi-tiered decision pipeline optimized for low latency, mathematical determinism, and high availability:

### 5.1 Primary Classifier Engine: TypeSafe Jev AI (`jev`)
* **Role:** Primary non-generative choice classifier.
* **Latency:** Low-latency execution (70ms – 500ms).
* **Execution Logic:** Jev AI does not generate conversational responses or hallucinate text. Instead, it reads the unstructured message state (`masked_subject` + `masked_body`) and calculates exact mathematical probabilities across pre-defined destination actions.
* **Request Payload Contract:**
  ```json
  {
    "state": "Subject: {masked_subject}\nBody: {masked_body}",
    "questions": [
      {
        "id": "gmail_router",
        "type": "choice",
        "options": ["github_issue_create", "freescout", "crm", "webhook_node"]
      }
    ]
  }
  ```
* **Response Payload Contract:**
  ```json
  {
    "gmail_router": {
      "winning_key": "webhook_node",
      "probabilities": {
        "webhook_node": 0.89,
        "github_issue_create": 0.08,
        "freescout": 0.02,
        "crm": 0.01
      },
      "confidence": 0.94
    }
  }
  ```
* **Action Key to Routing Destination Mapping:**
  - `github_issue_create` ➔ Engineering Bug / Technical Issue (`github`)
  - `freescout` ➔ Customer Support / Subscription Query (`freescout`)
  - `crm` ➔ High-Value Sales / Enterprise Pricing Inquiries (`crm`)
  - `webhook_node` ➔ Urgent Billing Alert / Critical System Event (`webhook`)
* **Host Allowlist:** Strictly restricted to `https://api.typesafe.ai` and `localhost/127.0.0.1` for tests (A13 security pattern).

### 5.2 Secondary Fallback Engine: Groq LLM (`groq`)
* **Role:** High-reasoning fallback when Jev AI is unavailable, times out, or encounters API errors.
* **Model:** `openai/gpt-oss-120b` (configured in `config.yaml` as `llm.classifier_model`).
* **Temperature:** `0.1` (ensures near-deterministic category, sentiment, and priority classification).
* **Extraction:** When invoked, Groq provides detailed schema extraction for category, priority, sentiment, and customer emotion.
* **Host Allowlist:** Strictly restricted to `https://api.groq.com`.

### 5.3 Tertiary Fallback Engine: Local Heuristic (`offline_heuristic`)
If both Jev AI and Groq are unavailable or the worker is offline:
1. The pipeline automatically falls back to the local rule-based heuristic ensemble.
2. The engine is tracked as `state["p2_classifier_used"] = "offline_heuristic"`.
3. **Fail-Closed Principle:** The offline heuristic assigns a bounded confidence score of `0.50` to `0.65` (strictly below `hitl_threshold: 0.85`).
4. **Result:** Virtually **100% of offline-classified emails are routed to the HITL review queue** (`hitl_pending`), preventing unverified guesses from dispatching without human oversight.

### 5.4 Engine Tracking Invariant
Phase 2 classifier engine is recorded in `p2_jobs.p2_classifier_used` with permitted values: `"jev"`, `"groq"`, or `"offline_heuristic"`. This preserves Phase 1's `email_triage.classifier_used` record without modification.

---

## 6. Client Alignment Questionnaire (Pre-Adapter Prerequisites)

The following 6 questions require formal confirmation by the client/stakeholder prior to implementing the destination adapters (P2-04 through P2-07):

### Question 1: Customer PII Policy for Support & Sales
* **Question:** Do your internal FreeScout agents and CRM sales representatives require unmasked customer names and email addresses to service requests?
* **Status:** ✅ **Aligned on Universal Selective Unmasking (`unmask_pii: true`)**
* **Options:**
  - `(Approved) Option A:` Universal Selective Unmasking: restore contact & technical context (`{"PERSON", "EMAIL", "PHONE", "IP_ADDRESS"}`) and bind real `sender_email` (with `type: "email"`), while keeping financial and security secrets (`{"CREDIT_CARD", "SSN", "IBAN", "API_KEY"}`) permanently masked. SQLite continues to persist zero raw text.
  - `Option B:` No, operate strictly on masked text (`masked_subject` and `masked_body`) across all destinations for maximum privacy.

### Question 2: GitHub Repository & Label Taxonomy
* **Question:** What is the target GitHub repository for automated engineering bug reports, and what label schema is required?
* **Options:**
  - `(Recommended) Option A:` `owner/repo` specified in `config.yaml` with labels `["bug", "triage:automated", "urgency:{level}"]`.
  - `Option B:` Custom multi-repo routing based on detected software component (e.g. `frontend-repo` vs `backend-repo`).

### Question 3: Primary CRM Target System
* **Question:** What CRM platform is the organization using for inbound sales and demo inquiry ingestion?
* **Options:**
  - `(Recommended) Option A:` HubSpot (REST API v3 with Deals and Contacts endpoints).
  - `Option B:` Salesforce (Lead Ingestion REST API).
  - `Option C:` Generic CRM Webhook / Zapier intake.

### Question 4: Primary Incident Webhook Destination
* **Question:** Where should urgent billing disputes and critical outage notifications be delivered?
* **Options:**
  - `(Recommended) Option A:` Slack Incoming Webhook (posting to `#ops-alerts` or `#finance-triage`).
  - `Option B:` PagerDuty / OpsGenie incident trigger API.
  - `Option C:` Discord / Microsoft Teams webhook.

### Question 5: Critical Outage Escalation Policy
* **Question:** When an inbound email reports an active production outage (`priority == 'Critical'`), should it divert past the HITL queue and alert on-call staff immediately?
* **Options:**
  - `(Recommended) Option A:` Yes, dispatch immediately via Webhook Alert, while concurrently queueing in HITL for operator logging.
  - `Option B:` No, require human operator approval in HITL before firing external webhook alerts.

### Question 6: Groq LLM API Quotas & Cost Budget
* **Question:** What is the allocated monthly budget and RPM (requests per minute) limit on your Groq Cloud account?
* **Options:**
  - `(Recommended) Option A:` Tier 2 / Pay-as-you-go (up to 300 RPM, estimated budget < $50/month).
  - `Option B:` Free Tier (30 RPM cap — requires worker batch pacing with 2-second rate-limiting delays).

---

## Approval & Sign-Off

| Role | Name | Status | Date |
|:---|:---|:---:|:---:|
| Lead Architecture & Security | Antigravity AI | Approved | 2026-10-26 |
| Engineering Reviewer | User | Pending Manual Review | — |
