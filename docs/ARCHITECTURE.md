# System Architecture: Customer Email Triage Automation

## 1. Purpose & Phases
LangGraph pipeline automating customer email triage with strict privacy and security invariants.
- **Phase 1 (Complete):** Ingestion, idempotency, signature stripping, local spaCy PII masking, sensitive-skip, and 3-tier gatekeeper.
- **Phase 2 (In Progress):** Deep semantic classification, HITL review queue, outbox ledger, multi-destination adapters (`P2-03` to `P2-07`), worker daemon (`P2-09`), and Gmail connector (`P2-12`).

## 2. Data Flow
```
Incoming Email
      │
      ▼
[ `nodes/ingest.py` ] ──(duplicate / in-flight)──► END
      │
      ▼
[ `nodes/signature_stripper.py` ]
      │
      ▼
[ `nodes/pii_masker.py` ]
      │
      ▼
[ `nodes/sensitive_skip.py` ] ──(is_sensitive=True)──► END (Quarantine: Review/Sensitive)
      │
      ▼
[ `nodes/jev_gatekeeper.py` ] ──(spam / manual_review)──► END (Junk/Spam or Review/Manual)
      │ (gatekeeper_approved)
      ▼
[ `nodes/classifier.py` ]
      │
      ▼
[ `nodes/hitl_queue.py` ] ──(hitl_status='pending')──► END (Review/HITL Queue)
      │ (hitl_status in 'auto_approved','approved')
      ▼
[ Downstream Dispatcher (P2-03) ] ──► GitHub / FreeScout / CRM / Webhook
```

## 3. Node Table
| File | Function | Reads State Keys | Writes State Keys | Side Effects | Routing & Outcomes |
|---|---|---|---|---|---|
| `nodes/ingest.py` | `ingest_node` | `email_id`, `message_id`, `thread_id`, `sender_email`, `sender_domain`, `email_subject`, `email_body`, `raw_body`, `has_attachments` | `email_id`, `message_id`, `thread_id`, `sender_email`, `sender_domain`, `email_subject`, `email_body`, `raw_body`, `has_attachments`, `is_active_thread`, `dispatch_status`, `routing_status`, `retry_count`, `error_message` | SQLite idempotency claim | `should_continue_triage`: `continue` (new/retry) or `end` (duplicate/in-flight/max retries) |
| `nodes/signature_stripper.py` | `signature_stripper_node` | `raw_body`, `email_body` | `cleaned_body`, `email_body` | None (pure regex) | Linear: proceeds to `nodes/pii_masker.py` |
| `nodes/pii_masker.py` | `pii_masker_node` | `email_subject`, `cleaned_body`, `email_body`, `raw_body`, `email_id`, `token_map` | `masked_subject`, `masked_body`, `token_map`, `spacy_failed`, `routing_status`, `dispatch_status`, `dispatch_target`, `gatekeeper_decision` | Loads local spaCy model | Linear: proceeds to `nodes/sensitive_skip.py` |
| `nodes/sensitive_skip.py` | `sensitive_skip_node` | `cleaned_body`, `email_body`, `email_subject`, `raw_body`, `token_map`, `email_id`, `labels_to_apply` | `is_sensitive`, `sensitive_reason`, `labels_to_apply`, `is_starred`, `dispatch_target`, `dispatch_status`, `routing_status`, `error_message` | SQLite mark done/failed | `should_route_after_sensitive`: `continue` (safe) or `end` (quarantine) |
| `nodes/jev_gatekeeper.py` | `jev_gatekeeper_node` | `masked_subject`, `masked_body`, `email_subject`, `cleaned_body`, `email_body`, `email_id`, `is_active_thread`, `labels_to_apply` | `gatekeeper_decision`, `is_spam`, `gatekeeper_confidence`, `is_threat`, `threat_details`, `classifier_used`, `labels_to_apply`, `routing_status`, `dispatch_target`, `dispatch_status`, `is_active_thread`, `is_starred`, `error_message` | HTTPS to Jev/Groq; SQLite update | `should_route_after_gatekeeper`: `continue` (approved) or `end` (spam/manual review/persist failed) |
| `nodes/classifier.py` | `classifier_node` | `email_id`, `masked_subject`, `masked_body` | `classification`, `p2_classifier_used` | HTTPS to Groq/Jev (if enabled) | Linear: proceeds to `nodes/hitl_queue.py` |
| `nodes/hitl_queue.py` | `hitl_queue_node` | `email_id`, `classification`, `p2_classifier_used`, `is_threat` | `hitl_status`, `hitl_reason`, `p2_status`, `dispatch_status`, `error_message` | SQLite Phase 2 update | `should_route_after_hitl`: `continue` (auto_approved/approved) or `end` (pending/persist failed) |

## 4. State Contract (`TriageState`)
- `email_id` (`str`): Ingestion (`nodes/ingest.py`). Canonical message identifier.
- `message_id` (`str`): Ingestion (`nodes/ingest.py`). RFC 2822 Message-ID.
- `thread_id` (`str`): Ingestion (`nodes/ingest.py`). Thread grouping identifier.
- `sender_email` (`str`): Ingestion (`nodes/ingest.py`). Normalized sender address.
- `sender_domain` (`str`): Ingestion (`nodes/ingest.py`). Extracted sender domain.
- `email_subject` (`str`): Ingestion (`nodes/ingest.py`). Raw subject line.
- `email_body` (`str`): Ingestion / `nodes/signature_stripper.py`. Cleaned body.
- `raw_body` (`str`): Ingestion (`nodes/ingest.py`). Preserved original raw body.
- `has_attachments` (`bool`): Ingestion (`nodes/ingest.py`). Flag for email attachments.
- `is_active_thread` (`Optional[bool]`): Ingestion (`nodes/ingest.py`). Verified against approved DB history.
- `cleaned_body` (`Optional[str]`): Stripper (`nodes/signature_stripper.py`). Body with quotes/signatures removed.
- `masked_body` (`Optional[str]`): PII Masker (`nodes/pii_masker.py`). Body with redactions.
- `masked_subject` (`Optional[str]`): PII Masker (`nodes/pii_masker.py`). Subject with redactions.
- `token_map` (`Dict[str, str]`): PII Masker (`nodes/pii_masker.py`). Bidirectional token mapping (never logged).
- `spacy_failed` (`Optional[bool]`): PII Masker (`nodes/pii_masker.py`). Runtime spaCy failure indicator.
- `is_sensitive` (`bool`): Guardrail (`nodes/sensitive_skip.py`). Sensitive keyword or high-density code match.
- `sensitive_reason` (`Optional[str]`): Guardrail (`nodes/sensitive_skip.py`). Matched sensitive phrase.
- `is_spam` (`Optional[bool]`): Gatekeeper (`nodes/jev_gatekeeper.py`). Spam decision flag.
- `gatekeeper_decision` (`Optional[str]`): Gatekeeper (`nodes/jev_gatekeeper.py`). 'legitimate', 'spam', 'manual_review'.
- `gatekeeper_confidence` (`Optional[float]`): Gatekeeper (`nodes/jev_gatekeeper.py`). Decision confidence score (0.0 to 1.0).
- `is_threat` (`Optional[bool]`): Gatekeeper (`nodes/jev_gatekeeper.py`). Security threat / prompt injection indicator.
- `threat_details` (`Optional[str]`): Gatekeeper (`nodes/jev_gatekeeper.py`). Threat pattern details.
- `classifier_used` (`Optional[str]`): Gatekeeper (`nodes/jev_gatekeeper.py`). Phase 1 engine ('jev', 'groq', 'regex').
- `customer_tier` (`Optional[str]`): Enrichment / Ingestion. Tier metadata (e.g. Enterprise, Free).
- `sla_target` (`Optional[str]`): Enrichment / Ingestion. SLA target string.
- `classification` (`Optional[EmailClassification]`): Classifier (`nodes/classifier.py`). Pydantic semantic categorization.
- `p2_classifier_used` (`Optional[str]`): Classifier (`nodes/classifier.py`). Phase 2 engine ('jev', 'groq', 'offline_heuristic', 'fail_closed').
- `p2_status` (`Optional[str]`): HITL Queue (`nodes/hitl_queue.py`). 'hitl_pending', 'auto_approved', 'persist_failed'.
- `hitl_status` (`Optional[str]`): HITL Queue (`nodes/hitl_queue.py`). 'none', 'pending', 'auto_approved', 'approved', 'rejected'.
- `hitl_reason` (`Optional[str]`): HITL Queue (`nodes/hitl_queue.py`). Explanation for HITL diversion.
- `labels_to_apply` (`List[str]`): Guardrail / Gatekeeper. Applied label list (e.g. 'Review/Sensitive', 'Junk/Spam').
- `is_starred` (`bool`): Guardrail / Gatekeeper. Mailbox priority flag.
- `dispatch_target` (`Optional[str]`): Guardrail / Gatekeeper. Service destination or review queue.
- `dispatch_status` (`Optional[str]`): Ingestion / Gatekeeper / Dispatcher. 'processing', 'done', 'failed'.
- `retry_count` (`int`): Ingestion (`nodes/ingest.py`). Retries executed count.
- `error_message` (`Optional[str]`): Ingestion / Gatekeeper. Error string on failure.
- `routing_status` (`Optional[str]`): Ingestion / Gatekeeper. Phase 1 lifecycle status.

## 5. Database (`triage.db`)
Main table: `email_triage`.
- Columns: `email_id` (TEXT PK), `message_id` (TEXT), `thread_id` (TEXT), `sender_email` (TEXT), `status` (TEXT), `retry_count` (INTEGER), `routing_status` (TEXT), `dispatch_target` (TEXT), `error_message` (TEXT), `created_at` (TEXT), `updated_at` (TEXT), `masked_subject` (TEXT), `masked_body` (TEXT), `is_active_thread` (INTEGER), `gatekeeper_decision` (TEXT), `gatekeeper_confidence` (REAL), `classifier_used` (TEXT), `p2_category` (TEXT), `p2_priority` (TEXT), `p2_sentiment` (TEXT), `p2_customer_emotion` (TEXT), `p2_summary` (TEXT), `p2_suggested_team` (TEXT), `p2_confidence` (REAL), `p2_classifier_used` (TEXT), `hitl_status` (TEXT), `hitl_reason` (TEXT), `hitl_notes` (TEXT), `reviewed_by` (TEXT), `reviewed_at` (TEXT).
- Status CHECK: `CHECK(status IN ('processing', 'done', 'failed'))`.
- Routing Status values: `processing`, `duplicate_skipped`, `in_flight_skipped`, `max_retries_exceeded`, `stale_recovery`, `retry`, `sensitive_diverted`, `spam_diverted`, `manual_review`, `gatekeeper_approved`, `persist_failed`.
- Phase 1 vs Phase 2: Phase 1 writes `status`, `routing_status`, and gatekeeper columns. Phase 2 writes ONLY `p2_*` columns, `hitl_*`, `reviewed_by`, and `reviewed_at`. Phase 2 NEVER overwrites `routing_status` or `status`.
- Migration method: `TriageDatabase._init_db()` executes idempotent `ALTER TABLE ADD COLUMN` statements guarded by `PRAGMA table_info`.

## 6. Configuration (`config.yaml`)
Schema validated strictly by `utils/config.py` (`validate_config`, unknown keys raise `ConfigError`).
- `system`: Core engine settings (`database_path`, `idempotency_stale_minutes`, `max_dispatch_retries`, `audit_log_enabled`, `persist_masked_text`).
- `privacy`: Redaction and scanning rules (`spacy_model`, `tech_terms_file`, `default_phone_region`, `tech_context_words`, `sensitive_keywords`, `max_code_density`).
- `security`: Safe scanning limits (`regex_scan_head`, `regex_scan_tail`).
- `gatekeeper`: Decision models and timeouts (`timeout_seconds`, `max_retries`, `api_key_env`, `fallback_model`, `groq_api_key_env`, `jev`).
- `llm`: Secondary fallback generative LLM (`model`, `temperature`, `confidence_threshold`, `groq_api_key_env`).
- `classification`: Semantic taxonomy settings (`primary`, `fallback`, `hitl_threshold`, `always_review_categories`, `max_subject_chars`, `max_body_chars`, `jev`).
- `destinations`: Downstream adapter targets (`Engineering`, `Support`, `Sales`, `Billing`).
- Env overrides: `DATABASE_PATH`, `IDEMPOTENCY_STALE_MINUTES`, `MAX_DISPATCH_RETRIES`. Secrets via `*_env` names.

## 7. External Calls
All external HTTP requests are strictly HTTPS and validated against the domain allowlist (`validate_outbound_url`):
- `api.typesafe.ai`: Called by `utils/jev_client.py` and `utils/classifier_client.py`. Receives masked text, returns mathematical routing choice.
- `api.groq.com`: Called by `utils/jev_client.py` and `utils/classifier_client.py`. Receives masked text, returns JSON classification.
- Privacy guarantee: Raw customer PII, unmasked bodies, raw subjects, and `token_map` NEVER leave the host.

## 8. Module Index
- `nodes/ingest.py`: Node 01: Ingestion, idempotency locking, and thread verification.
- `nodes/signature_stripper.py`: Node 02: Quoted reply and signature delimiter stripping.
- `nodes/pii_masker.py`: Node 03: On-premise spaCy NER and regex token masking.
- `nodes/sensitive_skip.py`: Node 04: Regulatory, legal, and security keyword diversion.
- `nodes/jev_gatekeeper.py`: Node 05: Spam, threat, and legitimacy gatekeeping.
- `nodes/classifier.py`: Node 06: Deep LLM intent, category, and sentiment classifier.
- `nodes/hitl_queue.py`: Node 07: Human-in-the-loop review queue and state gating.
- `utils/config.py`: Configuration loading, validation schemas, and secret resolution.
- `utils/text_tools.py`: Bounded scanning and ReDoS prevention utilities.
- `utils/jev_client.py`: TypeSafe System One client with Groq and heuristic fallback.
- `utils/classifier_client.py`: Multi-tier classifier client with bounded scan and pre-filter.
- `db/database.py`: SQLite idempotency store, retry tracking, and review resolution.
- `scripts/hitl_cli.py`: Reviewer CLI tool to list, show, approve, and reject reviews.
- `scripts/manual_classifier_check.py`: Standalone forced-offline classifier verification check.
- `scripts/jev_smoke_test.py`: Standalone TypeSafe System One API connectivity smoke test.
- `tools/egress_check.py`: Network egress auditor detecting data leaks.
- `tools/check_concurrency.py`: Multi-process SQLite lock stress test.
- `tests/conftest.py`: Test environment isolation fixtures and network egress blocks.

## 9. Extension Points
- **Add a Node:** Create `nodes/<name>.py` with `<name>_node(state: TriageState) -> dict`, register in `nodes/__init__.py`, and wire conditional edges in `pipeline.py`.
- **Add an Adapter:** Subclass `BaseDestinationAdapter` in `utils/adapters/`, implement `dispatch()` and `check_duplicate()`, register target in `config.yaml`.
- **Add a Config Key:** Add key to `_KNOWN_KEYS` in `utils/config.py`, add validator in `validate_config()`, and set default in `config.yaml`.
- **Add a DB Column:** Add column tuple to `new_columns` list in `TriageDatabase._init_db()`.
- **Add a Test:** Create `tests/test_<feature>.py`, mock external clients or use `temp_db` fixture, assert specific states.

## 10. Singletons & Test Isolation
- Process Singletons: Config cache (`reset_config_cache` in `utils/config.py`), spaCy model (`reset_spacy_cache` in `nodes/pii_masker.py`), JevClient (`reset_default_client` in `utils/jev_client.py`), ClassifierClient (`reset_default_classifier_client` in `nodes/classifier.py`).
- Test Isolation (`tests/conftest.py`): Blocks external socket egress, clears API env keys, and resets all singletons before and after every test.

## 11. Known Limitations & Open Items
- **Jev Choice Routing Mismatch (`ROADMAP.md` P2-01):** Jev's 4 routing options cannot express the 10-category taxonomy; `classification.jev.enabled: false` by default.
- **Pending Dispatcher & Adapters (`ROADMAP.md` P2-03 to P2-07):** Outbox pattern and external service adapters are not yet implemented.
- **Pending Worker Daemon (`ROADMAP.md` P2-09):** Standalone polling worker and atomic batch claiming are pending.
- **Pending Mailbox Connector (`ROADMAP.md` P2-12):** Gmail Pub/Sub webhook integration is pending.
