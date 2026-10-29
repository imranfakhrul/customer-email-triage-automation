# Customer Email Triage Automation — Remediation & Engineering Roadmap

This roadmap tracks all 24 security, correctness, performance, and documentation issues identified during the senior architectural and security code review (Commit `03867d1`).

Each issue is implemented individually with corresponding unit tests, verified against the benchmark suite, and committed atomically following our modular review workflow.

---

## 🎯 Next Up & Recommended Execution Order

**Phase 1 Status:** 🎉 **Delivered & Signed Off!** (All 24 Remediation Items Fully Resolved & Verified at Commit `020db77`).
**Phase 2 Status:** 🚀 **Phase 2 Architecture & Commit Roadmap Initialized!** (Ready for execution).

### Phase 1 Execution Summary:
1. **Critical PII & Fail-Closed Guardrails:** `A1` ✅ -> `A2` ✅ -> `A4` ✅ -> `A3` ✅ -> `A8` ✅ -> `A13` ✅
2. **State & Concurrency Hardening:** `A5` ✅ -> `A6` ✅ -> `A11` ✅ -> `A9` ✅ -> `A10` ✅
3. **Correctness & Performance (Part B):** `B1` ✅ -> `B2` ✅ -> `B3` ✅ -> `B4` ✅ -> `B5` ✅ -> `B6` ✅
4. **Testing, Docs & Packaging:** `C1` ✅ -> `C2` ✅ -> `C3` ✅ -> `C4` ✅ -> `A12` ✅ -> `A14` ✅

### Phase 2 Implementation Sequence:
1. **Track 0: Architectural Decisions & Client Alignment:** `P2-00` ✅ (Delivered in `docs/phase2_decisions.md`)
2. **Track 1: Intelligence Classification Engine:** `P2-01` ✅ (Deep Classifier) ➔ `P2-02` ✅ (HITL Review Queue)
3. **Track 2: Downstream Destination Adapters:** `P2-03a` ✅ (Foundations & Outbox Ledger) ➔ `P2-03b` ✅ (Router Node & Matrix) ➔ `P2-04a` ✅ (GitHub Formatting & Schema) ➔ `P2-04b` ✅ (GitHub Adapter & Remote Precheck) ➔ `P2-05` ✅ (FreeScout) ➔ `P2-06` ✅ (CRM) ➔ `P2-07` ✅ (Webhook)
4. **Track 3: Integration, Worker, Benchmark, Failure Tests & Docs:** `P2-08` ✅ (LangGraph Integration) ➔ `P2-09` ✅ (Queue Worker) ➔ `P2-10` ✅ (Benchmark Dataset) ➔ `P2-11` ✅ (Operational Docs)
5. **Track 4: Mailbox Ingestion Connector:** `P2-12` ✅ (Gmail Pub/Sub Connector)
6. **Track 5: Post-Review Production Remediation (PRR):** 13 Atomic Commits: `PRR-01` ✅ (Item 1: Stuck Approvals) ➔ `PRR-02` ✅ (Item 2: Adapter Registration) ➔ `PRR-03` ✅ (Item 3: Worker States) ➔ `PRR-04` ✅ (Flow E2E Test) ➔ `PRR-05` ✅ (Item 5: Unmasker Privacy) ➔ `PRR-06` ⏳ (Item 4: Gmail Spoof Guard) ➔ `PRR-07` ⏳ (Item 6: Fallback Domain) ➔ `PRR-08` ⏳ (Item 8: Post-Write Idempotency) ➔ `PRR-09` ⏳ (Item 9: FreeScout Fallthrough) ➔ `PRR-10` ⏳ (Item 10: HITL Reconcile) ➔ `PRR-11` ⏳ (Item 7: Webhook Allowlist) ➔ `PRR-12` ⏳ (Worker & Classifier Guards) ➔ `PRR-13` ⏳ (Gmail Auth Refresh & Pagination)

**Next Immediate Task:** `PRR-06` (`fix(mailbox): [PRR-06] enforce topmost mx.google.com authentication-results header and token parsing`).

---

## 📋 Completed Before This Review

The following foundational improvements were implemented and merged in earlier Phase 1 iterations (Commits `61658fd` to `03867d1`):
* **Jev System One Client Alignment (Commit `61658fd`):** Conformed API request/response schema to TypeSafe System One contract (`is_threat`, `threat_details`, `p_spam`, `p_threat`), added startup engine validation, and enabled `classifier_used` tracking.
* **Thread Bypass Removal & Thread Security (Commit `02650f9`):** Removed unverified active-thread bypass and enforced participant validation for email threads. *(Partially done: see A5 for remaining SQL history and payload guards).*
* **`gatekeeper_approved` Status Synchronization (Commit `02650f9`):** Implemented `db.mark_done` for approved emails and introduced `get_gatekeeper_approved()` reader.
* **First Tech-Terms Whitelist (Commit `03867d1`):** Externalized whitelist in `config/tech_terms.txt`, cached loader, and whole-entity matching for `PERSON` spans. *(Partially done: see A10 for remaining surname context guardrails).*
* **Billing Keyword Intent Phrases (Commit `02650f9`):** Tuned multi-word phrase patterns (`will file a chargeback`, `dispute notice`) for dispute handling.
* **Signature Stripper First Fix (Commit `02650f9`):** Added preceding body checks for opening lines and preserved short email bodies. *(Fully resolved in B1).*

---

## 📊 24-Point Remediation Progress Matrix

| # | Code | Area | Description | Status |
|:---:|:---:|:---|:---|:---:|
| **1** | **A1** | Security | Mask subject line & sender address domain before egress to Jev/Groq | ✅ Resolved |
| **2** | **A2** | Security | Suppress raw `token_map` from `main.py` CLI and logs; print entity counts | ✅ Resolved |
| **3** | **A3** | Security | Guard against Groq prompt injection with pre-filter & randomized delimiter tags | ✅ Resolved |
| **4** | **A4** | Security | Enforce fail-closed classifier normalization (`normalize_result`) with 0.70 threshold | ✅ Resolved |
| **5** | **A5** | Security | Harden active-thread detection against spoofing & unapproved thread history | ✅ Resolved |
| **6** | **A6** | Security | Eliminate ReDoS vulnerabilities in heuristic regexes & limit input length | ✅ Resolved |
| **7** | **A7** | Security | Defeat sensitive keyword evasion (NFKC, zero-width, Cyrillic/Greek homoglyphs, broad chargeback) | ✅ Resolved (`c75f0b5`) |
| **8** | **A8** | Security | Fail fast on startup & runtime safeguard if spaCy model is missing while AI keys active | ✅ Resolved (`8ec99a2`) |
| **9** | **A9** | Privacy | Integrate `phonenumbers` library, Luhn credit card check, and collision-safe tokens | ✅ Resolved |
| **10** | **A10** | Privacy | Contextualize technical terms whitelist to protect real surnames (Jenkins, Kafka, etc.) | ✅ Resolved |
| **11** | **A11** | Concurrency | Atomic SQLite idempotency check-and-claim to prevent multi-worker race conditions | ✅ Resolved |
| **12** | **A12** | Infrastructure | Run container as non-root `appuser`, fix data volume mounts, and honor `DATABASE_PATH` | ✅ Resolved |
| **13** | **A13** | Security | Hardened secrets handling: `override=False`, enforce `api.typesafe.ai` host, redact debug keys | ✅ Resolved |
| **14** | **A14** | Infrastructure | Pin exact dependency versions in `requirements.txt` and spaCy language model URL | ✅ Resolved |
| **15** | **B1** | Correctness | Refine signature stripper: RFC 3676, bare `--` code safety, bottom-up scan, safety size limit | ✅ Resolved (`8c13658`) |
| **16** | **B2** | Correctness | Remove generic business words from offline spam heuristics; route threats to manual review | ✅ Resolved |
| **17** | **B3** | Correctness | Tune sensitive keywords to intent phrases and establish single source in `config.yaml` | ✅ Resolved |
| **18** | **B4** | Correctness | Harmonize returned state with SQLite database and persist clean text for Phase 2 | ✅ Resolved |
| **19** | **B5** | Correctness | Resolve config relative to root, fail fast on invalid YAML, and honor environment overrides | ✅ Resolved |
| **20** | **B6** | Performance | Preload models and precompile regexes once at startup to eliminate per-email overhead | ✅ Resolved (`9646e04`) |
| **21** | **C1** | Testing | Expand synthetic benchmark validation to check all expected fields and default to offline | ✅ Resolved |
| **22** | **C2** | Testing | Isolate test suite from host environment variables (`.env`) for reproducible test runs | ✅ Resolved |
| **23** | **C3** | Testing | Ensure `scripts/jev_smoke_test.py` strictly verifies Jev response and exits non-zero on failure | ✅ Resolved |
| **24** | **C4** | Documentation | Reconcile README/ROADMAP test counts, directory trees, class names, and claim metrics | ✅ Resolved |

---

## Part A: Security and Privacy

### [A1] Mask Subject Line & Sender Address Before AI Egress
* **Status:** ✅ **Resolved**
* **Problem:** The PII masker currently masks only the email body. The raw subject line (which may contain names and credit cards) and raw sender email address are transmitted unmasked to Jev AI and Groq.
* **Solution:** 
  1. Mask `email_subject` in `pii_masker_node` using the same `token_map`, storing it as `masked_subject` in `TriageState`.
  2. Send `masked_subject` (never raw subject) to external classifiers. Fail closed to `manual_review` without calling external AI if `masked_subject` is missing.
  3. Send only the sender domain (e.g., `example.com`), omitting the personal username portion.
* **Done When:** Test feeds an email with subject PII and asserts external mocked API calls receive only redacted tokens and domain.

### [A2] Suppress Raw `token_map` from CLI and Logs
* **Status:** ✅ **Resolved**
* **Problem:** `main.py` prints the raw `token_map` dictionary in terminal output and logs, exposing real customer names, card numbers, and credentials.
* **Solution:** Remove `token_map` from CLI summaries. Display aggregate counts by entity type (e.g., `{"PERSON": 2, "EMAIL": 1}`) without plaintext values.
* **Done When:** Executing `python main.py --input data/sample_email.json` outputs zero plaintext PII in stdout/stderr.

### [A3] Prevent Groq LLM Prompt Injection Attacks
* **Status:** ✅ **Resolved**
* **Problem:** Unbounded email content is interpolated directly into Groq prompts. Adversarial emails with instructions (`Ignore previous instructions...`) can hijack the gatekeeper. `PROMPT_INJECTION_REGEX` only ran during offline fallback.
* **Solution:**
  1. Run `PROMPT_INJECTION_REGEX` on subject and body *before* invoking any AI; divert matches immediately to `manual_review`.
  2. Enclose customer email text in randomized boundary markers (`<email-XXXXXX>...</email-XXXXXX>`) with explicit system instructions to ignore internal directives.
  3. Strictly validate the returned JSON response structure.
* **Note on Benchmark Expectations:** Benchmark rows 91-99 and related gatekeeper tests currently assert `routing_status = 'spam_skipped'`. When A3 is implemented, their expected outcome will transition to `manual_review`.
* **Done When:** Tests verify that an adversarial injection payload diverts to `manual_review` without calling Groq, and that outgoing Groq prompts contain dynamic nonce tags.

### [A4] Fail-Closed Classifier Normalization
* **Status:** ✅ **Resolved**
* **Problem:** The gatekeeper fails open: unknown decisions default to `"legitimate"`, out-of-range confidence scores are accepted, and the confidence threshold (`llm.confidence_threshold` in config, default 0.70) is never enforced in code.
* **Solution:** Implement a unified `normalize_result(raw) -> dict` function:
  1. Unknown or malformed decisions default to `"manual_review"`.
  2. Confidence clamped to `[0.0, 1.0]` (NaN/None -> 0.0).
  3. If `is_threat` is True, force decision to at least `"manual_review"`.
  4. If decision is `"legitimate"` but confidence < `config["llm"]["confidence_threshold"]` (default 0.70), divert to `"manual_review"`.
* **Done When:** Table-driven unit test covers all edge cases (out-of-range confidence, unrecognized decision strings, threat flags).

### [A5] Harden Active-Thread Verification Against Spoofing
* **Status:** ✅ **Resolved**
* **Problem:** A spammer can send an initial email (caught as spam, marked done), then reply to the thread and have it classified as an active customer conversation. Empty senders match any address. Payloads can inject `is_active_thread: true`.
* **Solution:**
  1. Restrict SQL history queries strictly to `routing_status = 'gatekeeper_approved'`.
  2. Disallow empty sender matching; require non-empty exact equality.
  3. Initialize `is_active_thread = None` in initial state, relying solely on DB verification.
* **Done When:** Tests prove that spam threads, empty senders, and injected `is_active_thread: true` payloads all evaluate to `is_active_thread = False`.

### [A6] Eliminate ReDoS Backtracking in Heuristic Regexes
* **Status:** ✅ **Resolved**
* **Problem:** Patterns containing multiple `.*` with the `re.DOTALL` flag (such as `grandma.*read\s+me.*system\s+prompt` and spam phrases) trigger catastrophic backtracking on long inputs, stalling worker threads. Unbounded scans also allowed padding attacks to conceal payloads.
* **Solution:**
  1. Replaced unbounded `.*` / `.+` gaps with bounded gaps `.{0,200}` across `SPAM_REGEX`, `PROMPT_INJECTION_REGEX`, `nodes/signature_stripper.py` (`QUOTE_HEADERS`, `MOBILE_SIGS`, `GREETING_REGEX`), and upper bounded PII token quantifiers (`{14,256}`).
  2. Implemented shared `bounded_scan_text(text, head=10000, tail=2000)` helper that extracts the first `head` (10,000) and last `tail` (2,000) characters separated by newline, preventing ReDoS while neutralizing padding attacks at the tail. Made head and tail configurable under `security` in `config.yaml`.
  3. Ensured text sent externally or stored remains untouched (helper is strictly used for regex scans).
* **Done When:** Unit tests verify that adversarial 50 KB strings complete in < 0.05 seconds per regex step, padding attacks at the tail are detected as `manual_review`, and detection coverage remains 100% intact.

### [A7] Defeat Sensitive Keyword Evasion & Homoglyphs
* **Status:** ✅ **Resolved (`c75f0b5`)**
* **Problem:** Attackers could evade sensitive legal filters using Cyrillic/Greek homoglyphs (`pоlice`), zero-width spaces (`sub\u200bpoena`), full-width text (`ｓｕｂｐｏｅｎａ`), newlines (`legal\nnotice`), or spacing variations. The broad `chargeback` rule was missing.
* **Solution:**
  1. 4-step normalization pipeline: `unicodedata.normalize("NFKC")` -> strip zero-width characters -> `.casefold()` -> Cyrillic/Greek homoglyph map.
  2. Ephemeral guarantee: normalized text is used strictly for internal matching and never leaks to state, Jev, Groq, or DB.
  3. Regex phrase compilation with `re.split(r"[\s\-]+", kw)` and lookaround boundaries to preserve literal punctuation like `a.b(c)`.
  4. Inspection across `subject`, `cleaned_body`, and `raw_body`.
  5. Restored broad `\bchargebacks?\b` matching.
* **Note on Billing Intent:** `"Please refund my $20, I don't want to file a chargeback"` now routes to `Review/Sensitive` on purpose as a safe-side false positive due to the broad `\bchargebacks?\b` rule; this will be reduced via keyword scoring in B3.
* **Done When:** Unit tests verify diversion for all homoglyph, zero-width, full-width, spacing, and chargeback variants, and prove zero leakage of normalized text.

### [A8] Fail Fast on Startup & Runtime Safeguard for spaCy Failures
* **Status:** ✅ **Resolved**
* **Problem:** If spaCy fails to load (missing package, missing model, out-of-memory), the node currently logs a warning and proceeds, silently transmitting unmasked person names to external AI APIs.
* **Solution:**
  1. Startup: If external AI keys (Jev or Groq) are configured and spaCy fails to load, raise `RuntimeError` at startup to halt container initialization immediately. Load once and remember failure without retrying per email.
  2. Runtime safeguard: If the spaCy model is missing or unavailable at runtime while Jev or Groq is enabled, send nothing outside and divert the email to `manual_review` with `dispatch_status: "done"` and log warning with `email_id` only (no email content).
  3. Offline/no-keys fallback: If external AI is not enabled (no keys or `--offline`), keep working without spaCy but log exactly one warning at startup (`"names will only be masked by regex rules"`).
* **Done When:** Unit test mocking `spacy.load` to raise verifies that the pipeline refuses to boot with active API keys, runtime fallback routes to `manual_review` without external network calls, offline run logs exactly one warning, and spaCy available path is unchanged.

### [A9] Precision PII Regexes, Luhn Check & Token Nonces
* **Status:** ✅ **Resolved**
* **Problem:** Masker missed international phone numbers (`+44...`, `+880...`), truncated IBANs, JWTs, and API keys; falsely redacted 16-digit order numbers as credit cards without Luhn verification; corrupted text when customers quote earlier tokens like `[EMAIL_1]`.
* **Solution:**
  1. Integrated Google's `phonenumbers` library (`phonenumbers==9.0.41`). Always masks valid international phone numbers (`+...`); masks national-format numbers (no `+`) only if valid for configured `default_phone_region` (default `"US"`) and not preceded within ~18 chars by indicator keywords like `invoice`, `order`, `ticket`, `ref`, `id`, `no`, `#`, `tracking`.
  2. Implemented ISO/IEC 7812 Luhn checksum algorithm for 13-19 digit card candidates (`4111 1111 1111 1111` masked; `1234567890123456` unchanged).
  3. Added ISO 7064 Mod 97-10 IBAN validation (`GB82 WEST 1234 5698 7654 32` fully masked with zero partial leftovers).
  4. Added regex passes for JWTs, Google AIza (`AIza[0-9A-Za-z_\-]{35}`), OpenAI keys (`sk-(proj-)?[A-Za-z0-9_\-]{20,}`), Slack tokens (`xox[abpr]-...`), AWS keys (`AKIA...`), GitHub tokens (`gh[pousr]_...`), and password assignments (`password: ...`), executed before the phone pass so tokens aren't eaten by phone rules.
  5. Added IPv6 validation via `ipaddress.ip_address` and guarded IPv4 masking against version/build/release numbers (`"version 10.2.33.4"` stays unchanged).
  6. Implemented per-email 4-hex-char random nonce (`secrets.token_hex(2)`) for every token (e.g. `[EMAIL_1_a8f3]`), stored with `token_map["__nonce__"]` so subject and body share tokens and nonce without colliding with literal customer text like `[EMAIL_1]`.
  7. Updated consumers (`count_pii_entities` in `main.py`, `evaluate_sensitive` in `nodes/sensitive_skip.py`, `unmask_text`, and test suites).
* **Done When:** Table-driven test suite validates every PII type is redacted when valid and ignored when checksum/preceding-word rules apply; customer literal `[EMAIL_1]` survives round-trip; subject and body share tokens; egress invariant holds; all 129 tests and 100/100 benchmark pass.

### [A10] Contextualize Tech-Terms Whitelist (Surnames vs Tech)
* **Status:** ✅ **Resolved**
* **Problem:** Common surnames in the whitelist (Jenkins, Kafka, Helm, Apollo, Flask, Django) allowed customer names to be sent to external AI unmasked when signed alone or after a greeting/sign-off.
* **Solution:**
  1. Split `config/tech_terms.txt` into two tiers: `[unambiguous]` (infrastructure tools like Postgres, Kubernetes, Docker, always kept unmasked) and `[ambiguous]` (Jenkins, Kafka, Helm, Apollo, Flask, Django; no Ruby/Rust/Swift/Go).
  2. Implemented `load_tech_terms_tiers` returning `(unambiguous, ambiguous)` and updated `load_tech_terms_whitelist` to return the union for backward compatibility.
  3. Configured 26 technical context words under `privacy.tech_context_words` in `config.yaml` (`load_tech_context_words`).
  4. Context word adjacency rule: Ambiguous terms tagged as PERSON are kept unmasked ONLY if a technical context word is directly adjacent (within 2 words before or after, same sentence).
  5. Greeting/sign-off override: Lone ambiguous names directly after a greeting or sign-off (`Thanks, Jenkins`, `Hi Kafka,`, `Dear Mr. Helm`, `Regards,\nApollo`) are ALWAYS masked as PERSON.
  6. Exact whole-entity match preserved for multi-word entities (`Apollo Chen`, `Grafana Smith` are never whitelisted).
  7. Consistency Pass (Pass 9) updated to respect ambiguous context words and greeting overrides.
  8. Added `nlp_override` to `mask_pii` and `pii_masker_node` for deterministic logic tests independent of spaCy statistical NER quirks; added `@unittest.skipUnless(is_spacy_available(), ...)` guards to real-model tests.
* **Done When:** All logic tests and real-model tests pass; `"Thanks, Jenkins"` masked; `"Our Jenkins pipeline failed"` kept; `"Kafka broker unreachable"` kept; `"Hi Kafka,"` masked; `"Dear Mr. Helm"` masked; `"Please escalate to Apollo Chen"` masked; `"Grafana Smith"` masked; `"Postgres is down"` kept; `"Thanks, Jenkins. Our Jenkins pipeline failed"` sign-off masked and pipeline kept; case variations work; full pytest suite (154 passed) and offline benchmark (100/100) pass with zero row changes.

### [A11] Concurrency & Atomic SQLite Idempotency Locking
* **Status:** ✅ **Resolved**
* **Problem:** `check_and_acquire` executed a `SELECT` followed by an `INSERT`/`UPDATE` in separate statements. Concurrent worker threads raced and caused double processing, lost stale recoveries, or `sqlite3.IntegrityError` / `database is locked` crashes.
* **Solution:**
  1. For new emails: Single-statement `INSERT INTO email_triage ... ON CONFLICT(email_id) DO NOTHING` checking `cursor.rowcount == 1`.
  2. For stale lock recovery: Conditional `UPDATE email_triage SET status='processing', retry_count=retry_count+1, updated_at=?, routing_status='stale_recovery' WHERE email_id=? AND status='processing' AND updated_at < ? AND retry_count < ?` checking `cursor.rowcount == 1`.
  3. For retry-eligible failed emails: Conditional `UPDATE email_triage SET status='processing', retry_count=retry_count+1 ... WHERE email_id=? AND status='failed' AND retry_count < ?` checking `cursor.rowcount == 1`.
  4. Database connection resilience: Set `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;` on all connections. Caught lock collisions cleanly and treated lost races as `in_flight` / `already_completed` without leaking unhandled exceptions.
  5. Added standalone multiprocess/multithread verification tool `tools/check_concurrency.py`.
* **Done When:** Concurrency unit tests with 8 simultaneous threads across 30 trials (both new and stale locks) produce exactly 1 winner and 0 exceptions. Standalone tool `tools/check_concurrency.py` tests 4 processes and 8 threads across 30 trials and reports `RESULT: PASS`.

### [A12] Container Security & Environment File Locations
* **Status:** ✅ **Resolved**
* **Problem:** Docker container runs as `root`; compose mounts full repository read-write; `DATABASE_PATH` env var is ignored; `*.db` is copied into Docker image; documentation suggests `chmod 777 data`.
* **Solution:**
  1. **Non-Root User Hardening (`Dockerfile`):** Added non-root `appuser` (`useradd --create-home --uid 1000 --shell /bin/bash appuser`), created `/app/data` with ownership `chown -R appuser:appuser /app`, and set `USER appuser` before `CMD`.
  2. **Isolated Volume Mount (`docker-compose.yml`):** Removed insecure whole-repository mount `.:/app`; restricted mounts strictly to `./data:/app/data` to ensure container immutability and prevent host filesystem modification. Removed obsolete `version: "3.8"` tag.
  3. **Runtime Database Path Configuration (`docker-compose.yml`):** Set `DATABASE_PATH=/app/data/triage.db` in container environment, directing persistent SQLite records into the mounted volume.
  4. **Database Exclusion in Image Builds (`.dockerignore`):** Added `*.db`, `*.db-wal`, `*.db-shm`, and `data/*.db` to prevent baking host SQLite databases into Docker image layers.
  5. **Secure Host Permissions (`README.md`):** Replaced world-writable `chmod 777 data` advice with secure POSIX ownership: `chown -R 1000:1000 data`.
  6. **Dedicated Test Suite (`tests/test_a12_container_security.py`):** Added 5 unit tests validating non-root user creation, single-volume mounting, `.dockerignore` patterns, documentation advice, and `DATABASE_PATH` runtime override.
* **Done When:** Verified `docker compose run --rm email-triage whoami` outputs `appuser`, database generates inside `./data`, and 249 unit tests + 100/100 benchmark scenarios pass.

### [A13] Secrets Hardening & API Environment Controls
* **Status:** ✅ **Resolved**
* **Problem:** `load_dotenv(override=True)` overwrites production environment variables; arbitrary `JEV_API_URL` allows secret harvesting; smoke test prints partial API key; raw error response bodies are logged.
* **Solution:**
  1. Set `load_dotenv(override=False)`.
  2. Restrict allowed Jev/TypeSafe endpoints strictly to `api.typesafe.ai` (verified against `docs.typesafe.ai`, with localhost/test host exceptions).
  3. Redact API key characters in smoke test (print only `present` or `missing`).
  4. Log only HTTP status code on Jev API errors.
* **Done When:** Config loads without overriding existing environment; URLs not pointing to `api.typesafe.ai` (or local test hosts) are rejected; key secrets never appear in logs.

### [A14] Pin All Dependency Versions
* **Status:** ✅ **Resolved**
* **Problem:** `requirements.txt` had unpinned package versions allowing breaking upstream changes; `Dockerfile` downloaded unpinned spaCy model releases via dynamic `python -m spacy download en_core_web_sm`.
* **Solution:**
  1. Pinned exact versions (`==`) across all libraries in `requirements.txt` matching verified runtime environment (`pydantic==2.14.1`, `langgraph==1.2.16`, `langchain==1.4.6`, `langchain-groq==1.1.3`, `python-dotenv==1.2.4`, `pyyaml==6.0.3`, `spacy==3.8.16`, `requests==2.34.2`, `phonenumbers==9.0.41`).
  2. Pinned immutable direct release wheel URL for `en_core_web_sm-3.8.0` in `Dockerfile`.
  3. Added regression test suite `tests/test_a14_dependency_pinning.py` validating exact `==` pinning, prohibiting loose range specifiers (`>=`, `<=`, `~=`, bare names), and asserting Dockerfile model wheel URL pinning.
* **Done When:** Every entry in `requirements.txt` has exact `==` version pinning, `Dockerfile` pins the spaCy wheel, and all tests pass.

---

## Part B: Correctness

### [B1] Refine Signature Stripper & Prevent Real Text Loss
* **Status:** ✅ **Resolved (`8c13658`)**
* **Problem:** Top-down search deleted bug reports starting with *"Thanks."*; bare `--` stripped SQL queries; opening disclaimers were cut; no safety check prevented message deletion.
* **Solution:**
  1. Search for sign-offs bottom-up within the last 10 non-empty lines.
  2. Respect RFC 3676 `"-- "` with trailing space; allow bare `"--"` only if followed by <= 6 short lines and no code tokens (`SELECT`, `INSERT`, `;`, `{`, `}`, `=>`, `//`).
  3. Require substantive customer body prior to sign-offs (`has_substantive_body()`).
  4. Disclaimers at the top treated as customer text; bottom disclaimers require legal boilerplate terms.
  5. Direct safety size limit: stripping is aborted when it would remove more than half of the message AND the removed part looks like message body or the part before it has no substantive text (preserving the original text).
* **Done When:** Tests verify bug reports with opening "Thanks", SQL queries with `--`, disclaimers at top, and short 3-line emails are all preserved intact.

### [B2] Eliminate False Positives in Offline Spam Heuristics
* **Status:** ✅ **Resolved**
* **Problem:** Offline `SPAM_REGEX` matched ordinary words (`congratulations`, `paypal`, `docusign`, `norton`, `betting`, `"transfer of"`, `"prince \w+"`, `"cheap.*developers"`) and dumped valid customer emails straight into Junk. Threats and injections were handled inconsistently.
* **Solution:**
  1. Removed generic business single-words and weak patterns from `SPAM_REGEX` in `utils/jev_client.py`. Retained only multi-word unambiguous scam phrases (`claim your prize`, `you have won`, `verify your account`, `account (has been )?suspended`, `password (will )?expire`, `next of kin`, `inheritance`, `guaranteed returns`, `wire transfer .{0,60}(inheritance|lottery|prize)`, `no deposit`, `backlinks`, `guest post`, `pump and dump`, `act now limited time`, `awaiting your signature`, `document ready for signature`). All regex gap wildcards bounded to `.{0,60}` (never unbounded `.*`).
  2. Offline regex engine matches (`classifier_used == "regex"`) now produce `decision: "manual_review"` (`is_spam: True`, confidence 0.95), routing to `Review/Manual` rather than `spam_skipped` / `Junk/Spam`.
  3. External AI decisions (Jev and Groq) remain strictly preserved: live `decision: "spam"` still maps to `routing_status: "spam_skipped"`.
  4. Unified threat handling: any `is_threat: True` produces `decision: "manual_review"` across Jev AI, Groq LLM, regex pre-filters, and offline fallback.
  5. Default for unmatched clean emails remains `decision: "legitimate"` with confidence 0.85, approved offline.
  6. Updated benchmark expectations for rows 76-90 in `data/benchmark_emails.json` to `gatekeeper_decision: "manual_review"`, `dispatch_target: "Review/Manual"`, `routing_status: "manual_review"`. Zero benchmark spam rows end as approved.
* **Done When:** Unit tests verify customer emails mentioning PayPal, DocuSign, Norton, Prince George's County, cheap hosting, and betting API are approved offline (`gatekeeper_approved`), real spam samples divert to `manual_review`, mocked Jev spam routes to `spam_skipped`, and 100/100 benchmark scenarios pass.

### [B3] Consolidate Sensitive Keywords to Intent Phrases
* **Status:** ✅ **Resolved**
* **Problem:** Bare words (`gdpr`, `police`, `erasure`, `dsar`, `ccpa`) diverted normal sales and operational questions to legal review. Keyword list was duplicated across `nodes/sensitive_skip.py` and `config.yaml`.
* **Solution:**
  1. Replaced bare topic words with explicit actionable intent phrases in `config.yaml`:
     - Law enforcement: `"police report"`, `"contacted the police"`, `"contact the police"`, `"contacting the police"`, `"police investigation"`, `"filed a police"`, `"police department"`, `"alerted the police"`, `"report to the police"` (replacing bare `"police"`).
     - Privacy & regulatory: `"gdpr erasure request"`, `"right to erasure"`, `"right to be forgotten"`, `"under article 17"`, `"data subject access request"`, `"subject access request"`, `"dsar request"`, `"ccpa request"`, `"ccpa deletion request"`, `"do not sell my personal information"`, `"do not sell"` (replacing bare `"gdpr"`, `"erasure"`, `"dsar"`, `"ccpa"`).
  2. Established `config.yaml` (`privacy.sensitive_keywords`) as the SINGLE source of truth. Removed `DEFAULT_SENSITIVE_KEYWORDS` (38 items) from `nodes/sensitive_skip.py`, replacing with a tiny emergency fallback `EMERGENCY_SENSITIVE_KEYWORDS` (<= 5 high-risk phrases: `"subpoena"`, `"court order"`, `"lawsuit"`, `"formal chargeback"`, `"gdpr erasure request"`).
  3. Scoring deferred; chargeback stays broad on purpose (retaining `r"\bchargebacks?\b"` safe-side routing).
  4. Preserved A7 normalization (NFKC, zero-width removal, casefold, homoglyph translation, flexible whitespace/hyphen matching).
  5. Scenarios 61-75 in benchmark verified: 100% (15/15) still divert to `sensitive_diverted` with zero changes to expected benchmark values.
* **Done When:** Tests verify `"Is your product GDPR compliant?"`, `"Do you support erasure of old records?"`, and `"Our office is next to the police station, can you ship there?"` are not diverted, while explicit erasure requests under Article 17, police fraud reports, subpoenas, and chargebacks divert. Unit test proves keyword list is loaded only from config.

### [B4] Synchronize In-Memory State & SQLite Record
* **Status:** ✅ **Resolved**
* **Problem:** For approved emails, database row was marked `done` with `gatekeeper_approved`, but returned state claimed `dispatch_status: 'processing'`. Active thread was conflated with routing status (`active_thread_continuation`). Database write errors were swallowed or falsely claimed success. Phase 2 had no access to clean masked text in SQLite.
* **Solution:**
  1. **Schema Migration (`db/database.py`):** Added nullable columns `masked_subject TEXT`, `masked_body TEXT`, `is_active_thread INTEGER`, `gatekeeper_decision TEXT`, `gatekeeper_confidence REAL`, `classifier_used TEXT`. Idempotent migration in `_init_db` via `PRAGMA table_info(email_triage)` and `ALTER TABLE ... ADD COLUMN`. Defined `PersistenceError(Exception)` and raised if `cursor.rowcount == 0`.
  2. **Atomic Single-Path Persistence (`db/database.py`):** Consolidated all triage fields in `TriageDatabase.mark_done` into one `UPDATE` statement. Masked subject and body are persisted ONLY for `gatekeeper_approved` and `manual_review` (when `system.persist_masked_text: true` in `config.yaml`). Discarded/skipped emails (`spam_skipped`, `sensitive_diverted`) and `persist_masked_text: false` store `NULL`. `token_map` and raw PII are never persisted.
  3. **State & DB Harmonization (`nodes/jev_gatekeeper.py`):** Approved emails return `dispatch_status: "done"`, `routing_status: "gatekeeper_approved"`, and `is_active_thread: bool`. Removed `"active_thread_continuation"` routing status entirely across code, ingest node (`routing_status: "processing"`), benchmark, and tests.
  4. **Consolidated Helper & Fail-Safe Routing (`nodes/jev_gatekeeper.py`):** Replaced duplicate outcome blocks with private helper `_record_and_build_gatekeeper_result`. If `mark_done` fails, logs exception class name and `email_id` only (zero email text), attempts best-effort `db.mark_failed`, and returns `routing_status: "persist_failed"`, `dispatch_status: "failed"`, `error_message: "database write failed"`. Updated `should_route_after_gatekeeper` to return `"end"` if `dispatch_status == "failed"` or `routing_status == "persist_failed"`. Identical safe DB error handling applied in `nodes/sensitive_skip.py`.
  5. **Benchmark Harmonization (`data/benchmark_emails.json`):** Updated rows 51-60 to expect `routing_status: "gatekeeper_approved"`, `is_active_thread: true`, `dispatch_status: "done"`.
* **Done When:** Unit tests verify returned state and database row match identically (`gatekeeper_approved` + `done`), DB write failures route to `persist_failed` / `failed` and stop router, schema migration preserves existing rows, and 100/100 benchmark scenarios pass.

### [B5] Fail-Fast Config Loader & Environment Variable Overrides
* **Status:** ✅ **Resolved**
* **Problem:** `config.yaml` was resolved relative to working directory, causing failures when run from subdirectories. Config errors and missing files were caught and silently swallowed with empty `{}` across database, ingest, PII masking, sensitive-skip, and Jev client modules. Certain environment variable overrides were ignored.
* **Solution:**
  1. **Root-Anchored Paths (`utils/config.py`):** Defined `BASE_DIR = Path(__file__).resolve().parent.parent` and `DEFAULT_CONFIG_PATH = BASE_DIR / "config.yaml"`. Any relative config path argument or relative path within config (`system.database_path`, `privacy.tech_terms_file`) is resolved against `BASE_DIR`.
  2. **Comprehensive Validation & ConfigError (`utils/config.py`):** Defined `ConfigError(ValueError)`. Added strict section and field validation rejecting unknown keys (typo protection), disallowing booleans for integers, enforcing boundary rules (e.g. `0 < lo < hi < 1.0`, `0 < confidence <= 1.0`, `0 <= temp <= 2.0`), and formatting YAML errors without leaking file content or secrets.
  3. **Runtime Environment Overrides (`utils/config.py`):** Applied `DATABASE_PATH`, `IDEMPOTENCY_STALE_MINUTES` (`int > 0`), and `MAX_DISPATCH_RETRIES` (`int >= 0`) with strict precedence (`env > config.yaml`). Empty or unset values preserve config defaults; invalid values raise `ConfigError` naming the variable. Documented precedence in `.env.example` and `README.md`.
  4. **Eliminated All Silent Swallows:** Removed all 13 `try ... load_config() ... except Exception: config = {}` and fallback swallows across `db/database.py`, `nodes/ingest.py`, `nodes/pii_masker.py`, `nodes/sensitive_skip.py`, and `utils/jev_client.py`. Config errors now propagate cleanly as `ConfigError`.
  5. **Startup Fail-Fast (`main.py`):** Evaluated and validated config as the very first operation in `main()`. On `FileNotFoundError` or `ConfigError`, prints `[-] Configuration error: <message>` to `stderr` and exits immediately with code `2` with zero traceback and zero DB creation.
* **Done When:** Table-driven unit tests verify invalid YAML/types/typos raise `ConfigError`, CWD-independent resolution passes, env overrides take effect and flow into nodes, 13 swallows confirmed removed, and 221 unit tests + 100/100 benchmark scenarios pass.

### [B6] Optimize Process Lifecycle & Eliminate Repeated Work
* **Status:** ✅ **Resolved (`9646e04`)**
* **Problem:** spaCy model is repeatedly re-attempted on failure; `load_config()` reads YAML from disk on every email; regex patterns are recompiled on every invocation; LangGraph pipeline rebuilt per email in `process_single_email`.
* **Solution:**
  1. **Thread-Safe Config Caching (`utils/config.py`):** Added `get_config()` loading and validating once per process under a mutex lock; added `reset_config_cache()`; `load_config()` stays uncached; eliminated all per-email `load_config()` calls across `nodes/ingest.py`, `nodes/pii_masker.py`, `nodes/sensitive_skip.py`, `nodes/jev_gatekeeper.py`, `db/database.py`, `utils/jev_client.py`, and `main.py`.
  2. **Keyword Pattern Caching (`nodes/sensitive_skip.py`):** Added `get_compiled_keyword_patterns(keywords)` caching compiled regex tuples under a lock with `reset_keyword_patterns_cache()`.
  3. **spaCy Per-Model Caching (`nodes/pii_masker.py`):** Cache per model name in `_SPACY_MODELS`, remember failures in `_SPACY_FAILED_MODELS` without retrying; thread-safe tech terms tiers and context words caching.
  4. **Shared Default JevClient (`utils/jev_client.py` & `nodes/jev_gatekeeper.py`):** Reuse one lazily created, thread-safe, process-wide `JevClient` via `get_default_client()` with `reset_default_client()`, preserving the A13 session-wide 401 disable state across all emails.
  5. **Pipeline Reuse & Warmup (`pipeline.py` & `main.py`):** `process_single_email` compiles pipeline once; added `prepare_runtime(offline=...)` preloading config, keyword regexes, tech terms, spaCy, and default client at startup.
* **Done When:** Verified 100/100 benchmark equivalence against pre-B6 baseline (0 diff between `/tmp/b6_before.json` and `/tmp/b6_after.json`); average benchmark latency reduced by 57% (from 68.8ms to 29.7ms/email); unit test suite expanded to 229 tests including concurrency (8 threads) and lifecycle count tests (`yaml.safe_load == 1`, `spacy.load == 1`, `re.compile("subpoena") == 1`, `JevClient <= 1`).

---

## Part C: Tests and Documentation

### [C1] Comprehensive Benchmark Validation & Offline Default
* **Status:** ✅ **Resolved**
* **Problem:** Benchmark runner only validated 5 fields, ignoring discrepancies in `dispatch_status`, `is_threat`, etc. Benchmark defaulted to live API keys. Duplicate test faked state with manual `db.mark_done()`.
* **Solution:**
  1. **Comprehensive Field Assertions (`main.py`):** Replaced hardcoded 5-field checks with a full loop checking 100% of keys in each scenario's `expected` dictionary (`routing_status`, `routing_status_in`, `dispatch_status`, `dispatch_target`, `gatekeeper_decision`, `is_active_thread`, `is_sensitive`, `is_spam`, `is_threat`).
  2. **Safe Default Offline Mode & `--live` Flag (`main.py`):** Defaulted CLI execution to `offline = True` unless `--live` is explicitly passed. Preserved `--offline` argument for backward compatibility.
  3. **Natural Duplicate Delivery (`main.py` & `tests/test_pipeline_e2e.py`):** Removed artificial `db.mark_done(...)` state tampering; transmitted payload once through the pipeline naturally, allowing subsequent benchmark invocation to verify true idempotency deduplication.
  4. **Benchmark Harmonization (`data/benchmark_emails.json`):** Aligned scenarios 51-60 with post-A5 security architecture where active threads are evaluated by the gatekeeper rather than bypassed (removed stale `gatekeeper_confidence: 1.0`).
* **Done When:** All 100 benchmark scenarios pass with 100% of expected fields asserted; `--live` flag verified; natural duplicate retransmission verified; 232 pytest unit tests pass.

### [C2] Deterministic Test Environment Isolation
* **Status:** ✅ **Resolved**
* **Problem:** Tests make live calls to external APIs if host `.env` file contains keys, causing flaky tests, rate-limiting, and test data leaks.
* **Solution:**
  1. **Network Egress Guard (`tests/conftest.py`):** Patched `requests.adapters.HTTPAdapter.send`, `httpx.HTTPTransport.handle_request`, `httpx.AsyncHTTPTransport.handle_async_request`, and `socket.socket.connect` to block all unmocked outbound WAN calls with `NetworkEgressBlockedError` while allowing loopback interfaces (`127.0.0.1`, `localhost`, `::1`).
  2. **Hermetic Environment Shield (`tests/conftest.py`):** Added an `autouse=True` fixture `isolate_test_environment` that strips ambient external AI credentials (`JEV_API_KEY`, `GROQ_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `LANGCHAIN_API_KEY`, `LANGSMITH_API_KEY`) from `os.environ` by default and resets singleton caches (`reset_config_cache()`, `reset_default_client()`) before and after each test.
  3. **Unit Test Hardening (`tests/test_jev_client.py`):** Decorated `test_placeholder_key_skips_jev` with `@patch.dict(os.environ, {"JEV_API_KEY": "", "GROQ_API_KEY": ""})` to isolate `key=None` tests under standalone/unittest runners.
  4. **Dedicated Isolation Suite (`tests/test_c2_isolation.py`):** Added 7 comprehensive unit tests verifying unmocked `requests`, `httpx`, and raw socket WAN attempts are caught and blocked, loopback connections remain permitted, ambient credentials are stripped, and offline pipelines with dummy keys run without network egress.
* **Done When:** Verified full test suite (239 tests) passes deterministically with real keys injected into environment (`JEV_API_KEY="sk_live_super_secret" GROQ_API_KEY="gsk_live_super_secret"`), `tools/egress_check.py` verifies zero network egress, and 100/100 benchmark scenarios pass in ~21.5ms/email.

### [C3] Strict Jev Smoke Test Verification
* **Status:** ✅ **Resolved**
* **Problem:** `scripts/jev_smoke_test.py` reports success even if Jev returns 401 or 500 and falls back to offline heuristics.
* **Solution:**
  1. **Strict Classifier Engine Assertion (`scripts/jev_smoke_test.py`):** Explicitly check `result.get("classifier_used") == "jev"`. If Jev returns HTTP 401, 500, times out, or fails closed to Groq/regex fallback (`classifier_used != "jev"`), print a clear error detailing the fallback engine used and exit with code 1 (`sys.exit(1)`).
  2. **Preserve Missing Key Guidance (`scripts/jev_smoke_test.py`):** When no key or placeholder is detected, continue printing guidance and exit with code 0 (`sys.exit(0)`).
  3. **Dedicated Test Suite (`tests/test_c3_smoke_test.py`):** Added 5 unit tests validating that HTTP 401, HTTP 500, and network timeouts each raise `SystemExit(1)` and report failures, valid Jev HTTP 200 responses succeed, and missing keys exit with code 0.
* **Done When:** Running smoke test with an invalid key outputs failure message (`[-] Smoke test FAILED: TypeSafe System One (Jev) API did not produce decision`) and exits with returncode 1; 244 unit tests and 100/100 benchmark scenarios pass.

### [C4] Documentation Synchronization & Metric Accuracy
* **Status:** ✅ **Resolved**
* **Problem:** Test counts in README/ROADMAP are outdated; file tree omits test modules; unbacked marketing claims exist (`enterprise-grade`, `sub-second`); dual naming (`JevClient` vs `JevAIClient`).
* **Solution:**
  1. **Synchronize Test & Benchmark Metrics (`README.md`):** Updated unit test counts from 61 to 244 (100% passing) and synthetic benchmark count from 10 to 100 scenarios. Documented safe default `--offline` mode and explicit `--live` flag.
  2. **Comprehensive File Tree Expansion (`README.md`):** Updated repository tree to include all 16 test files in `tests/`, `scripts/jev_smoke_test.py`, `tools/check_concurrency.py`, `tools/egress_check.py`, and `check.sh`.
  3. **Unify Canonical Client Naming (`pipeline.py` & `utils/jev_client.py`):** Replaced `JevAIClient` with `JevClient` in `pipeline.py` imports, type annotations, and docstrings; maintained `JevAIClient = JevClient` as an explicit backward-compatibility alias in `utils/jev_client.py`.
  4. **Replace Unbacked Buzzwords with Empirical Benchmarks (`README.md`):** Removed unbacked marketing claims (`enterprise-grade`, `sub-second`) in favor of descriptive architecture (`local-first, privacy-preserving`) and measured performance metrics (low latency with local heuristic fallback; ~22ms/email average benchmark throughput).
* **Done When:** Every metric, diagram, and code reference in documentation matches codebase reality; 244 automated unit tests and 100/100 benchmark scenarios pass with 0 row changes. Part C is 100% complete.

---

## Part D: Phase 2 — Deep Classification & Downstream Dispatch Automation

Phase 2 builds upon the hardened, local-first foundation delivered in Phase 1. It consumes sanitized, privacy-vetted, gatekeeper-approved emails and intelligently routes them to external business destinations (GitHub, FreeScout, CRM, Webhook Alerts) with fail-safe Human-in-the-Loop review gating, an Outbox dispatch ledger, and strict idempotency protection.

### 1. Phase 1 Termination & State Handoff Trace

To guarantee strict architectural isolation and zero regressions, Phase 1 has a concrete, verified boundary:

* **Git Commit Anchor:** Terminated and delivered at Commit `020db77` (`chore: make check.sh executable`), preceded by `a609589` (`chore: final pre-delivery fixes, dev dependencies, batch execution, and metric accuracy`). All 24 remediation issues (A1–A14, B1–B6, C1–C4) are closed and verified with 265 passing tests.
* **Execution Boundary:** Pipeline execution concludes after Node 05 (`jev_gatekeeper_node`). Nodes 01 through 05 (`ingest` -> `signature_stripper` -> `pii_masker` -> `sensitive_skip` -> `jev_gatekeeper`) handle intake, normalization, sanitization, and safety approval.
* **Data Handoff Contract:** Approved records reside in the SQLite database specified by `config["system"]["database_path"]` (default `triage.db` in project root; `/app/data/triage.db` only in Docker via `DATABASE_PATH` environment variable override applied in `utils/config.py`) inside the `email_triage` table with:
  - `status = 'done'`
  - `routing_status = 'gatekeeper_approved'`
  - `gatekeeper_decision = 'legitimate'`

* **Real Persisted Handoff Schema from `db/database.py`:**
  The `email_triage` table consists of exactly the following 17 columns defined in `TriageDatabase._init_db`:
  ```sql
  CREATE TABLE email_triage (
      email_id TEXT PRIMARY KEY,
      message_id TEXT,
      thread_id TEXT,
      sender_email TEXT,
      status TEXT NOT NULL CHECK(status IN ('processing', 'done', 'failed')),
      retry_count INTEGER DEFAULT 0,
      routing_status TEXT,
      dispatch_target TEXT,
      error_message TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      masked_subject TEXT,
      masked_body TEXT,
      is_active_thread INTEGER,
      gatekeeper_decision TEXT,
      gatekeeper_confidence REAL,
      classifier_used TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_thread_id ON email_triage(thread_id);
  CREATE INDEX IF NOT EXISTS idx_status ON email_triage(status);
  ```

* **Crucial Schema Invariants & Constraints:**
  1. **No `sender_domain` Column:** The `email_triage` table has **NO** `sender_domain` column. Sender domain is derived dynamically at runtime from `sender_email` via `sender_email.split("@")[-1]` or `email.utils.parseaddr(sender_email)[1].split("@")[-1]`.
  2. **Allowed `classifier_used` Values:** In Phase 1, `classifier_used` records the gatekeeper engine decision. Permitted values are strictly restricted to `"jev"`, `"groq"`, and `"regex"` (Phase 1 heuristic regex fallback, not `"offline_heuristic"`).
  3. **Strict Status Constraint:** `status` has a SQLite CHECK constraint: `CHECK(status IN ('processing', 'done', 'failed'))`. Writing values like `'processing_p2'`, `'p2_done'`, `'dispatched'`, or `'hitl_pending'` directly to `email_triage` will cause SQLite constraint violations (`IntegrityError`) and crash the application.
  4. **Active Thread Continuity Invariant (A5 Security):** `db/database.py` evaluates ongoing thread context via `get_active_thread_records(thread_id)` using the exact query:
     ```sql
     SELECT * FROM email_triage
     WHERE thread_id = ? AND routing_status = 'gatekeeper_approved'
     ORDER BY updated_at DESC
     ```
     If Phase 2 were to overwrite `routing_status` with `'dispatched'` or `'hitl_pending'`, subsequent emails in the same conversation thread would fail the A5 thread history check and participant validation.
  5. **Phase 1 Idempotency Preservation:** Intake queries (`claim_processing`) verify whether an email is already completed via `status == 'done'`.
  6. **Zero-Touch Policy on `email_triage`:** Because of constraints 3, 4, and 5, **Phase 2 must NOT modify or overwrite any columns or values in `email_triage`.** The `email_triage` table is strictly READ-ONLY during Phase 2.

* **Dedicated Phase 2 State Architecture (`p2_jobs` & `p2_dispatch_log`):**
  To maintain 100% backward compatibility and preserve all Phase 1 invariants, Phase 2 introduces two dedicated tables via an idempotent migration in `TriageDatabase._init_db`:

  ```sql
  -- Phase 2 Processing State and HITL Lifecycle
  CREATE TABLE IF NOT EXISTS p2_jobs (
      email_id TEXT PRIMARY KEY REFERENCES email_triage(email_id),
      state TEXT NOT NULL CHECK(state IN (
          'unclaimed', 'claimed', 'hitl_pending', 'hitl_resolved',
          'dispatching', 'done', 'failed', 'dead_letter'
      )),
      worker_id TEXT,
      claimed_at TEXT,
      attempts INTEGER DEFAULT 0,
      category TEXT,
      priority TEXT,
      sentiment TEXT,
      customer_emotion TEXT,
      summary TEXT,
      suggested_team TEXT,
      confidence REAL,
      p2_classifier_used TEXT,
      hitl_status TEXT DEFAULT 'none' CHECK(hitl_status IN (
          'none', 'pending', 'approved', 'rejected', 'overridden'
      )),
      hitl_notes TEXT,
      reviewed_by TEXT,
      reviewed_at TEXT,
      dispatch_target TEXT,
      error_message TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_p2_jobs_state ON p2_jobs(state);
  CREATE INDEX IF NOT EXISTS idx_p2_jobs_claimed ON p2_jobs(claimed_at);

  -- Phase 2 Outbox Pattern Dispatch Ledger
  CREATE TABLE IF NOT EXISTS p2_dispatch_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email_id TEXT NOT NULL REFERENCES email_triage(email_id),
      destination TEXT NOT NULL,
      action_type TEXT NOT NULL,
      idempotency_key TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL CHECK(state IN (
          'pending', 'sent', 'confirmed', 'unknown', 'failed'
      )),
      remote_id TEXT,
      error_message TEXT,
      attempt_number INTEGER DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_p2_dispatch_idempotency ON p2_dispatch_log(idempotency_key);
  CREATE INDEX IF NOT EXISTS idx_p2_dispatch_email ON p2_dispatch_log(email_id);
  ```

* **Preservation Verification Test Requirement:**
  Automated tests in `tests/test_p2_worker.py` and `tests/test_p2_pipeline_e2e.py` must explicitly verify:
  1. Throughout the full Phase 2 lifecycle (claiming, classifying, HITL review, dispatching, and completion), `email_triage.status` remains `'done'` and `routing_status` remains `'gatekeeper_approved'`.
  2. A5 thread history queries (`get_active_thread_records`) and thread participant validation continue to return expected records before, during, and after Phase 2 completion.
  3. Intake duplicate checks (`claim_processing`) continue to recognize previously processed emails as `'already_completed'`.

* **Strict Privacy Invariant:**
  - **`token_map` is NEVER persisted to SQLite or passed across process boundaries.**
  - All Phase 2 intelligence classification and external adapter formatting operate strictly on `masked_subject` and `masked_body`.
  - Downstream systems requiring raw customer PII (e.g. creating a real FreeScout ticket) re-fetch original text from the authorized mailbox API using `message_id` (via P2-12).

---

### 2. Phase 2 Pipeline Topology & Node Architecture

```
[Phase 1 Handoff: email_triage (gatekeeper_approved)]
                         │
                         ▼
           ┌───────────────────────────┐
           │   p2_jobs Intake/Claim    │ ◄── Atomic row claiming & crash recovery
           └─────────────┬─────────────┘
                         │
                         ▼
           ┌───────────────────────────┐
           │    Node 06: Classifier    │ ──► Deep LLM / Heuristic Ensemble
           │(10 Categories, Sentiment, │     - Reuses A3 delimiters & injection pre-filter
           │ Emotion, Priority)        │     - Reuses A4 fail-closed normalize_classification
           └─────────────┬─────────────┘     - Reuses A6 length bounds & A13 host allowlist
                         │
                         ▼
           ┌───────────────────────────┐
           │   Node 07: HITL Gating    │ ──► Triggers: confidence < 0.85, angry/frustrated
           └──────┬─────────────┬──────┘     high priority, Security/Account, or unmapped.
                  │             │
    (Review Req.) │             │ (Auto-Approved >= 0.85)
                  ▼             │
     ┌───────────────────────┐  │
     │  p2_jobs hitl_pending │  │
     │  CLI: hitl_cli.py     │  │
     │  (approve / override) │  │
     └────────────┬──────────┘  │
                  │             │
      (Resolved)  └──────┐      │
                         ▼      ▼
           ┌───────────────────────────┐
           │   Node 08: Dispatcher     │ ──► Multi-Destination Router & Safety Rails
           │ (Outbox Ledger & Checks)  │     - dispatch.dry_run (default: true)
           └─────────────┬─────────────┘     - Global kill switch & daily caps
                         │                   - Persists 'pending' to p2_dispatch_log
                         │                   - Resolves 'unknown' via remote query
          ┌──────────────┼──────────────┬──────────────┐
          ▼              ▼              ▼              ▼
   ┌──────────────┐┌──────────────┐┌──────────────┐┌──────────────┐
   │ GitHub Issue ││  FreeScout   ││   CRM Lead   ││ Webhook Node │
   │   Adapter    ││ Ticket Node  ││  Ingestion   ││ (Disputes &  │
   │ (Bugs/Feat)  ││ (CS Support) ││ (Sales/Demo) ││ Crit Outage) │
   └──────────────┘└──────────────┘└──────────────┘└──────────────┘
          │              │              │              │
          └──────────────┴──────┬───────┴──────────────┘
                                ▼
                   ┌──────────────────────────┐
                   │    p2_dispatch_log       │ ──► State: confirmed / failed
                   │    p2_jobs (done)        │     (email_triage untouched)
                   └──────────────────────────┘
```

---

### 3. Phase 2 Modular Commit Roadmap Matrix

| # | Code | Track | Commit Description | Target Files | Status |
|:---:|:---:|:---|:---|:---|:---:|
| **0** | **P2-00** | Track 0 | `docs(decisions): [P2-00] phase 2 architectural decisions, client alignment questionnaire, and destination data policies` | `docs/phase2_decisions.md`, `ROADMAP.md` | ✅ Complete |
| **1** | **P2-01** | Track 1 | `feat(classifier): [P2-01] deep LLM intent, category, and sentiment classifier node with phase 1 guardrails` | `nodes/classifier.py`, `utils/classifier_client.py`, `state.py`, `config.yaml`, `tests/test_p2_classifier.py`, `tests/test_p2_egress.py` | ✅ Complete |
| **2** | **P2-02** | Track 1 | `feat(hitl): [P2-02] human-in-the-loop review queue, state gating, and reviewer cli interface` | `nodes/hitl_queue.py`, `scripts/hitl_cli.py`, `db/database.py`, `config.yaml`, `tests/test_p2_hitl.py` | ✅ Complete |
| **3a** | **P2-03a** | Track 2 | `feat(dispatch): [P2-03a] dispatcher foundations, base adapter contract, and outbox ledger` | `utils/adapters/__init__.py`, `utils/adapters/base.py`, `db/database.py`, `config.yaml`, `utils/config.py`, `state.py`, `tests/test_p2_dispatch_foundations.py`, `docs/ARCHITECTURE.md`, `docs/phase2_decisions.md`, `ROADMAP.md`, `README.md` | ✅ Complete |
| **3b** | **P2-03b** | Track 2 | `feat(dispatch): [P2-03b] multi-destination dispatcher router node, rate caps, and circuit breakers` | `nodes/dispatcher.py`, `nodes/__init__.py`, `tests/test_p2_dispatcher.py`, `ROADMAP.md`, `docs/ARCHITECTURE.md`, `README.md` | ✅ Complete |
| **4a** | **P2-04a** | Track 2 | `feat(adapters): [P2-04a] github issues contract, fixtures, formatting, and config schema` | `docs/contracts/github_issues.md`, `tests/fixtures/github/*.json`, `utils/adapters/github_format.py`, `config.yaml`, `utils/config.py`, `.env.example`, `tests/test_p2_github_format.py`, `docs/ARCHITECTURE.md`, `ROADMAP.md`, `README.md` | ✅ Complete |
| **4b** | **P2-04b** | Track 2 | `feat(adapters): [P2-04b] github issues adapter with deduplication precheck and retry` | `utils/adapters/github_adapter.py`, `utils/adapters/__init__.py`, `tests/test_p2_github_adapter.py`, `docs/ARCHITECTURE.md`, `ROADMAP.md`, `README.md` | ✅ Complete |
| **5** | **P2-05** | Track 2 | `feat(adapters): [P2-05] freescout helpdesk adapter with universal selective unmasking and thread continuity` | `utils/unmasker.py`, `utils/adapters/freescout_adapter.py`, `utils/adapters/freescout_format.py`, `docs/contracts/freescout.md`, `tests/fixtures/freescout/*.json`, `config.yaml`, `utils/config.py`, `utils/adapters/__init__.py`, `tests/test_p2_unmasker.py`, `tests/test_p2_freescout_format.py`, `tests/test_p2_freescout_adapter.py`, `scripts/check_p2_05.py` | ✅ Complete |
| **6** | **P2-06** | Track 2 | `feat(adapters): [P2-06] crm lead ingestion adapter with output hardening and lead scoring` | `utils/adapters/crm_adapter.py`, `utils/adapters/crm_format.py`, `docs/contracts/crm_hubspot.md`, `tests/fixtures/crm/*.json`, `config.yaml`, `utils/config.py`, `utils/adapters/__init__.py`, `tests/test_p2_crm_format.py`, `tests/test_p2_crm_adapter.py`, `scripts/check_p2_06.py` | ✅ Complete |
| **7** | **P2-07** | Track 2 | `feat(adapters): [P2-07] webhook alert adapter with hmac signing and dual formatting` | `utils/adapters/webhook_adapter.py`, `utils/adapters/webhook_format.py`, `docs/contracts/webhook_alert.md`, `tests/fixtures/webhook/*.json`, `config.yaml`, `utils/config.py`, `utils/adapters/__init__.py`, `tests/test_p2_webhook_format.py`, `tests/test_p2_webhook_adapter.py`, `scripts/check_p2_07.py`, `.env.example`, `docs/ARCHITECTURE.md`, `README.md` | ✅ Complete |
| **8** | **P2-08** | Track 3 | `feat(pipeline): [P2-08] end-to-end langgraph phase 2 graph compilation and dispatch handoff` | `pipeline.py`, `tests/test_p2_pipeline_e2e.py`, `scripts/check_p2_08.py`, `docs/ARCHITECTURE.md`, `README.md` | ✅ Complete |
| **9** | **P2-09** | Track 3 | `feat(worker): [P2-09] persistent phase 2 queue worker, atomic claiming, and crash recovery` | `scripts/phase2_worker.py`, `db/database.py`, `tools/run_worker.sh`, `tests/test_p2_worker.py` | ✅ Complete |
| **10** | **P2-10** | Track 3 | `feat(testing): [P2-10] phase 2 synthetic benchmark dataset, failure-injection suite, and adapter contracts` | `data/benchmark_phase2.json`, `main.py`, `tests/test_p2_benchmark.py`, `tests/test_p2_failure_injection.py`, `tests/test_p2_adapter_contracts.py`, `scripts/*_smoke_test.py` | ✅ Complete |
| **11** | **P2-11** | Track 3 | `docs(phase2): [P2-11] complete phase 2 documentation, architecture diagrams, and operator runbooks` | `README.md`, `ROADMAP.md`, `docs/architecture_phase2.md`, `docs/hitl_runbook.md`, `tests/test_p2_documentation.py` | ✅ Complete |
| **12** | **P2-12** | Track 4 | `feat(mailbox): [P2-12] gmail pub/sub mailbox connector, auth lifecycle, and original text re-fetch` | `utils/mailbox/gmail_connector.py`, `utils/mailbox/base.py`, `scripts/renew_mailbox_watch.py`, `config.yaml`, `.env.example`, `tests/test_p2_mailbox_connector.py` | ✅ Complete |

---

### 4. Detailed Specifications for Commits P2-00 through P2-12

#### [P2-00] Phase 2 Architectural Decisions, Client Alignment Questionnaire, and Destination Data Policies
* **Status:** ✅ Complete (Delivered in `docs/phase2_decisions.md`)
* **Scope:** `docs/phase2_decisions.md`, `ROADMAP.md`
* **Problem:** Key architectural, operational, and data privacy policies must be decided in writing before writing downstream adapter code. In particular, `config.yaml` currently sets `use_masked_text_only: false` for Support, Sales, and Billing, creating an ambiguity between the Phase 1 masked invariant and downstream requirements.
* **Solution:**
  1. Record definitive destination data policy:
     - **Engineering (GitHub):** Strictly `use_masked_text_only: true`. Public or shared engineering repositories receive sanitized, masked text only.
     - **Support (FreeScout), Sales (CRM), Billing (Webhook):** Record whether these systems operate on masked text or authorized original text re-fetched from the mailbox via `message_id` (P2-12).
  2. Masked Text Retention Policy: Define SQLite retention schedule for `masked_subject` and `masked_body` in `email_triage` (e.g. rolling 30/90-day retention with scheduled purge script, vs permanent audit retention).
  3. Dry-Run Policy: Set default `dispatch.dry_run: true`. Document operational protocol for promoting dry-run staging to live delivery.
  4. Daily Rate Limits & Cap Policies: Define per-destination daily dispatch limits (e.g., GitHub: 200 issues/day, FreeScout: 1,000 tickets/day, CRM: 500 leads/day, Webhook: 200 alerts/day) to prevent API quota exhaustion and alert storms.
  5. Classifier Model Selection: Record model configuration (`llm.classifier_model: "openai/gpt-oss-120b"` on Groq), temperature (0.1 for high determinism), and token budgets.
  6. Document Mandatory Client Questionnaire (must be confirmed before starting P2-04):
     - Question 1: Should FreeScout and CRM receive re-fetched unmasked customer names/emails or remain masked?
     - Question 2: What are the exact GitHub repository owner/repo and required project labels?
     - Question 3: What CRM system (HubSpot, Salesforce, Pipedrive, custom webhook) is the primary target?
     - Question 4: What is the primary incident webhook target (Slack incoming webhook, PagerDuty, Discord)?
     - Question 5: What is the desired alert escalation policy for critical infrastructure outages?
     - Question 6: What are the daily volume quotas and budget constraints for Groq API classification calls?
* **Done When:** `docs/phase2_decisions.md` is fully drafted and reviewed, capturing all policies and questionnaire items.

#### [P2-01] Deep LLM Intent, Category, and Sentiment Classifier Node with Phase 1 Guardrails
* **Status:** ✅ Complete
* **Scope:** `nodes/classifier.py`, `utils/classifier_client.py`, `state.py`, `config.yaml`, `tests/test_p2_classifier.py`, `tests/test_p2_egress.py`
* **Problem:** Approved emails lack deep semantic classification. Downstream systems cannot distinguish between bug reports, sales inquiries, billing disputes, complaints, and critical infrastructure outages. Furthermore, the classifier must not introduce prompt injection vulnerabilities or bypass Phase 1 security guardrails.
* **Solution:**
  1. Implement `classifier_node(state: TriageState) -> dict` consuming `masked_subject` and `masked_body`, populating `state["classification"]` with an `EmailClassification` object.
  2. Implement `EmailClassification` schema in `state.py`:
     - `category`: `Bug Report`, `Feature Request`, `Demo Request`, `Pricing Inquiry`, `Billing Issue`, `Refund Request`, `Security/Account`, `Complaint`, `General Query`, `Other`.
     - `priority`: `Critical`, `High`, `Medium`, `Low`.
     - `sentiment`: `Positive`, `Neutral`, `Negative`.
     - `customer_emotion`: `Calm`, `Frustrated`, `Angry` (explicitly separated from sentiment).
     - `summary`: One-sentence concise executive summary.
     - `suggested_team`: `Engineering`, `Sales`, `Billing`, `Support`, `Security`.
     - `confidence`: `0.0` to `1.0`.
  3. Multi-Tiered Classification Architecture:
     - **Primary Engine:** TypeSafe Jev AI (`jev`) choice-based classifier (`id: "gmail_router"`, options: `["github_issue_create", "freescout", "crm", "webhook_node"]`) calculating exact mathematical probabilities in 70–500ms without text hallucination.
     - **Architectural Limitation & Configuration:** Jev's four routing choices cannot express the 10-category taxonomy (`Bug Report`, `Feature Request`, `Demo Request`, `Pricing Inquiry`, `Billing Issue`, `Refund Request`, `Security/Account`, `Complaint`, `General Query`, `Other`) nor customer emotion. Therefore, `classification.jev.enabled: false` is configured by default in `config.yaml`, skipping the Jev tier when disabled and delegating deep 10-category taxonomy classification to Groq LLM with local offline heuristic fallback.
     - **Secondary Fallback:** Groq LLM (`groq`, model `openai/gpt-oss-120b`) for generative schema extraction if Jev times out or is unreachable.
     - **Tertiary Fallback:** Local offline heuristic ensemble (`offline_heuristic`), fail-closed to HITL review.
  4. Track Phase 2 classifier engine via dedicated field `state["p2_classifier_used"]` (`"jev"`, `"groq"`, or `"offline_heuristic"`), strictly preserving Phase 1's `state["classifier_used"]` (`"jev"`, `"groq"`, or `"regex"`) without overwriting it.
  5. Reuse Phase 1 Security Protections:
     - **A3 Prompt Injection Defense:** Dynamic boundary delimiters (`<<<P2_CLASSIFICATION_INPUT_{uuid}>>>`) and pre-filter injection detection (`is_potential_injection`). If injection detected, divert to `hitl_pending` with priority `High`.
     - **A4 Fail-Closed Normalization (`normalize_classification`):** Malformed, invalid, or hallucinated JSON defaults to `category="Other"`, `priority="Medium"`, `suggested_team="Support"`, `confidence=0.0` (forcing HITL gating).
     - **A6 Bounded Input Scans:** Clamps `masked_subject` to 2,000 chars and `masked_body` to 10,000 chars before calling classifier.
     - **A13 Host Allowlist:** Enforces HTTPS-only egress to approved endpoints (`https://api.typesafe.ai` and `https://api.groq.com`).
  6. Phase 2 Egress Test: Automated test in `tests/test_p2_egress.py` verifying that during classification only allowed hosts receive network traffic, and outbound payloads contain only masked tokens (zero unmasked text, zero `token_map`).
* **Done When:** Unit tests verify 10-category taxonomy, sentiment/emotion separation, injection pre-filter, fail-closed normalization, bounded input enforcement, and egress isolation.

#### [P2-02] Human-in-the-Loop Review Queue, State Gating, and Reviewer CLI Interface
* **Status:** ✅ Complete
* **Scope:** `nodes/hitl_queue.py`, `scripts/hitl_cli.py`, `db/database.py`, `config.yaml`, `tests/test_p2_hitl.py`
* **Problem:** Automated classification is inherently probabilistic. High-urgency angry customers, low-confidence predictions, security issues, and unmapped inquiries must not be dispatched automatically without human oversight. Operators need an audit-trailed interface to review and re-route items without overwriting Phase 1 triage data.
* **Solution:**
  1. Strict Phase 1 Isolation & Gating Status Model:
     - Phase 2 NEVER modifies or overwrites `email_triage.routing_status` or `dispatch_target`. Phase 1 triage decisions (`gatekeeper_approved`) remain immutable.
     - `hitl_status` values are strictly defined as: `none`, `pending`, `auto_approved` (machine passed), `approved` (human approved), `rejected` (human rejected). Automated passes must never be labelled `approved`.
     - `hitl_queue_node` returns `hitl_status`, `hitl_reason`, and `p2_status` (`"hitl_pending"`, `"auto_approved"`, or `"persist_failed"`). It does NOT return `routing_status`.
     - Conditional router `should_route_after_hitl` returns `"continue"` only when `hitl_status IN ('auto_approved', 'approved')` and `p2_status != 'persist_failed'`.
  2. Multi-Rule Gating Evaluation:
     - Divert to `hitl_status = 'pending'`, `p2_status = 'hitl_pending'` if:
       - Threat or prompt-injection pre-filter flagged by classifier (`p2_classifier_used == 'regex_filter'` or `is_threat` or prompt injection pattern), OR
       - Category in `classification.always_review_categories` (default `["Security/Account"]`), regardless of confidence or customer emotion, OR
       - Classification is missing, None, or malformed, OR
       - `confidence < classification.hitl_threshold` (default `0.85`), OR
       - Category is `Other` or unmapped, OR
       - `customer_emotion in ["Frustrated", "Angry"]` AND `priority in ["Critical", "High"]`.
  3. Reviewer CLI Tool (`scripts/hitl_cli.py`):
     - `hitl_cli.py list [--json] [--limit N]`: Displays pending reviews with `email_id`, `age`, `category`, `priority`, `confidence`, `reason`, `masked_subject`, and `masked_body` (strictly omitting `sender_email` and raw text).
     - `hitl_cli.py show <email_id>`: Displays full details of a pending review item with masked text and classifier reasoning.
     - `hitl_cli.py approve <email_id> --by <name> [--notes <text>] [--category <c>] [--team <t>]`: Approves classification, sets `hitl_status = 'approved'`, updates `hitl_notes`, `reviewed_by`, `reviewed_at`, and optional category/team overrides atomically.
     - `hitl_cli.py reject <email_id> --by <name> --notes <text>`: Rejects item with mandatory notes, sets `hitl_status = 'rejected'` atomically, terminating without dispatch.
     - Exit codes: `0` success, `2` invalid input or B5 single-line configuration error, `3` not found or not pending.
  4. Concurrency & State Machine Integrity:
     - `resolve_hitl_review` updates only `WHERE email_id = ? AND hitl_status = 'pending'`. Concurrent reviews guarantee exactly one winner while others raise `HitlStateError`.
     - Re-running Phase 2 classification never overwrites a human approval or rejection (`record_phase2_classification` returns `False`).
* **Done When:** Unit tests verify confidence threshold, emotion triggers, mandatory policy categories, prompt-injection diversion, Phase 1 status isolation, concurrency races, CLI commands, and exit codes.

#### [P2-03a] Dispatcher Foundations: Base Adapter, Outbox Ledger, and Safety Rails Configuration
* **Status:** ✅ Complete
* **Scope:** `utils/adapters/__init__.py`, `utils/adapters/base.py`, `db/database.py`, `config.yaml`, `utils/config.py`, `state.py`, `tests/test_p2_dispatch_foundations.py`, `ROADMAP.md`, `docs/phase2_decisions.md`, `docs/ARCHITECTURE.md`, `README.md`
* **Problem:** Downstream integrations are varied. Hardcoding dispatch logic without an outbox ledger leads to duplicate dispatches on network timeouts. Missing safety rails risk runaway API billing or alert storms.
* **Solution:**
  1. Base Adapter Abstract Contract (`BaseDestinationAdapter` in `utils/adapters/base.py`):
     - Consumes `DispatchPayload` (adapters receive `DispatchPayload`; provides stable SHA-256 hash, clamped text, and optional `customer_email: Optional[str] = None` supporting destination content resolution without breaking zero-PII public destinations).
     - Defines `DispatchResult` (non-empty `remote_id` <= 128 chars).
     - Exceptions: `AdapterError` base; `AdapterTransientError` (safe to retry), `AdapterPermanentError` (rejected), and `AdapterUnknownOutcomeError` (timeout after send, blind retries forbidden).
     - Thread-safe registry (`register_adapter`, `get_adapter`, `reset_adapters`) for canonical services (`github`, `freescout`, `crm`, `webhook`).
  2. Outbox Pattern Dispatch Ledger (`p2_dispatch_log` in `db/database.py`):
     - Table with composite unique constraint `UNIQUE(idempotency_key, mode)`: dry runs use state `'simulated'` and mode `'dry_run'` (never `'sent'`), live dispatches use mode `'live'`. Simulated rows never block later real dispatches (D1).
     - Every state change is ONE atomic SQL statement checking rowcount (never SELECT-then-UPDATE).
     - `begin_dispatch`: requires Phase 1 `routing_status == 'gatekeeper_approved'`. First attempt inserts `pending`, retries update `failed`/`deferred` rows if `attempts < max_attempts`, exhaust transitions to `'dead_letter'` (reason `'retries_exhausted'`) directly on the ledger (D6).
     - `record_dispatch_attempt`: increments attempts on pending rows only.
     - `finish_dispatch`: validates target state in (`confirmed`, `failed`, `unknown`, `dead_letter`, `simulated`, `deferred`) and code formats.
     - `resolve_unknown_dispatch`: resolves `'unknown'` rows to `'confirmed'` (with `remote_id`) or `'failed'` (reason `'operator_not_sent'`).
     - `count_confirmed_today`: counts live confirmed dispatches since 00:00 UTC today; ignores simulated rows and older days.
     - `get_failure_streak`: counts consecutive failures in newest-first live rows; resets on `'confirmed'`.
     - `divert_to_hitl`: diverts auto_approved/approved emails to pending HITL review with zero modification to Phase 1 data.
  3. Configuration & Safety Rails (`config.yaml` & `utils/config.py`):
     - Canonical destination service names: `github`, `freescout`, `crm`, `webhook` (replacing legacy `Engineering`, `Support`, `Sales`, `Billing` per D3).
     - B5 fail-fast schema validation: `dispatch` section (`dry_run: true`, `kill_switch: false`, `max_attempts: 3`, `pending_timeout_minutes: 10`, `backoff_base_seconds: 1.0`, `backoff_max_seconds: 20.0`).
     - B5 destination validation: `destinations.<service>` requires all 4 destinations with `enabled: false`, `daily_cap: int`, `use_masked_text_only: bool`, and `circuit_breaker` (`failure_threshold: 5`, `cooldown_seconds: 900`).
     - Defer Policy (D4): Daily cap exceeded, open circuit breaker, kill switch active, disabled destination, or missing adapter DEFER the action (ledger state `'deferred'` + reason code). They do NOT divert to HITL.
     - Dry-run audit logging (D2): Structured audit log carrying zero customer text (only `email_id`, `destination`, `action_type`, `payload_sha256`, `payload_bytes`).
* **Done When:** 28 unit tests in `tests/test_p2_dispatch_foundations.py` verify base adapter abstraction, payload clamping, stable hashing, outbox ledger atomic transitions, dry-run/live coexistence, retry to dead_letter, unknown resolution, daily counts, and strict config validation.

#### [P2-03b] Multi-Destination Dispatcher Router Node, Matrix Gating, and Dual-Action Webhook Alerts
* **Status:** ✅ **Complete**
* **Scope:** `nodes/dispatcher.py`, `nodes/__init__.py`, `tests/test_p2_dispatcher.py`
* **Problem:** Downstream integrations need an intelligent router node that gates intake, evaluates the 10-category taxonomy against destination services, supports dual-action alerts for critical issues, and coordinates with the outbox ledger.
* **Solution:**
  1. Dispatch Intake Gating:
     - Dispatcher node consumes emails only when `hitl_status IN ('auto_approved', 'approved')` and Phase 1 `routing_status == 'gatekeeper_approved'`.
  2. Comprehensive Deterministic Routing Matrix (D5):
     - `Bug Report` ➔ GitHub Issues (`github`). If `priority == "Critical"`, also triggers Webhook Alert (`webhook`).
     - `Feature Request` ➔ GitHub Issues (`github`) with `type:feature` label.
     - `Demo Request`, `Pricing Inquiry` ➔ CRM Leads (`crm`).
     - `General Query`, `Complaint` ➔ FreeScout Helpdesk (`freescout`). If `priority == "Critical"`, also triggers Webhook Alert (`webhook`).
     - `Security/Account` ➔ Diverted to HITL Review Queue (`hitl_pending`) + Webhook Alert (`webhook`).
     - `Billing Issue`, `Refund Request`: Always create a FreeScout ticket (`freescout`), and when `priority in ("Critical", "High")`, also trigger Webhook Alert (`webhook`).
     - `Other` or unmapped category ➔ Fails closed directly to HITL (`hitl_pending`).
  3. Dispatcher Node Implementation:
     - Implement `dispatcher_node(state: TriageState) -> dict` returning owned state keys: `dispatch_target`, `dispatch_status`, `dispatch_results`, and `error_message`.
     - Implement conditional edge `should_route_after_dispatcher(state: TriageState) -> str`.
     - Coordinates with `db.begin_dispatch()`, adapter execution, and `db.finish_dispatch()`.
* **Done When:** Table-driven tests verify complete 10-category routing, dual-action critical alerts, intake gating, and dry-run execution.

#### [P2-04a] GitHub Issues Contract, Fixtures, Output Formatting, and Config Schema
* **Scope:** `docs/contracts/github_issues.md`, `tests/fixtures/github/*.json`, `utils/adapters/github_format.py`, `config.yaml`, `utils/config.py`, `.env.example`, `tests/test_p2_github_format.py`
* **Status:** ✅ **Complete**
* **Problem:** Automated GitHub issue creation without output hardening allows customer emails to inject arbitrary markdown, mention unintended GitHub users/teams, trigger cross-issue linking, or spoof deduplication markers.
* **Solution:**
  1. Contract documentation: Researched official docs (docs.github.com) and documented auth, rate limits, pagination, and endpoints in `docs/contracts/github_issues.md`. Created authentic response fixtures in `tests/fixtures/github/`.
  2. Pure formatting and output hardening in `utils/adapters/github_format.py`:
     - Anchored marker prefix (`<!-- triage-bot:v1\nkey: ...\n-->\n`) strictly at index 0 of body.
     - Neutralize text: strips control chars and bidi overrides (`U+202A`–`U+202E`, `U+2066`–`U+2069`), defangs `@` mentions (`@\u200buser`) and `#` issue links (`#\u200b123`), escapes comment markers (`<!\u200b--`, `--\u200b>`).
     - Adaptive code fences (`fence_block`) for summaries and customer text (length = max backtick run + 1, min 3). Customer text is never rendered unfenced.
     - Title truncation (max 120 chars) and label generation (`triage:automated`, `type:bug`/`type:feature`, `urgency:{level}`).
  3. Config schema & validation:
     - Added GitHub destination settings in `config.yaml` and schema validation in `utils/config.py`. Enforces B5 rule (unknown keys on any destination raise `ConfigError`).
* **Done When:** Table-driven tests verify complete output hardening, adaptive code fencing, marker parser anchoring, and config schema validation.

#### [P2-04b] GitHub Issues Adapter with Deduplication Precheck and Remote Check
* **Scope:** `utils/adapters/github_adapter.py`, `utils/adapters/__init__.py`, `tests/test_p2_github_adapter.py`
* **Status:** ✅ **Complete**
* **Problem:** Live HTTP dispatches require rate limit handling, duplicate detection, network error classification (transient vs permanent), and circuit breaking.
* **Solution:**
  1. Implement `GitHubAdapter(BaseDestinationAdapter)` interfacing with GitHub REST API v3 (`POST /repos/{owner}/{repo}/issues`).
  2. Duplicate Detection & Remote Check:
     - Before creating issue, searches recent bot issues (`GET /repos/{owner}/{repo}/issues`) for the anchored idempotency marker (`<!-- triage-bot:v1\nkey: ...\n-->`). If match found, returns existing issue ID without re-creating.
     - Ignores pull requests (`pull_request` key), issues created by other logins, and unanchored markers. Truncated lookbacks fail closed with `AdapterError`.
  3. Safety, Authentication, and Exception Classification:
     - Token read from `token_env` at call time and never logged or stored.
     - Outbound URLs re-validated before session calls (insecure schemes, credentials, or non-allowlisted hosts abort with zero session calls).
     - Response status codes and low-level network errors strictly mapped to `AdapterTransientError`, `AdapterPermanentError`, or `AdapterUnknownOutcomeError`.
     - Log entries contain only `email_id`, status code, outcome class names, and constant reason codes.
  4. Note: Registering the adapter at application/pipeline startup belongs to P2-08/P2-09.
* **Done When:** Unit tests with mocked HTTP responses verify issue creation, duplicate detection via markers, rate limiting, and failure classifications.

#### [P2-05a] FreeScout Contract, Selective Unmasking Helper, Output Formatting, and Schema
* **Scope:** `utils/unmasker.py`, `docs/contracts/freescout.md`, `tests/fixtures/freescout/*.json`, `utils/adapters/freescout_format.py`, `config.yaml`, `utils/config.py`, `.env.example`, `tests/test_p2_unmasker.py`, `tests/test_p2_freescout_format.py`
* **Status:** ⏳ Pending
* **Problem:** Support tickets created in FreeScout require customer contact information and readable problem descriptions for agents to respond, while high-risk financial/auth secrets must remain masked and untrusted customer text must not inject arbitrary HTML or script payloads.
* **Solution:**
  1. Universal Unmasking Helper (`utils/unmasker.py`):
     - Implement central function `resolve_dispatch_content(state: TriageState, unmask_pii: bool = False, allowed_entity_types: Optional[Set[str]] = None, mailbox_fetcher: Optional[Callable[[str], Optional[str]]] = None) -> Dict[str, Any]`.
     - When `unmask_pii=False`: returns strictly `masked_subject`, `masked_body`, and `sender_domain`.
     - When `unmask_pii=True`: restores allowed entity placeholders (`{"PERSON", "EMAIL", "PHONE", "IP_ADDRESS"}`) via `nodes.pii_masker.unmask_text`, while strictly retaining high-risk secrets (`{"CREDIT_CARD", "SSN", "IBAN", "API_KEY"}`) as masked tokens.
     - Fallback handling: If `token_map` is absent (such as in standalone Phase 2 worker mode), binds customer email to persisted `sender_email` and supports `mailbox_fetcher(message_id)` before falling back to `masked_body`.
  2. FreeScout Contract & Fixtures:
     - Document official FreeScout REST API v1 (`POST /api/conversations`, `GET /api/conversations`, `POST /api/conversations/{id}/threads`) in `docs/contracts/freescout.md`.
     - Create realistic mock fixtures in `tests/fixtures/freescout/*.json` for 201 Created, 200 List/Search, 401 Unauthorized, 422 Validation Error, and 429 Rate Limit.
  3. Output Formatting & HTML Hardening (`utils/adapters/freescout_format.py`):
     - Format FreeScout conversation JSON payload (`mailboxId`, `subject`, `customer: {"email": sender_email}`, `threads: [...]`).
     - Hardening: wrap customer text in sanitized HTML structures, HTML-escape entities (`&`, `<`, `>`, `"`, `'`), defang script tags, iframes, and inline event handlers (`onload`, `onerror`).
     - System correlation marker: anchor `<!-- triage-bot:v1 key: ... -->` in thread content for deduplication.
  4. Config Schema & Customer Type Policy:
     - Add `destinations.freescout.unmask_pii: true` in `config.yaml` with schema validation in `utils/config.py`.
     - When `unmask_pii: true` and `sender_email` present, bind customer with `type: "email"` so support agents receive notifications and reply directly to the customer. Fall back to `bot_customer_id` with `type: "phone"` only when `unmask_pii: false` or `sender_email` is missing.
* **Done When:** Unit tests verify selective unmasking entity filtering, secret retention, HTML sanitization, correlation marker anchoring, and config schema validation.

#### [P2-05b] FreeScout Helpdesk Adapter with Thread Continuity and Retry Policy
* **Scope:** `utils/adapters/freescout_adapter.py`, `utils/adapters/__init__.py`, `tests/test_p2_freescout_adapter.py`
* **Status:** ⏳ Pending
* **Problem:** Live HTTP dispatches to FreeScout must append to existing conversation threads on customer replies, detect duplicate submissions, and classify API errors accurately.
* **Solution:**
  1. Implement `FreeScoutAdapter(BaseDestinationAdapter)` interfacing with FreeScout REST API.
  2. Thread Continuity & Deduplication Pre-Check:
     - Search conversations for matching correlation marker or `thread_id`.
     - If matching active ticket exists, append reply via `POST /api/conversations/{id}/threads` instead of creating detached duplicates.
  3. Authentication, Safe Headers & Exception Mapping:
     - Header `X-FreeScout-API-Key` loaded securely from environment (`FREESCOUT_API_KEY`).
     - Transient vs permanent error mapping (429/503 -> `AdapterTransientError`, 400/401/422 -> `AdapterPermanentError`).
* **Done When:** Unit tests with mocked HTTP responses verify conversation creation, thread reply appending, duplicate prevention, and retry classifications.

#### [P2-06] CRM Lead Ingestion Adapter with Output Hardening and Lead Scoring
* **Scope:** `utils/adapters/crm_adapter.py`, `config.yaml`, `.env.example`, `tests/test_p2_crm_adapter.py`
* **Status:** ⏳ Pending
* **Problem:** Inbound sales demo and pricing requests must be captured as structured leads with unmasked contact information for sales follow-up without allowing formula injection (`=`, `+`, `-`, `@`) or duplicate lead creation.
* **Solution:**
  1. Implement `CRMAdapter` interfacing with CRM webhook / REST API (HubSpot or generic CRM).
  2. Selective Contact Unmasking:
     - Configure `destinations.crm.unmask_pii: true` using `resolve_dispatch_content` to restore customer name, email, and phone while keeping payment/secret tokens masked.
     - Extract company domain from `sender_email` (filtering out public domains like `gmail.com`, `yahoo.com`).
  3. Output Hardening & Formula Injection Protection:
     - Sanitize all customer text fields; prefix formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`) with single quote (`'`) to protect CSV exports and spreadsheets against formula injection.
     - Neutralize HTML and script tags.
  4. Dynamic Domain & Lead Scoring:
     - Calculate lead score (0-100) based on inquiry category (`Demo Request` = 80, `Pricing Inquiry` = 70), urgency (`High` = +20), and company domain presence.
  5. Deduplication:
     - Check CRM for existing lead by `email_id` custom property or sender domain within a 24-hour sliding window before creating contact or deal.
* **Done When:** Unit tests verify contact unmasking, formula injection neutralization, domain extraction, lead score calculation, deal deduplication, and mock CRM ingestion.

#### [P2-07] Webhook Alert Adapter with HMAC Signing for Urgent Billing and Critical Alerts
* **Scope:** `utils/adapters/webhook_adapter.py`, `config.yaml`, `.env.example`, `tests/test_p2_webhook_adapter.py`
* **Problem:** Urgent billing disputes (double-charging, payment failures) and critical issues require instantaneous notification to finance or on-call channels with cryptographic authenticity and replay protection.
* **Solution:**
  1. Implement `WebhookAdapter` delivering cryptographically signed HTTP POST webhooks.
  2. Masked Context Policy:
     - Enforce `destinations.webhook.unmask_pii: false` by default, delivering structured metadata + masked context (`email_id`, `category`, `priority`, `amount_detected`, `masked_summary`) to prevent PII exposure in shared chat channels.
     - Configurable `unmask_pii: true` override only for dedicated internal financial endpoints.
  3. Trigger Routing (per D5 dual-action alert rules):
     - Priority `Critical` on `Bug Report`, `General Query`, or `Complaint` (triggers webhook alert alongside primary GitHub/FreeScout dispatch).
     - Priority `High` or `Critical` on `Billing Issue` or `Refund Request` (triggers webhook alert alongside primary FreeScout ticket dispatch).
     - High-risk security inquiries (`Security/Account` category).
  4. Cryptographic Authenticity & Security Headers:
     - Compute HMAC-SHA256 signature in `X-Signature-SHA256` computed over raw request body using shared secret (`WEBHOOK_SECRET_KEY_ENV`).
     - Include `Idempotency-Key: {email_id}:{destination}:alert` and `X-Correlation-ID: {email_id}` headers.
     - Include timestamp header `X-Timestamp-ISO` to prevent replay attacks beyond 5-minute tolerance.
  5. Output Hardening: Escape JSON fields to prevent JSON payload injection.
  6. Retry Policy: Exponential backoff with jitter on 5xx; fail-closed on 4xx.
* **Done When:** Unit tests verify HMAC signature computation, idempotency header inclusion, replay timestamp validation, JSON payload escaping, and retry backoff.

#### [P2-08] End-to-End LangGraph Phase 2 Graph Compilation and Dispatch Handoff
* **Scope:** `pipeline.py`, `tests/test_p2_pipeline_e2e.py`
* **Problem:** Phase 1 and Phase 2 nodes must integrate into a unified LangGraph workflow while supporting standalone background worker execution that consumes pre-approved database records without re-running Phase 1.
* **Solution:**
  1. Unified Pipeline Mode (`create_triage_pipeline(phase2=True)`):
     - Chains Node 05 (`gatekeeper`) ➔ Node 06 (`classifier`) ➔ Node 07 (`hitl_queue`) ➔ Node 08 (`dispatcher`).
  2. Standalone Worker Pipeline Mode (`create_phase2_worker_pipeline()`):
     - Standalone graph starting directly at Node 06 (`classifier`), consuming database-claimed records from `p2_jobs` without re-running Nodes 01–05.
  3. Conditional Edges:
     - `classifier` ➔ conditional routing to `hitl_queue` (if confidence < threshold or frustrated/high) or `dispatcher`.
     - `dispatcher` ➔ conditional routing to destination adapters based on category, priority, and dry-run flag.
  4. SQLite State Synchronization:
     - Persists Phase 2 metadata to `p2_jobs` and `p2_dispatch_log`.
     - Strictly enforces Zero-Touch Policy on `email_triage`.
* **Done When:** E2E integration tests verify both unified and standalone execution flows, conditional edge traversal, and proper state persistence across SQLite tables.

#### [P2-09] Persistent Phase 2 Queue Worker, Atomic Claiming, and Crash Recovery
* **Status:** ✅ Complete
* **Scope:** `scripts/phase2_worker.py`, `db/database.py`, `tools/run_worker.sh`, `tests/test_p2_worker.py`
* **Problem:** In production, Phase 2 runs as an asynchronous background service. Multiple workers polling the database must never claim the same email concurrently, and crashed workers must not leave jobs permanently stuck.
* **Solution:**
  1. Intake Ingestion from Phase 1:
     - Worker identifies records in `email_triage` with `status = 'done'` and `routing_status = 'gatekeeper_approved'` that lack corresponding rows in `p2_jobs`, and inserts them into `p2_jobs` with `state = 'unclaimed'`.
  2. Atomic Batch Claiming Query:
     - Implements `db.claim_p2_jobs(batch_size=10, worker_id=...)` executing a single atomic SQLite transaction:
       ```sql
       UPDATE p2_jobs
       SET state = 'claimed',
           worker_id = ?,
           claimed_at = CURRENT_TIMESTAMP,
           attempts = attempts + 1,
           updated_at = CURRENT_TIMESTAMP
       WHERE email_id IN (
           SELECT email_id FROM p2_jobs
           WHERE state IN ('unclaimed', 'hitl_resolved')
           ORDER BY created_at ASC
           LIMIT ?
       );
       ```
     - Guarantees zero race conditions across multiple worker processes.
  3. Crash Recovery & Stale Claim Sweeper:
     - Stale claims older than 15 minutes (`state IN ('claimed', 'dispatching')` with `claimed_at < 15 minutes ago`) are automatically reset back to `state = 'unclaimed'` for re-processing.
  4. Dead-Letter Queue:
     - If `attempts > max_dispatch_retries` (default 3), transitions to `state = 'dead_letter'` with `error_message`, alerts operators, and halts automated retries.
  5. Graceful Shutdown: Handles SIGINT and SIGTERM cleanly, finishing in-flight dispatches before exiting.
  6. Phase 1 Preservation Verification: Confirms `email_triage` row remains untouched.
* **Done When:** Concurrency tests verify multi-worker race conditions result in 0 duplicate claims, crashed workers recover within 15 minutes, and dead-letter transitions succeed without touching `email_triage`.

#### [P2-10] Phase 2 Synthetic Benchmark Dataset, Failure-Injection Suite, and Adapter Contracts
* **Status:** ✅ Complete
* **Scope:** `data/benchmark_phase2.json`, `main.py`, `tests/test_p2_benchmark.py`, `tests/test_p2_failure_injection.py`, `tests/test_p2_adapter_contracts.py`, `scripts/*_smoke_test.py`
* **Problem:** Phase 2 requires thorough benchmark validation covering all categories, edge cases, failure scenarios, and contract compliance without making live network calls in CI.
* **Solution:**
  1. Synthetic Benchmark Dataset (`data/benchmark_phase2.json`):
     - 50 diverse email scenarios evenly covering all 10 categories, emotional states (`Frustrated`, `Angry`, `Calm`), priority levels, edge cases, and dual-dispatch assertions (verifying primary FreeScout ticket creation alongside secondary Webhook alert dispatch on High/Critical billing issues `p2_bench_021`–`p2_bench_025`).
  2. Failure-Injection Test Suite (`tests/test_p2_failure_injection.py`):
     - **Timeout after successful send:** Remote API receives payload, but client times out. Asserts ledger state is marked `'unknown'`, blind retry is avoided, and remote check confirms creation.
     - **Concurrent worker claims:** Multiple threads/processes claiming the same queue simultaneously. Asserts zero dual claims.
     - **Worker process killed mid-dispatch:** Simulates SIGKILL during dispatch. Asserts stale sweeper recovers job cleanly.
     - **Forged marker email:** Inbound email containing spoofed correlation markers. Asserts system rejects forged marker.
  3. Adapter Contract Tests (`tests/test_p2_adapter_contracts.py`):
     - Recorded fixtures verifying JSON schemas, headers, and error responses for GitHub, FreeScout, CRM, and Webhook adapters.
  4. Sandbox Smoke Test Scripts:
     - Standalone scripts (`scripts/github_smoke_test.py`, `scripts/freescout_smoke_test.py`, `scripts/crm_smoke_test.py`, `scripts/webhook_smoke_test.py`) for manual end-to-end verification against developer sandbox accounts using explicit `--live` flag.
  5. Network Isolation: `tests/conftest.py` pytest network egress guard remains active across all automated test suites.
* **Done When:** Benchmark test passes 50/50 scenarios; failure-injection tests pass; contract tests verify all payloads; network egress guard confirms zero unmocked network calls.

#### [P2-11] Complete Phase 2 Documentation, Architecture Diagrams, and Operator Runbooks
* **Status:** ✅ Complete
* **Scope:** `README.md`, `ROADMAP.md`, `docs/architecture_phase2.md`, `docs/hitl_runbook.md`, `tests/test_p2_documentation.py`
* **Problem:** Operators, developers, and reviewers require comprehensive documentation, state diagrams, and runbooks to manage Phase 2 in production.
* **Solution:**
  1. Update `README.md` with Phase 2 features, architecture overview, configuration options, and benchmark results.
  2. Create `docs/architecture_phase2.md` with complete Mermaid state transitions, data flows, and outbox ledger diagrams.
  3. Create `docs/hitl_runbook.md` providing step-by-step instructions for support operators using `scripts/hitl_cli.py` to review, approve, override, and reconcile triage queues.
  4. Verify all documented environment variables, CLI options, and test metrics against the codebase.
* **Done When:** Documentation accuracy pass verifies that every diagram, command, and configuration option in the documentation matches the code.

#### [P2-12] Gmail Pub/Sub Mailbox Connector, Auth Lifecycle, and Original Text Re-fetch
* **Status:** ✅ Complete
* **Scope:** `utils/mailbox/gmail_connector.py`, `utils/mailbox/base.py`, `scripts/renew_mailbox_watch.py`, `config.yaml`, `.env.example`, `tests/test_p2_mailbox_connector.py`
* **Problem:** Automated triage requires an ingestion bridge to import live emails from enterprise mailboxes without polling delays, pass email authentication metadata, and re-fetch original unmasked text for authorized downstream destinations when configured.
* **Solution:**
  1. Mailbox Intake Module (`utils/mailbox/gmail_connector.py`):
     - Implements `GmailConnector` using official Google API client with least-privilege OAuth 2.0 read-only scopes (`https://www.googleapis.com/auth/gmail.readonly`).
  2. Cloud Pub/Sub Watch Setup & Automated Renewal:
     - Sets up mailbox push notifications via `users.watch()`.
     - Implements `scripts/renew_mailbox_watch.py` for automated renewal cron (Gmail watches expire after 7 days).
  3. Incremental History Sync:
     - Fetches new messages using `users.history.list` and `historyId`, preventing duplicate intakes.
     - Parses MIME structures into pipeline intake format.
  4. SPF / DKIM / DMARC Header Verification:
     - Extracts `Authentication-Results` and `Received-SPF` headers from raw email.
     - Passes authentication status (`auth_status: pass/fail/none`) into pipeline state, closing the known sender-spoofing limitation of A5.
  5. Authorized Original-Text Re-fetch:
     - Implements `refetch_original_email(message_id: str) -> dict` callable ONLY by downstream adapters where `use_masked_text_only: false`, ensuring raw PII is never stored in SQLite.
  6. Modularity & Out-of-Scope Statement:
     - Defines abstract `BaseMailboxConnector`. If client environment utilizes Microsoft 365, IMAP, or external webhook push, the connector can be substituted without altering pipeline logic.
* **Done When:** Unit tests verify OAuth credential handling, Pub/Sub message parsing, history sync, SPF/DKIM header extraction, and original text re-fetch with mock Gmail API.

---

## 🛠️ Phase 2 Post-Review Production Remediation Roadmap (PRR-01 to PRR-13)

This roadmap incorporates the 10 code review findings and lower-priority operational cleanups, organized **1-by-1** in the recommended execution order:
**1 → 2 → 3 (Flow Fixes) · 5, 4, 6 (Privacy & Security) · 8, 9, 10 (Idempotency) · 7 & Lower-Priority Items (Configuration & Cleanups).**

### Remediation Commit Matrix (1-by-1 Atomic Commits)

| # | Code | Group | Scope & Commit Description | Target Files | Status |
|:---:|:---:|:---|:---|:---|:---:|
| **1** | **PRR-01** | Flow (Item 1) | `fix(hitl): [PRR-01] pass through human approvals directly to dispatcher without re-gating` | `nodes/hitl_queue.py`, `scripts/phase2_worker.py`, `tests/test_p2_prr_01_hitl_approval.py` | ✅ Complete |
| **2** | **PRR-02** | Flow (Item 2) | `fix(dispatcher): [PRR-02] auto-register active production adapters at startup and on demand` | `utils/adapters/__init__.py`, `nodes/dispatcher.py`, `scripts/phase2_worker.py`, `tests/test_p2_prr_02_adapter_registry.py` | ✅ Complete |
| **3** | **PRR-03** | Flow (Item 3) | `fix(worker): [PRR-03] handle deferred and dead-letter dispatches with retryable job states` | `scripts/phase2_worker.py`, `db/database.py`, `tests/test_p2_prr_03_worker_states.py` | ✅ Complete |
| **4** | **PRR-04** | Flow (E2E) | `test(e2e): [PRR-04] integration test asserting human approval to worker dispatch to confirmed ledger flow` | `tests/test_p2_prr_04_e2e_approval_flow.py` | ✅ Complete |
| **5** | **PRR-05** | Security (Item 5) | `fix(unmasker): [PRR-05] fail closed on missing masked text and re-scrub secrets on mailbox re-fetch` | `utils/unmasker.py`, `tests/test_p2_prr_05_unmasker_secrets.py` | ✅ Complete |
| **6** | **PRR-06** | Security (Item 4) | `fix(mailbox): [PRR-06] enforce topmost mx.google.com authentication-results header and token parsing` | `utils/mailbox/gmail_connector.py`, `tests/test_p2_prr_06_gmail_auth.py` | ⏳ Pending |
| **7** | **PRR-07** | Security (Item 6) | `fix(freescout): [PRR-07] enforce non-routable invalid domain for synthetic customer fallback` | `utils/adapters/freescout_format.py`, `tests/test_p2_prr_07_freescout_domain.py` | ⏳ Pending |
| **8** | **PRR-08** | Idempotency (Item 8) | `fix(adapters): [PRR-08] split connection setup errors from post-write resets to prevent blind retries` | `utils/adapters/base.py`, `utils/adapters/webhook_adapter.py`, `utils/adapters/freescout_adapter.py`, `utils/adapters/crm_adapter.py`, `tests/test_p2_prr_08_post_write_retry.py` | ⏳ Pending |
| **9** | **PRR-09** | Idempotency (Item 9) | `fix(freescout): [PRR-09] eliminate thread append unhandled error fallthrough to new conversation` | `utils/adapters/freescout_adapter.py`, `tests/test_p2_prr_09_freescout_fallthrough.py` | ⏳ Pending |
| **10** | **PRR-10** | Idempotency (Item 10) | `feat(hitl): [PRR-10] add hitl_cli reconcile command to resolve unknown-outcome outbox rows` | `scripts/hitl_cli.py`, `docs/hitl_runbook.md`, `tests/test_p2_prr_10_hitl_reconcile.py` | ⏳ Pending |
| **11** | **PRR-11** | Config (Item 7) | `fix(webhook): [PRR-11] strictly enforce config host allowlist and require non-empty hmac secret` | `utils/adapters/webhook_adapter.py`, `utils/adapters/webhook_format.py`, `tests/test_p2_prr_11_webhook_allowlist.py` | ⏳ Pending |
| **12** | **PRR-12** | Cleanups (Worker/Classifier) | `fix(worker): [PRR-12] protect config immutability, worker CAS guard, and classifier empty fail-closed` | `scripts/phase2_worker.py`, `db/database.py`, `nodes/classifier.py`, `nodes/dispatcher.py`, `tests/test_p2_prr_12_operational_guards.py` | ⏳ Pending |
| **13** | **PRR-13** | Cleanups (Gmail Auth) | `fix(mailbox): [PRR-13] add gmail 401 token refresh retry and history pagination` | `utils/mailbox/gmail_connector.py`, `tests/test_p2_prr_13_gmail_lifecycle.py` | ⏳ Pending |

---

### Detailed Specifications for PRR Commits (PRR-01 through PRR-13)

#### [PRR-01] Human Approval Pass-Through Routing (Item 1)
* **Status:** ✅ Complete
* **Scope:** `nodes/hitl_queue.py`, `scripts/phase2_worker.py`, `tests/test_p2_prr_01_hitl_approval.py`
* **Problem:** Approved emails in `hitl_resolved` state are currently re-evaluated by `classifier_node` and `hitl_queue_node`. The node re-flags them as `pending`, terminating execution before `dispatcher_node` and resetting the job back to `hitl_pending` in `p2_jobs`.
* **Solution:**
  1. In `nodes/hitl_queue.py`, inspect prior approval state: if `hitl_status == 'approved'`, return `hitl_status: "approved"` and pass directly through to `dispatcher_node` without re-evaluating gating conditions or making LLM calls.
  2. In `scripts/phase2_worker.py`, pass `hitl_status = "approved"` when claiming `hitl_resolved` jobs.
* **Done When:** Unit tests verify that pre-approved jobs traverse `hitl_queue_node` to `dispatcher_node` without re-entering `hitl_pending`.

#### [PRR-02] Production Destination Adapter Registration (Item 2)
* **Status:** ✅ Complete
* **Scope:** `utils/adapters/__init__.py`, `nodes/dispatcher.py`, `scripts/phase2_worker.py`, `tests/test_p2_prr_02_adapter_registry.py`
* **Problem:** `_ADAPTER_REGISTRY` is only populated in tests. In production (`dispatch.dry_run: false`), `dispatcher_node` fails to find adapters and defers every action with `adapter_unavailable`.
* **Solution:**
  1. Implement `register_default_adapters(config)` in `utils/adapters/__init__.py` registering enabled adapters at startup (`phase2_worker.py`, `main.py`).
  2. In `nodes/dispatcher.py:resolve_adapter`, add fallback on-demand registration so uninitialized destinations resolve automatically.
* **Done When:** Tests verify that live dispatches find registered adapters from config without `adapter_unavailable` deferrals.

#### [PRR-03] Worker Job State Mapping for Deferred and Failed Dispatches (Item 3)
* **Status:** ✅ Complete
* **Scope:** `scripts/phase2_worker.py`, `db/database.py`, `tests/test_p2_prr_03_worker_states.py`
* **Problem:** `phase2_worker.py` maps unhandled statuses to `done` via an `else:` branch, silently dropping emails deferred by daily caps, kill switches, or circuit breakers.
* **Solution:**
  1. In `phase2_worker.py`, explicitly map `deferred` to `unclaimed` (retryable on subsequent worker cycles) and `dead_letter` to `dead_letter`.
  2. Ensure transient failed jobs are reclaimed up to `max_retries`.
* **Done When:** Tests assert that deferred dispatches remain retryable in `p2_jobs` and are not marked `done`.

#### [PRR-04] End-to-End Approval to Confirmed Outbox Flow (Verification)
* **Status:** ✅ Complete
* **Scope:** `tests/test_p2_prr_04_e2e_approval_flow.py`
* **Problem:** Need automated test asserting the complete flow: review item creation ➔ `hitl_cli approve` ➔ worker cycle ➔ destination dispatch ➔ `confirmed` outbox ledger row.
* **Solution:** Implement full integration test running the exact production lifecycle without mocked shortcuts.
* **Done When:** Test runs approval, executes worker cycle, and asserts `confirmed` outbox row in SQLite.

#### [PRR-05] Unmasker Missing Text Safeguard & Re-Fetch Secret Scrubbing (Item 5)
* **Status:** ✅ Complete
* **Scope:** `utils/unmasker.py`, `tests/test_p2_prr_05_unmasker_secrets.py`
* **Problem:** `utils/unmasker.py` falls back to raw text fields if `masked_body` is missing. Re-fetching via `mailbox_fetcher` inserts raw unmasked text directly, skipping the secret filter.
* **Solution:** Enforce Invariant 5: read only `masked_*`; if missing, fail closed immediately. When re-fetching original email via `mailbox_fetcher`, scrub high-risk secrets (`CREDIT_CARD`, `SSN`, `IBAN`, `API_KEY`) before selectively restoring allowed contact entities.
* **Done When:** Tests assert missing masked text raises error, and re-fetched email bodies retain high-risk secret masks.

#### [PRR-06] Gmail SPF/DKIM/DMARC Header Spoof Defense (Item 4)
* **Status:** ⏳ Pending
* **Scope:** `utils/mailbox/gmail_connector.py`, `tests/test_p2_prr_06_gmail_auth.py`
* **Problem:** Collapsing headers into a dict overwrites Google's authentic header with lower attacker-injected headers. Substring checks match within comments.
* **Solution:** Inspect headers in transmission order, extracting exclusively the topmost `Authentication-Results` header where `authserv-id` begins with `mx.google.com`. Parse exact key-value tokens with bounded regexes.
* **Done When:** Tests verify attacker headers injected lower down are ignored, and valid Google auth headers evaluate accurately.

#### [PRR-07] FreeScout Non-Routable Fallback Domain (Item 6)
* **Status:** ⏳ Pending
* **Scope:** `utils/adapters/freescout_format.py`, `tests/test_p2_prr_07_freescout_domain.py`
* **Problem:** When unmasking is disabled or sender email is absent, `freescout_format.py` constructs `triage+{email_id}@{sender_domain}`, creating routable addresses on third-party domains (e.g. `gmail.com`).
* **Solution:** Fall back strictly to the RFC 2606 reserved non-routable domain `triage+{email_id}@customer.invalid`.
* **Done When:** Tests verify synthetic addresses always terminate with `@customer.invalid`.

#### [PRR-08] Error Classification: Connection Setup vs Post-Write Resets (Item 8)
* **Status:** ⏳ Pending
* **Scope:** `utils/adapters/base.py`, `utils/adapters/webhook_adapter.py`, `utils/adapters/freescout_adapter.py`, `utils/adapters/crm_adapter.py`, `tests/test_p2_prr_08_post_write_retry.py`
* **Problem:** Catching all `ConnectionError` exceptions and raising `AdapterTransientError` blind-retries requests where bytes were already written to the server.
* **Solution:** Adopt `is_connection_setup_error` from `utils/adapters/base.py` across all adapters. Only connection-setup failures raise `AdapterTransientError`; post-write connection resets and ambiguous 5xx errors raise `AdapterUnknownOutcomeError`.
* **Done When:** Tests verify connection resets after request write are classified as unknown outcome, preventing duplicate retries.

#### [PRR-09] FreeScout Thread Append Fallthrough Elimination (Item 9)
* **Status:** ⏳ Pending
* **Scope:** `utils/adapters/freescout_adapter.py`, `tests/test_p2_prr_09_freescout_fallthrough.py`
* **Problem:** In `freescout_adapter.py:append_thread`, unhandled HTTP status codes (500, 502, 504, 400) fall through to `# 2. Create New Conversation`, issuing a second request that creates duplicate tickets.
* **Solution:** Add an explicit `else:` clause raising `AdapterUnknownOutcomeError` on 5xx or `AdapterPermanentError` on 4xx, preventing fallthrough.
* **Done When:** Tests verify thread append 500/502 errors never fall through to create new conversations.

#### [PRR-10] Operator CLI Reconciliation for Unknown-Outcome Outbox Rows (Item 10)
* **Status:** ⏳ Pending
* **Scope:** `scripts/hitl_cli.py`, `docs/hitl_runbook.md`, `tests/test_p2_prr_10_hitl_reconcile.py`
* **Problem:** When an outbox ledger row enters `unknown` state, `dispatcher_node` diverts it to HITL. `scripts/hitl_cli.py` has no command to resolve unknown outcomes, causing infinite loops between HITL and dispatcher.
* **Solution:** Add `reconcile` subcommand to `scripts/hitl_cli.py` (`hitl_cli reconcile <email_id> --destination <dest> --status <confirmed|failed> --by <operator> [--remote-id <id>]`) calling `db.resolve_unknown_dispatch()`. Update `docs/hitl_runbook.md`.
* **Done When:** CLI tests verify `reconcile` transitions ledger row to `confirmed` or `failed` and allows pipeline to finish.

#### [PRR-11] Webhook Config Host Allowlist Enforcement & Secret Validation (Item 7)
* **Status:** ⏳ Pending
* **Scope:** `utils/adapters/webhook_adapter.py`, `utils/adapters/webhook_format.py`, `tests/test_p2_prr_11_webhook_allowlist.py`
* **Problem:** `webhook_adapter.py` automatically injects `target_host` into `_allowed_hosts`, making allowlisting ineffective. It also allows empty secrets, transmitting empty HMAC signatures.
* **Solution:** Strictly enforce `allowed_hosts` from configuration without adding `target_host`. Validate that `WEBHOOK_SECRET_KEY` is configured and non-empty in `validate_config()`.
* **Done When:** Tests verify unlisted webhook hosts are rejected, and empty secret keys fail validation.

#### [PRR-12] Worker Config Isolation, CAS Guard, and Empty Body Fail-Closed (Cleanups)
* **Status:** ⏳ Pending
* **Scope:** `scripts/phase2_worker.py`, `db/database.py`, `nodes/classifier.py`, `nodes/dispatcher.py`, `tests/test_p2_prr_12_operational_guards.py`
* **Problem:** Worker mutates cached config; `finish_p2_job` lacks CAS check; classifier only checks `is None` allowing empty strings.
* **Solution:** Deepcopy config in `phase2_worker.py`; add `AND (worker_id = ? OR worker_id IS NULL)` to `finish_p2_job`; fail closed in `classifier_node` if `not masked_subject or not masked_body`; enforce single trial probe in circuit breaker.
* **Done When:** Tests assert worker config isolation, concurrent worker overwrite prevention, and empty body classifier fail-closed.

#### [PRR-13] Gmail Ingestion Auth Refresh & Pagination (Cleanups)
* **Status:** ⏳ Pending
* **Scope:** `utils/mailbox/gmail_connector.py`, `tests/test_p2_prr_13_gmail_lifecycle.py`
* **Problem:** `fetch_new_messages` lacks 401 token refresh retry and ignores `nextPageToken`.
* **Solution:** On HTTP 401, refresh OAuth token and retry once; iterate on `nextPageToken` up to 5 pages.
* **Done When:** Tests verify automatic 401 token refresh and multi-page history synchronization.


