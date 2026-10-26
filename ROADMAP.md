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
1. **Track 1: Intelligence Classification Engine:** `P2-01` (Deep Classifier) ➔ `P2-02` (HITL Review Queue)
2. **Track 2: Downstream Destination Adapters:** `P2-03` (Router & Base Adapter) ➔ `P2-04` (GitHub) ➔ `P2-05` (FreeScout) ➔ `P2-06` (CRM) ➔ `P2-07` (Webhook)
3. **Track 3: Integration, Worker, Benchmark & Docs:** `P2-08` (LangGraph Integration) ➔ `P2-09` (Queue Worker) ➔ `P2-10` (Benchmark Dataset) ➔ `P2-11` (Operational Docs)

**Next Immediate Task:** `P2-01` (`feat(classifier): [P2-01] deep LLM intent, category, and sentiment classifier node`).

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

Phase 2 builds upon the hardened, local-first foundation delivered in Phase 1. It consumes sanitized, privacy-vetted, gatekeeper-approved emails and intelligently routes them to external business destinations (GitHub, FreeScout, CRM, Webhook Alerts) with fail-safe Human-in-the-Loop review gating.

### 1. Phase 1 Termination & State Handoff Trace

To guarantee strict isolation and zero regressions, Phase 1 has a concrete, verified boundary:

* **Git Commit Anchor:** Terminated and delivered at Commit `020db77` (`chore: make check.sh executable`), preceded by `a609589` (`chore: final pre-delivery fixes, dev dependencies, batch execution, and metric accuracy`). All 24 remediation issues (A1–A14, B1–B6, C1–C4) and 7 final pre-delivery items are closed and verified.
* **Execution Boundary:** Pipeline execution concludes after Node 05 (`jev_gatekeeper_node`). Nodes 01 through 05 (`ingest` -> `signature_stripper` -> `pii_masker` -> `sensitive_skip` -> `jev_gatekeeper`) handle intake, normalization, sanitization, and safety approval.
* **Data Handoff Contract:** Approved records reside in `data/triage.db` inside the `email_triage` table with:
  - `status = 'done'`
  - `routing_status = 'gatekeeper_approved'`
  - `gatekeeper_decision = 'legitimate'`
* **Persisted Handoff Schema:**
  - `email_id` (TEXT, Primary Key)
  - `message_id` (TEXT, Correlation / Mailbox ID)
  - `thread_id` (TEXT, Thread continuity identifier)
  - `sender_email` (TEXT, Full sender address for authorized dispatch)
  - `sender_domain` (TEXT, Extracted sender domain)
  - `masked_subject` (TEXT, Precision-masked subject line)
  - `masked_body` (TEXT, Cleaned, signature-stripped, PII-masked body)
  - `is_active_thread` (INTEGER, Boolean flag indicating ongoing thread)
  - `gatekeeper_confidence` (REAL, Gatekeeper confidence score)
  - `classifier_used` (TEXT, Engine identifier e.g. `jev`, `groq`, `offline_heuristic`)
* **Handoff Reader API:**
  - `TriageDatabase.get_gatekeeper_approved(limit=100) -> list[dict]`
  - Tested and operational in `db/database.py`.
* **Strict Privacy Invariant:**
  - **`token_map` is NEVER persisted to SQLite or passed across process boundaries.**
  - All Phase 2 intelligence classification and external adapter formatting operate strictly on `masked_subject` and `masked_body`.
  - Downstream systems requiring raw customer PII (e.g. creating a real FreeScout ticket) re-fetch original text from the authorized mailbox API using `message_id`.

---

### 2. Phase 2 Pipeline Topology & Node Architecture

```
[Phase 1 Handoff: gatekeeper_approved]
                  │
                  ▼
   ┌─────────────────────────────┐
   │    Node 06: Classifier      │ ──► Deep LLM / Heuristic Ensemble
   │ (Intent, Urgency, Category) │     (bug_report, support, billing, sales)
   └──────────────┬──────────────┘
                  │
                  ▼
   ┌─────────────────────────────┐
   │   Node 07: HITL Gating      │ ──► Confidence < 0.85 or Frustrated High-Urgency?
   └──────┬───────────────┬──────┘
          │ (Borderline)  │ (Approved >= 0.85)
          ▼               ▼
   ┌─────────────┐ ┌─────────────────────────────┐
   │ HITL Review │ │    Node 08: Dispatcher      │ ──► Multi-Destination Router
   │    Queue    │ └──────────────┬──────────────┘
   └─────────────┘                │
         ┌────────────────────────┼────────────────────────┬────────────────────────┐
         ▼                        ▼                        ▼                        ▼
  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
  │ GitHub Issue │         │  FreeScout   │         │   CRM Lead   │         │   Webhook    │
  │   Adapter    │         │ Ticket Node  │         │ Ingestion    │         │ Alert Node   │
  │ (Bug Reports)│         │ (CS Support) │         │ (Sales/Demo) │         │(Dispute/Crit)│
  └──────────────┘         └──────────────┘         └──────────────┘         └──────────────┘
```

---

### 3. Phase 2 Modular Commit Roadmap Matrix

| # | Code | Track | Commit Description | Target Files | Status |
|:---:|:---:|:---|:---|:---|:---:|
| **1** | **P2-01** | Track 1 | `feat(classifier): [P2-01] deep LLM intent, category, and sentiment classifier node` | `nodes/classifier.py`, `utils/classifier_client.py`, `state.py`, `config.yaml`, `tests/test_p2_classifier.py` | ⏳ Ready |
| **2** | **P2-02** | Track 1 | `feat(hitl): [P2-02] human-in-the-loop review queue router and state gating` | `nodes/hitl_queue.py`, `db/database.py`, `tests/test_p2_hitl.py` | ⏳ Pending |
| **3** | **P2-03** | Track 2 | `feat(dispatch): [P2-03] multi-destination dispatcher router and abstract adapter base` | `nodes/dispatcher.py`, `utils/adapters/base.py`, `db/database.py`, `tests/test_p2_dispatcher_router.py` | ⏳ Pending |
| **4** | **P2-04** | Track 2 | `feat(adapters): [P2-04] github issues adapter for engineering bug reports` | `utils/adapters/github_adapter.py`, `tests/test_p2_github_adapter.py` | ⏳ Pending |
| **5** | **P2-05** | Track 2 | `feat(adapters): [P2-05] freescout helpdesk adapter for general customer support` | `utils/adapters/freescout_adapter.py`, `tests/test_p2_freescout_adapter.py` | ⏳ Pending |
| **6** | **P2-06** | Track 2 | `feat(adapters): [P2-06] crm lead ingestion adapter for sales demo and pricing inquiries` | `utils/adapters/crm_adapter.py`, `tests/test_p2_crm_adapter.py` | ⏳ Pending |
| **7** | **P2-07** | Track 2 | `feat(adapters): [P2-07] webhook alert adapter for urgent billing and refund disputes` | `utils/adapters/webhook_adapter.py`, `tests/test_p2_webhook_adapter.py` | ⏳ Pending |
| **8** | **P2-08** | Track 3 | `feat(pipeline): [P2-08] end-to-end langgraph phase 2 graph compilation and dispatch handoff` | `pipeline.py`, `tests/test_p2_pipeline_e2e.py` | ⏳ Pending |
| **9** | **P2-09** | Track 3 | `feat(worker): [P2-09] persistent phase 2 queue worker and background poller` | `scripts/phase2_worker.py`, `db/database.py`, `tools/run_worker.sh`, `tests/test_p2_worker.py` | ⏳ Pending |
| **10** | **P2-10** | Track 3 | `feat(testing): [P2-10] phase 2 synthetic benchmark dataset and validation suite` | `data/benchmark_phase2.json`, `main.py`, `tests/test_p2_benchmark.py` | ⏳ Pending |
| **11** | **P2-11** | Track 3 | `docs(phase2): [P2-11] complete phase 2 documentation, architecture diagrams, and runbooks` | `README.md`, `ROADMAP.md`, `docs/` | ⏳ Pending |

---

### 4. Detailed Specifications for Commits P2-01 through P2-11

#### [P2-01] Deep LLM Intent, Category, and Sentiment Classifier Node
* **Scope:** `nodes/classifier.py`, `utils/classifier_client.py`, `state.py`, `config.yaml`, `tests/test_p2_classifier.py`
* **Problem:** Approved emails lack deep semantic classification. Downstream systems cannot distinguish between engineering bug reports, sales inquiries, general support tickets, and urgent billing issues.
* **Solution:**
  1. Implement `classifier_node(state: TriageState) -> dict` consuming `masked_subject` and `masked_body`, populating `state["classification"]` with an `EmailClassification` object.
  2. `EmailClassification` (in `state.py`) defines explicit schema enums:
     - `category`: `Bug Report`, `Demo Request`, `Pricing Inquiry`, `Billing Issue`, `Refund Request`, `General Query`.
     - `priority`: `Critical`, `High`, `Medium`, `Low`.
     - `sentiment`: `Positive`, `Neutral`, `Negative`, `Frustrated` (supports emotional escalation detection).
     - `summary`: One-sentence clean summary.
     - `suggested_team`: `Engineering`, `Sales`, `Billing`, `Support`.
     - `confidence`: `0.0` to `1.0`.
  3. Track Phase 2 classifier engine via dedicated field `state["p2_classifier_used"]` (e.g. `"groq"` or `"offline_heuristic"`), preserving Phase 1's `state["classifier_used"]` (which records `"jev"`, `"groq"`, or `"regex"` gatekeeper decisions) without overwriting it.
  4. Enforce fail-closed normalization — unknown or malformed output defaults to `manual_review` routing.
* **Done When:** Table-driven unit tests verify schema conformance, mock LLM responses, offline fallback, and confidence clamping.

#### [P2-02] Human-in-the-Loop Review Queue Router and State Gating
* **Scope:** `nodes/hitl_queue.py`, `db/database.py`, `config.yaml`, `tests/test_p2_hitl.py`
* **Problem:** High-risk or low-confidence automated classifications should not be dispatched automatically to live destinations without human validation.
* **Solution:**
  1. Implement `hitl_queue_node` evaluating classifier confidence against configurable threshold (`classification.hitl_threshold: 0.85`).
  2. Divert to `hitl_pending` if:
     - `confidence < 0.85`, OR
     - `sentiment == "Frustrated"` AND `priority in ["Critical", "High"]`, OR
     - Category classification is unrecognized or malformed.
  3. Extend SQLite schema with `hitl_status`, `hitl_notes`, `reviewed_by`, and `reviewed_at`.
  4. Expose `get_pending_hitl_reviews()` and `resolve_hitl_review()` in `TriageDatabase`.
* **Done When:** Boundary tests verify confidence < 0.85 and frustrated+high-priority route to HITL; schema migration and review resolution APIs verified.

#### [P2-03] Multi-Destination Dispatcher Router and Abstract Adapter Base
* **Scope:** `nodes/dispatcher.py`, `utils/adapters/base.py`, `db/database.py`, `tests/test_p2_dispatcher_router.py`
* **Problem:** Downstream integrations are varied. Hard-coding API calls in pipeline nodes violates separation of concerns and creates duplicate external actions on unhandled retries.
* **Solution:**
  1. Define abstract base class `BaseDestinationAdapter(ABC)` with `dispatch()`, `validate_config()`, and `health_check()`.
  2. Define `DispatchResult` dataclass (`success`, `destination`, `remote_id`, `idempotency_key`, `retryable`, `error`).
  3. Implement deterministic routing matrix across all 6 categories:
     - `Bug Report` ➔ GitHub Issues (`github`)
     - `Demo Request`, `Pricing Inquiry` ➔ CRM Leads (`crm`)
     - `General Query` ➔ FreeScout Helpdesk (`freescout`)
     - `Billing Issue`, `Refund Request`:
       - If `priority in ["Critical", "High"]` (e.g. urgent billing disputes, double-charging, and payment failures that pass Phase 1; explicit "chargeback" keywords are already diverted in Phase 1's `sensitive_skip` node) ➔ Webhook Alert (`webhook`)
       - If `priority in ["Medium", "Low"]` (routine invoice/receipt query) ➔ FreeScout Helpdesk (`freescout`)
     - Any unmapped category ➔ Fails closed to `manual_review` / `hitl_pending`.
  4. Idempotency Key Specification: Every dispatch operation generates a deterministic `idempotency_key = f"{email_id}:{destination}:{action_type}"` to protect against duplicate dispatch.
* **Done When:** Registry unit tests verify adapter discovery, routing logic across all categories, and fail-closed error handling.

#### [P2-04] GitHub Issues Adapter for Engineering Bug Reports
* **Scope:** `utils/adapters/github_adapter.py`, `config.yaml`, `.env.example`, `tests/test_p2_github_adapter.py`
* **Problem:** Software bug reports need structured creation in GitHub with appropriate labels, urgency, and traceability without exposing customer PII or creating duplicate issues on network retries.
* **Solution:**
  1. Implement `GitHubAdapter` interfacing with GitHub REST API v3 (`POST /repos/{owner}/{repo}/issues`).
  2. Format issue title `[Triage Bug] {masked_subject}` and markdown body containing triage summary, sender domain, and correlation marker `<!-- triage-id: {email_id} -->`.
  3. Duplicate-Dispatch Protection: Check existing issues by correlation marker before retrying on timeout to ensure duplicate issues are never created.
  4. Apply labels: `bug`, `triage:automated`, `urgency:{level}`.
  5. Implement exponential backoff retry on HTTP 429/503.
* **Done When:** Unit tests assert payload format, label mapping, offline stub behavior, idempotency check, and rate limit retries.

#### [P2-05] FreeScout Helpdesk Adapter for General Customer Support
* **Scope:** `utils/adapters/freescout_adapter.py`, `config.yaml`, `.env.example`, `tests/test_p2_freescout_adapter.py`
* **Problem:** General support tickets need ticket creation in helpdesk software while preserving conversation continuity across multiple replies.
* **Solution:**
  1. Implement `FreeScoutAdapter` interfacing with FreeScout API (`POST /api/conversations`).
  2. Bind `thread_id` and `message_id` to conversation headers to append replies to existing tickets.
  3. Map mailboxes based on product or department tags.
* **Done When:** Unit tests verify conversation payload structure, thread continuity headers, and mock API interactions.

#### [P2-06] CRM Lead Ingestion Adapter for Sales Demo and Pricing Inquiries
* **Scope:** `utils/adapters/crm_adapter.py`, `config.yaml`, `.env.example`, `tests/test_p2_crm_adapter.py`
* **Problem:** High-value enterprise pricing requests and demo inquiries must be captured as qualified leads in CRM systems without delay.
* **Solution:**
  1. Implement `CRMAdapter` formatting leads for HubSpot / generic CRM webhooks.
  2. Extract company domain from sender domain; calculate lead score (0-100) based on urgency and inquiry intent.
  3. Deduplicate leads by sender domain within a configurable time window.
* **Done When:** Unit tests verify lead scoring algorithm, domain parsing, payload schema, and mock delivery.

#### [P2-07] Webhook Alert Adapter for Urgent Billing and Refund Disputes
* **Scope:** `utils/adapters/webhook_adapter.py`, `config.yaml`, `.env.example`, `tests/test_p2_webhook_adapter.py`
* **Problem:** Urgent billing disputes, double-charging, or payment failures that pass Phase 1 (since explicit "chargeback" keywords are already diverted in Phase 1's `sensitive_skip` node) require immediate notification to on-call or finance teams without duplicate alert spamming on retries.
* **Solution:**
  1. Implement `WebhookAdapter` delivering cryptographically signed HTTP POST webhooks.
  2. Compute HMAC-SHA256 signature in `X-Signature-SHA256` header using shared secret.
  3. Include `Idempotency-Key: {email_id}:{destination}:alert` and `X-Correlation-ID: {email_id}` headers to protect receiving webhook services from processing duplicates.
  4. Implement retry policy with exponential backoff and jitter.
* **Done When:** Unit tests verify HMAC signature computation, idempotency header inclusion, payload structure, network timeout handling, and retry policy.

#### [P2-08] End-to-End LangGraph Phase 2 Graph Compilation and Dispatch Handoff
* **Scope:** `pipeline.py`, `tests/test_p2_pipeline_e2e.py`
* **Problem:** Phase 1 and Phase 2 nodes must be linked within LangGraph with clean conditional edges, supporting both unified execution and standalone worker execution without re-running Phase 1.
* **Solution:**
  1. Extend `create_triage_pipeline()` to accept `phase2: bool = False`. When `True`, chains Node 05 (`gatekeeper`) → Node 06 (`classifier`) → Node 07 (`hitl_queue`) → Node 08 (`dispatcher`).
  2. Implement standalone Phase 2 sub-graph `create_phase2_worker_pipeline()` starting directly at Node 06 (Classifier), consuming database-claimed approved records without re-running Gatekeeper.
  3. Add conditional routing edges on `classification.confidence`, `hitl_status`, and `dispatch_target`.
  4. Harmonize returned `TriageState` fields with atomic SQLite updates in `db/database.py`.
* **Done When:** Integration tests execute approved emails through the full LangGraph Phase 2 pipeline to adapter mock stubs with all state fields correctly populated.

#### [P2-09] Persistent Phase 2 Queue Worker and Background Poller
* **Scope:** `scripts/phase2_worker.py`, `db/database.py`, `tools/run_worker.sh`, `tests/test_p2_worker.py`
* **Problem:** In production, triage classification and downstream dispatching operate asynchronously from mailbox ingestion, requiring atomic batch claiming, worker crash recovery, and double-dispatch prevention.
* **Solution:**
  1. Implement continuous polling worker querying atomic `db.claim_gatekeeper_approved(batch_size=10, worker_id=...)`.
  2. Atomic Batch Claiming: Uses single SQL transaction setting `status = 'processing_p2'`, `worker_id = ?`, `updated_at = CURRENT_TIMESTAMP`, completely preventing multi-worker race conditions.
  3. Stale Job Recovery: Periodically resets abandoned jobs (`status = 'processing_p2'` older than 15 minutes) back to `status = 'done'` for safe re-claiming.
  4. Terminal State Transition: Upon successful dispatch or HITL diversion, marks `status = 'p2_done'` and `routing_status = 'dispatched'` (or `'hitl_pending'`), removing it from the polling pool permanently.
  5. Add graceful shutdown handling on SIGINT/SIGTERM.
* **Done When:** Concurrency tests verify multi-worker execution processes records without duplicate claims, crashed worker jobs recover safely, and terminal status updates cleanly.

#### [P2-10] Phase 2 Synthetic Benchmark Dataset and Validation Suite
* **Scope:** `data/benchmark_phase2.json`, `main.py`, `tests/test_p2_benchmark.py`
* **Problem:** Phase 2 requires comprehensive, deterministic benchmark validation covering all categories, urgency levels, and adapter routes.
* **Solution:**
  1. Create 50 synthetic test emails (10 GitHub bugs, 10 FreeScout tickets, 10 CRM leads, 10 Billing webhooks, 10 HITL reviews).
  2. Add `--phase2` CLI flag to `main.py`.
  3. Assert 100% of expected fields across all 50 scenarios in offline mock mode.
* **Done When:** Benchmark runner executes `main.py --phase2` with 50/50 scenarios passing in offline mock mode.

#### [P2-11] Phase 2 Documentation, Architecture Diagrams, and Runbooks
* **Scope:** `README.md`, `ROADMAP.md`, `docs/architecture_phase2.md`
* **Problem:** Operators and developers need clear runbooks, API documentation, and architecture diagrams for Phase 2.
* **Solution:**
  1. Update `README.md` with Phase 2 capabilities, environment variables, adapter documentation, and benchmark metrics.
  2. Add mermaid sequence and state diagrams for Phase 2.
  3. Document operational runbooks for HITL review operators.
* **Done When:** Documentation accuracy pass verifies all documented CLI commands, environment variables, and test counts.
