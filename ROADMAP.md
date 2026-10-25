# Customer Email Triage Automation — Remediation & Engineering Roadmap

This roadmap tracks all 24 security, correctness, performance, and documentation issues identified during the senior architectural and security code review (Commit `03867d1`).

Each issue is implemented individually with corresponding unit tests, verified against the benchmark suite, and committed atomically following our modular review workflow.

---

## 🎯 Next Up & Recommended Execution Order

**Next up:** **[B5] Fail-Fast Config Loader & Environment Variable Overrides** (or **[A12] Container Security & Environment File Locations**)

### Recommended Execution Roadmap:
1. **Critical PII & Fail-Closed Guardrails:** `A1` -> `A2` -> `A4` -> `A3` -> `A8` -> `A13`
2. **State & Concurrency Hardening:** `A5` -> `A6` -> `A11` -> `A9` -> `A10`
3. **Correctness & Performance (Part B):** `B1` -> `B2` -> `B3` -> `B4` -> `B5` -> `B6`
4. **Testing, Docs & Packaging:** `C1` -> `C2` -> `C3` -> `C4` -> `A12` -> `A14`

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
| **12** | **A12** | Infrastructure | Run container as non-root `appuser`, fix data volume mounts, and honor `DATABASE_PATH` | ⏳ Pending |
| **13** | **A13** | Security | Hardened secrets handling: `override=False`, enforce `api.typesafe.ai` host, redact debug keys | ✅ Resolved |
| **14** | **A14** | Infrastructure | Pin exact dependency versions in `requirements.txt` and spaCy language model URL | ⏳ Pending |
| **15** | **B1** | Correctness | Refine signature stripper: RFC 3676, bare `--` code safety, bottom-up scan, safety size limit | ✅ Resolved (`8c13658`) |
| **16** | **B2** | Correctness | Remove generic business words from offline spam heuristics; route threats to manual review | ✅ Resolved |
| **17** | **B3** | Correctness | Tune sensitive keywords to intent phrases and establish single source in `config.yaml` | ✅ Resolved |
| **18** | **B4** | Correctness | Harmonize returned state with SQLite database and persist clean text for Phase 2 | ✅ Resolved |
| **19** | **B5** | Correctness | Resolve config relative to root, fail fast on invalid YAML, and honor environment overrides | ⏳ Pending |
| **20** | **B6** | Performance | Preload models and precompile regexes once at startup to eliminate per-email overhead | ⏳ Pending |
| **21** | **C1** | Testing | Expand synthetic benchmark validation to check all expected fields and default to offline | ⏳ Pending |
| **22** | **C2** | Testing | Isolate test suite from host environment variables (`.env`) for reproducible test runs | ⏳ Pending |
| **23** | **C3** | Testing | Ensure `scripts/jev_smoke_test.py` strictly verifies Jev response and exits non-zero on failure | ⏳ Pending |
| **24** | **C4** | Documentation | Reconcile README/ROADMAP test counts, directory trees, class names, and claim metrics | ⏳ Pending |

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
* **Problem:** Docker container runs as `root`; compose mounts full repository read-write; `DATABASE_PATH` env var is ignored; `*.db` is copied into Docker image; documentation suggests `chmod 777 data`.
* **Solution:**
  1. Add non-root `appuser` (`RUN useradd --create-home appuser && USER appuser`).
  2. Mount only `./data:/app/data` in `docker-compose.yml`.
  3. Read `DATABASE_PATH` from environment with default fallback to `data/triage.db`.
  4. Add `*.db` to `.dockerignore`. Update README to use `chown 1000:1000 data`.
* **Done When:** `docker compose run --rm email-triage whoami` outputs `appuser`, and database file generates inside `./data`.

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
* **Problem:** `requirements.txt` has unpinned package versions; Dockerfile downloads unpinned spaCy model releases.
* **Solution:** Pin exact versions (`==`) across all libraries in `requirements.txt` and pin direct release URL for the spaCy model.
* **Done When:** Every entry in `requirements.txt` has exact `==` version pinning.

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
* **Problem:** `config.yaml` is resolved relative to working directory, causing failures when run from subdirectories. Config errors are caught and swallowed with empty `{}`. Certain env vars are ignored.
* **Solution:**
  1. Resolve `config.yaml` relative to project root (`BASE_DIR`).
  2. Load and validate config once at startup; fail fast with informative errors.
  3. Apply environment variable overrides for `DATABASE_PATH`, `IDEMPOTENCY_STALE_MINUTES`, and `MAX_DISPATCH_RETRIES`.
* **Done When:** Invalid configuration causes immediate process exit with clear error; config loads reliably from any execution directory.

### [B6] Optimize Process Lifecycle & Eliminate Repeated Work
* **Problem:** spaCy model is repeatedly re-attempted on failure; `load_config()` reads YAML from disk on every email; regex patterns are recompiled on every invocation.
* **Solution:**
  1. Preload and cache spaCy model once at startup.
  2. Load configuration once in `main.py` and pass down.
  3. Precompile all keyword and heuristic regexes at startup.
* **Done When:** Tests verify that spaCy loading, config I/O, and pattern compilation occur exactly once per process.

---

## Part C: Tests and Documentation

### [C1] Comprehensive Benchmark Validation & Offline Default
* **Problem:** Benchmark runner only validates 5 fields, ignoring discrepancies in `dispatch_status`, `is_threat`, etc. Benchmark defaults to live API keys. Duplicate test fakes state with manual `db.mark_done()`.
* **Solution:**
  1. Assert all keys present in scenario `expected` dictionary.
  2. Default to `--offline` mode; require explicit `--live` flag for network calls.
  3. Transmit identical email payload twice through pipeline to verify duplicate delivery naturally.
* **Note on Benchmark Transitions:** Benchmark rows 76-99 currently assert `spam_skipped`. They will be systematically updated to expect `manual_review` alongside the implementation of A3 and B2.
* **Done When:** Benchmark runner checks 100% of expected fields across all 100 scenarios.

### [C2] Deterministic Test Environment Isolation
* **Problem:** Tests make live calls to external APIs if host `.env` file contains keys, causing flaky tests, rate-limiting, and test data leaks.
* **Solution:** Use `@patch.dict(os.environ, {}, clear=True)` or pass mock clients directly into nodes to ensure tests run completely isolated from host keys.
* **Done When:** Full test suite passes deterministically with real keys in `.env` and zero network access.

### [C3] Strict Jev Smoke Test Verification
* **Problem:** `scripts/jev_smoke_test.py` reports success even if Jev returns 401 or 500 and falls back to offline heuristics.
* **Solution:** Explicitly check `result["classifier_used"] == "jev"`; exit with code 1 (`sys.exit(1)`) on fallback.
* **Done When:** Running smoke test with an invalid key outputs failure and exits with non-zero exit code.

### [C4] Documentation Synchronization & Metric Accuracy
* **Problem:** Test counts in README/ROADMAP are outdated; file tree omits test modules; unbacked marketing claims exist (`enterprise-grade`, `sub-second`); dual naming (`JevClient` vs `JevAIClient`).
* **Solution:**
  1. Sync README and ROADMAP with real pytest output and test counts.
  2. Update file trees.
  3. Unify client naming to `JevClient`.
  4. Remove unbacked buzzwords; add measurable latency benchmarks.
* **Done When:** Every metric, diagram, and code reference in documentation matches codebase reality.
