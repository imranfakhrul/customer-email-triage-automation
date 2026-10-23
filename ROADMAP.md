# Customer Email Triage Automation — Remediation & Engineering Roadmap

This roadmap tracks all 24 security, correctness, performance, and documentation issues identified during the senior architectural and security code review (Commit `03867d1`).

Each issue is implemented individually with corresponding unit tests, verified against the benchmark suite, and committed atomically following our modular review workflow.

---

## 🎯 Next Up & Recommended Execution Order

**Next up:** **[A4] Fail-Closed Classifier Normalization**

### Recommended Execution Roadmap:
1. **Critical PII & Fail-Closed Guardrails:** `A1` -> `A2` -> `A4` -> `A3` -> `A8` -> `A13`
2. **State & Concurrency Hardening:** `A5` -> `A6` -> `A11` -> `A9` -> `A10`
3. **Correctness & Performance (Part B):** `B2` -> `B3` -> `B4` -> `B5` -> `B6`
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
| **3** | **A3** | Security | Guard against Groq prompt injection with pre-filter & randomized delimiter tags | ⏳ Pending |
| **4** | **A4** | Security | Enforce fail-closed classifier normalization (`normalize_result`) with 0.70 threshold | ⏳ Pending |
| **5** | **A5** | Security | Harden active-thread detection against spoofing & unapproved thread history | 🟡 Partially Done |
| **6** | **A6** | Security | Eliminate ReDoS vulnerabilities in heuristic regexes & limit input length | ⏳ Pending |
| **7** | **A7** | Security | Defeat sensitive keyword evasion (NFKC, zero-width, Cyrillic/Greek homoglyphs, broad chargeback) | ✅ Resolved (`c75f0b5`) |
| **8** | **A8** | Security | Fail fast on startup & runtime safeguard if spaCy model is missing while AI keys active | ⏳ Pending |
| **9** | **A9** | Privacy | Integrate `phonenumbers` library, Luhn credit card check, and collision-safe tokens | ⏳ Pending |
| **10** | **A10** | Privacy | Contextualize technical terms whitelist to protect real surnames (Jenkins, Kafka, etc.) | 🟡 Partially Done |
| **11** | **A11** | Concurrency | Atomic SQLite idempotency check-and-claim to prevent multi-worker race conditions | ⏳ Pending |
| **12** | **A12** | Infrastructure | Run container as non-root `appuser`, fix data volume mounts, and honor `DATABASE_PATH` | ⏳ Pending |
| **13** | **A13** | Security | Hardened secrets handling: `override=False`, enforce `api.typesafe.ai` host, redact debug keys | ⏳ Pending |
| **14** | **A14** | Infrastructure | Pin exact dependency versions in `requirements.txt` and spaCy language model URL | ⏳ Pending |
| **15** | **B1** | Correctness | Refine signature stripper: RFC 3676, bare `--` code safety, bottom-up scan, safety size limit | ✅ Resolved (`8c13658`) |
| **16** | **B2** | Correctness | Remove generic business words from offline spam heuristics; route threats to manual review | ⏳ Pending |
| **17** | **B3** | Correctness | Tune sensitive keywords to intent phrases and establish single source in `config.yaml` | ⏳ Pending |
| **18** | **B4** | Correctness | Harmonize returned state with SQLite database and persist clean text for Phase 2 | ⏳ Pending |
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
* **Problem:** Unbounded email content is interpolated directly into Groq prompts. Adversarial emails with instructions (`Ignore previous instructions...`) can hijack the gatekeeper. `PROMPT_INJECTION_REGEX` only ran during offline fallback.
* **Solution:**
  1. Run `PROMPT_INJECTION_REGEX` on subject and body *before* invoking any AI; divert matches immediately to `manual_review`.
  2. Enclose customer email text in randomized boundary markers (`<email-XXXXXX>...</email-XXXXXX>`) with explicit system instructions to ignore internal directives.
  3. Strictly validate the returned JSON response structure.
* **Note on Benchmark Expectations:** Benchmark rows 91-99 and related gatekeeper tests currently assert `routing_status = 'spam_skipped'`. When A3 is implemented, their expected outcome will transition to `manual_review`.
* **Done When:** Tests verify that an adversarial injection payload diverts to `manual_review` without calling Groq, and that outgoing Groq prompts contain dynamic nonce tags.

### [A4] Fail-Closed Classifier Normalization
* **Problem:** The gatekeeper fails open: unknown decisions default to `"legitimate"`, out-of-range confidence scores are accepted, and the confidence threshold (`llm.confidence_threshold` in config, default 0.70) is never enforced in code.
* **Solution:** Implement a unified `normalize_result(raw) -> dict` function:
  1. Unknown or malformed decisions default to `"manual_review"`.
  2. Confidence clamped to `[0.0, 1.0]` (NaN/None -> 0.0).
  3. If `is_threat` is True, force decision to at least `"manual_review"`.
  4. If decision is `"legitimate"` but confidence < `config["llm"]["confidence_threshold"]` (default 0.70), divert to `"manual_review"`.
* **Done When:** Table-driven unit test covers all edge cases (out-of-range confidence, unrecognized decision strings, threat flags).

### [A5] Harden Active-Thread Verification Against Spoofing
* **Status:** 🟡 **Partially Done**
  * *Done earlier:* Verified participant addresses against thread history in Commit `02650f9`.
  * *Still missing:* (1) Restrict SQL history queries strictly to `routing_status = 'gatekeeper_approved'` (currently counts any `status = 'done'`, including spam/sensitive). (2) Disallow empty sender matching; require non-empty exact equality. (3) Initialize `is_active_thread = None` in initial state, ignoring incoming payload claims.
* **Problem:** A spammer can send an initial email (caught as spam, marked done), then reply to the thread and have it classified as an active customer conversation. Empty senders match any address. Payloads can inject `is_active_thread: true`.
* **Solution:**
  1. Restrict SQL history queries strictly to `routing_status = 'gatekeeper_approved'`.
  2. Disallow empty sender matching; require non-empty exact equality.
  3. Initialize `is_active_thread = None` in initial state, relying solely on DB verification.
* **Done When:** Tests prove that spam threads, empty senders, and injected `is_active_thread: true` payloads all evaluate to `is_active_thread = False`.

### [A6] Eliminate ReDoS Backtracking in Heuristic Regexes
* **Problem:** Patterns containing multiple `.*` with the `re.DOTALL` flag (such as `grandma.*read\s+me.*system\s+prompt`) trigger catastrophic backtracking on long inputs, stalling worker threads.
* **Solution:**
  1. Replace unbounded `.*` with bounded matches (`.{0,200}`).
  2. Enforce an upper bound on text length (10,000 characters) before running heuristic regexes.
* **Done When:** Test runs heuristic evaluation against a 50 KB adversarial string and completes in < 1.0 second.

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
* **Problem:** If spaCy fails to load (missing package, missing model, out-of-memory), the node currently logs a warning and proceeds, silently transmitting unmasked person names to external AI APIs.
* **Solution:**
  1. Startup: If external AI keys (Jev or Groq) are configured and spaCy fails to load, raise `RuntimeError` at startup to halt container initialization immediately.
  2. Runtime safeguard: If the spaCy model is missing or unavailable at runtime while Jev or Groq is enabled, send nothing outside and divert the email to `manual_review`.
* **Done When:** Unit test mocking `spacy.load` to raise verifies that the pipeline refuses to boot with active API keys, and runtime fallback routes to `manual_review` without external network calls.

### [A9] Precision PII Regexes, Luhn Check & Token Nonces
* **Problem:** Masker misses international phone numbers (`+44...`, `+880...`), truncated IBANs, JWTs, and API keys; falsely redacts 16-digit order numbers as credit cards without Luhn verification; corrupts text when customers quote earlier tokens like `[EMAIL_1]`.
* **Solution:**
  1. Use Google's `phonenumbers` library for international phone number parsing.
  2. Implement Luhn checksum algorithm for credit card matching.
  3. Add IBAN mod-97 validation.
  4. Add regexes for JWTs, Google API keys (`AIza...`), OpenAI keys (`sk-proj-...`), and Slack tokens.
  5. Append per-message random nonces to placeholders (e.g., `[EMAIL_1_a8f3]`).
* **Done When:** Test suite validates each PII type is redacted when valid and ignored when checksum fails.

### [A10] Contextualize Tech-Terms Whitelist (Surnames vs Tech)
* **Status:** 🟡 **Partially Done**
  * *Done earlier:* Externalized tech terms whitelist in `config/tech_terms.txt`, cached loader, and whole-entity matching for `PERSON` spans in Commit `03867d1`.
  * *Still missing:* Ambiguous names (Jenkins, Kafka, Helm, Apollo, Flask, Django) must be kept only when a technical context word is directly adjacent (e.g., `Jenkins pipeline`, `Kafka cluster`); a lone name (for example after a greeting or sign-off like *"Thanks, Jenkins"*) must always be masked. Add `@unittest.skipUnless(spacy_available)` guards to tests.
* **Problem:** Common surnames in the whitelist allow customer surnames to be sent to external AI unmasked when signed alone.
* **Solution:** Implement contextual adjacency verification: ambiguous terms are skipped only if accompanied by directly adjacent technical context words; otherwise, mask as person.
* **Done When:** `"Thanks, Jenkins"` masks the name, while `"our Jenkins pipeline failed"` does not.

### [A11] Concurrency & Atomic SQLite Idempotency Locking
* **Problem:** `check_and_acquire` executes a `SELECT` followed by an `INSERT`/`UPDATE` in separate statements. Concurrent worker threads race and cause double processing or `sqlite3.IntegrityError` crashes.
* **Solution:**
  1. For new emails: `INSERT ... ON CONFLICT(email_id) DO NOTHING` and inspect `cursor.rowcount == 1`.
  2. For stale lock recovery: conditional `UPDATE email_triage SET status='processing' ... WHERE email_id=? AND status='processing' AND updated_at < ?` and check `cursor.rowcount == 1`.
* **Done When:** Concurrency test with 8 simultaneous threads attempting to lock the same email results in exactly 1 winner and 0 crashes.

### [A12] Container Security & Environment File Locations
* **Problem:** Docker container runs as `root`; compose mounts full repository read-write; `DATABASE_PATH` env var is ignored; `*.db` is copied into Docker image; documentation suggests `chmod 777 data`.
* **Solution:**
  1. Add non-root `appuser` (`RUN useradd --create-home appuser && USER appuser`).
  2. Mount only `./data:/app/data` in `docker-compose.yml`.
  3. Read `DATABASE_PATH` from environment with default fallback to `data/triage.db`.
  4. Add `*.db` to `.dockerignore`. Update README to use `chown 1000:1000 data`.
* **Done When:** `docker compose run --rm email-triage whoami` outputs `appuser`, and database file generates inside `./data`.

### [A13] Secrets Hardening & API Environment Controls
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
* **Problem:** Offline `SPAM_REGEX` matches ordinary words (`congratulations`, `paypal`, `docusign`, `norton`, `betting`) and dumps valid customer emails straight into Junk. Threats and injections are handled inconsistently.
* **Solution:**
  1. Remove generic business terms from `SPAM_REGEX`; preserve only clear spam phrases.
  2. Route offline heuristic matches to `manual_review` instead of `spam_skipped`.
  3. Ensure all threats route consistently to `manual_review`.
* **Note on Benchmark Expectations:** Benchmark rows 76-90 (offline spam heuristics) currently assert `routing_status = 'spam_skipped'`. When B2 is implemented, heuristic matches will transition to `manual_review`.
* **Done When:** Unit tests verify common inquiries mentioning PayPal or DocuSign do not route to Junk.

### [B3] Consolidate Sensitive Keywords to Intent Phrases
* **Problem:** Bare words (`gdpr`, `police`, `erasure`) divert normal sales questions to legal review. Keyword list is duplicated across `nodes/sensitive_skip.py` and `config.yaml`.
* **Solution:**
  1. Replace bare words with intent phrases (`gdpr erasure request`, `police report`, `under article 17`).
  2. Establish `config.yaml` as the single source of truth, removing duplicate keyword lists in code.
  3. Implement scoring for sensitive phrases so ambiguous chargeback mentions can be differentiated from explicit dispute filings.
* **Done When:** `"Is your product GDPR compliant?"` is not diverted, while explicit erasure requests divert.

### [B4] Synchronize In-Memory State & SQLite Record
* **Problem:** For approved emails, database row is marked `done` with `gatekeeper_approved`, but returned state says `dispatch_status: 'processing'`. Active thread is conflated with routing status. Database write errors are swallowed.
* **Solution:**
  1. Align returned state: `dispatch_status: "done"`, `routing_status: "gatekeeper_approved"`.
  2. Treat active thread as metadata flag (`is_active_thread: true`), not routing status.
  3. Fail fast or mark email failed if database write fails.
  4. Persist masked subject and body in database for downstream Phase 2 workers.
* **Done When:** Unit test verifies returned state and database row match identically for approved emails.

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
