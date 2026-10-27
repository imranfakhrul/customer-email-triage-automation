# TypeSafe System One — Choice Question Specification Contract

**Reference:** [TypeSafe System One Documentation (docs.typesafe.ai)](https://docs.typesafe.ai)  
**Contract Version:** 1.0.0 (Verified Phase 1 & Phase 2 Alignment)  
**Protocol:** REST API (`POST https://api.typesafe.ai/v1/systemone`)

---

## 1. Specification Overview

In TypeSafe System One (Jev AI), a **Choice** question is a non-generative classification primitive that asks the model to select exactly **one option from a defined set of criteria** based on the provided `state`.

Unlike generative LLMs that produce conversational text, Jev returns:
1. `choice`: The winning discrete option string chosen from the defined criteria keys.
2. `confidence`: A single scalar metric between `0.0` and `1.0` derived from the concentration of probability mass.
3. `probabilities`: A probability distribution mapping across all defined options.

---

## 2. Request Structure (API Contract)

The request payload requires:
* `model`: Model identifier string (e.g. `"jev-1.13.0"`).
* `state`: The unstructured text or object representing the input state (e.g. masked email subject and body).
* `questions`: A dictionary mapping each custom question identifier to its question specification:
  * `type`: Fixed string `"choice"`.
  * `instructions`: The routing instruction or question guiding the model.
  * `criteria`: A dictionary where each key is an option identifier and each value describes that option.

### Example Request:
```json
{
  "model": "jev-1.13.0",
  "state": "Subject: 500 Internal Server Error on checkout\nBody: The payment submission endpoint is throwing an unhandled exception.",
  "questions": {
    "gmail_router": {
      "type": "choice",
      "instructions": "Which department action should handle this customer email?",
      "criteria": {
        "github_issue_create": "Technical bugs, code defects, crashes, or 500 errors requiring engineering attention",
        "freescout": "Standard customer support questions, helpdesk queries, or general assistance",
        "crm": "Sales leads, demo requests, enterprise plan upgrades, or contract inquiries",
        "webhook_node": "Automated system alerts, payment webhook triggers, or urgent billing disputes"
      }
    }
  }
}
```

---

## 3. Response Structure (API Contract)

The response from `POST /v1/systemone` returns an `answers` mapping keyed by question identifier:

### Example Response:
```json
{
  "model": "jev-1.13.0",
  "answers": {
    "gmail_router": {
      "choice": "github_issue_create",
      "confidence": 0.94,
      "probabilities": {
        "github_issue_create": 0.88,
        "webhook_node": 0.08,
        "freescout": 0.03,
        "crm": 0.01
      }
    }
  }
}
```

---

## 4. Architectural Limitation in Phase 2

* **Limitation:** Jev's 4 routing choices (`github_issue_create`, `freescout`, `crm`, `webhook_node`) map directly to destination dispatch targets, but cannot natively express the full 10-category taxonomy required by Phase 2 (`Bug Report`, `Feature Request`, `Demo Request`, `Pricing Inquiry`, `Billing Issue`, `Refund Request`, `Security/Account`, `Complaint`, `General Query`, `Other`), nor can it extract granular customer emotion (`Calm`, `Frustrated`, `Angry`).
* **Default Configuration:** `classification.jev.enabled: false` is configured by default in `config.yaml`.
* **Fallback Behavior:** When `classification.jev.enabled` is false, the classification engine delegates deep semantic extraction to Groq LLM (`openai/gpt-oss-120b`), with local offline heuristic fallback when external connectivity is absent.
