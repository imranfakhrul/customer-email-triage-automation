# HubSpot CRM REST API v3 Contract

## 1. Overview
This document specifies the HTTP API contract for the Customer Email Triage Automation pipeline interfacing with HubSpot CRM REST API v3 for inbound lead creation (`create_lead` action).

## 2. Authentication & Base URL
- **Base URL:** `https://api.hubapi.com` (strictly allowlisted, HTTPS only)
- **Authentication:** Bearer token via `Authorization: Bearer <CRM_API_KEY>`
- **Environment Variable:** `CRM_API_KEY` (or custom configured `api_key_env`)
- **Headers:**
  - `Authorization`: `Bearer <CRM_API_KEY>`
  - `Content-Type`: `application/json`
  - `Accept`: `application/json`
  - `User-Agent`: `Customer-Email-Triage-Automation`

## 3. Endpoints

### 3.1 Contact Lookup / Deduplication Pre-Check
- **Method:** `GET`
- **Path:** `/crm/v3/objects/contacts/{email}?idProperty=email`
- **Query Parameters:**
  - `idProperty`: `email`
  - `properties`: `email,firstname,lastname,company,hs_lead_status,triage_email_id,triage_idempotency_key`
- **Responses:**
  - `200 OK`: Contact exists. Response body contains `id`, `properties`.
  - `404 Not Found`: Contact does not exist. Safe to proceed with creation.

### 3.2 Create Contact / Lead
- **Method:** `POST`
- **Path:** `/crm/v3/objects/contacts`
- **Request Body (JSON):**
  ```json
  {
    "properties": {
      "email": "jane.prospect@enterprise.com",
      "firstname": "Jane",
      "lastname": "Prospect",
      "phone": "+1-555-0199",
      "company": "enterprise.com",
      "hs_lead_status": "NEW",
      "lead_score": "85",
      "triage_email_id": "em_001",
      "triage_idempotency_key": "idemp_crm_em001",
      "message": "We would like to request an enterprise demo for 500 seats."
    }
  }
  ```
- **Responses:**
  - `201 Created`: Contact created successfully. Response body contains `id`, `createdAt`, `properties`.
  - `409 Conflict`: Existing contact collision. Response body contains `message` with existing contact ID or `context.id`.
  - `422 Unprocessable Entity`: Validation failure.
  - `429 Too Many Requests`: Rate limit exceeded.
  - `503 Service Unavailable`: Temporary upstream downtime.

## 4. Privacy & Hardening Guarantees
1. **Universal Selective Unmasking:** Restores contact info (`PERSON`, `EMAIL`, `PHONE`, `IP_ADDRESS`) so sales reps can reach prospects.
2. **Secret Defense:** `CREDIT_CARD`, `SSN`, `IBAN`, and `API_KEY` are permanently blocked from unmasking.
3. **Formula / CSV Injection Defanging:** All string fields starting with `=`, `+`, `-`, `@`, `\t`, `\r` are prefixed with `'` to prevent spreadsheet code execution when exported.
4. **Freemail Domain Filtering:** Personal email domains (`gmail.com`, `yahoo.com`, `hotmail.com`, etc.) are recognized so corporate domains can be properly scored.
