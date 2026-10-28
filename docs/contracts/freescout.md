# FreeScout Helpdesk REST API v1 Contract

Verified against FreeScout API documentation (https://github.com/freescout-helpdesk/freescout / Help Scout API v1 format).

## 1. Authentication & Security
- **Transport Security:** HTTPS only (`https://<configured-freescout-host>`). Plain HTTP or non-allowlisted hosts are rejected. Redirects are never followed for mutational calls.
- **API Key Header:** `X-FreeScout-API-Key: <FREESCOUT_API_KEY>` (or query parameter `apiKey=<key>`). Header is enforced for security.
- **Request Headers:**
  - `Accept: application/json`
  - `Content-Type: application/json`
  - `User-Agent: Customer-Email-Triage-Automation`
- **Scope & Permissions:**
  - The API key must belong to an active user with permissions to create and view conversations in the target mailbox.

## 2. Endpoints

### 2.1 Create Conversation (New Ticket)
- **Endpoint:** `POST /api/conversations`
- **Request JSON Schema:**
  ```json
  {
    "mailboxId": 1,
    "type": "email",
    "status": "active",
    "subject": "Ticket Subject Line",
    "customer": {
      "email": "customer@example.com",
      "firstName": "First",
      "lastName": "Last"
    },
    "threads": [
      {
        "type": "customer",
        "text": "<p>Sanitized HTML body</p>",
        "customer": {
          "email": "customer@example.com"
        }
      }
    ]
  }
  ```
- **Responses:**
  - `201 Created`:
    - Headers: `Location: /api/conversations/{id}`
    - JSON Body: `{"id": 12345, "number": 101, "mailboxId": 1, "status": "active", "subject": "...", "createdAt": "..."}`
  - `400 Bad Request`: Invalid request JSON.
  - `401 Unauthorized`: Missing or invalid API key.
  - `403 Forbidden`: User lacks permission for the specified mailbox.
  - `422 Unprocessable Entity`: Validation failure (e.g. missing `mailboxId`, missing `customer.email`, or empty `threads`).
  - `429 Too Many Requests`: Rate limit exceeded.
  - `500 / 503`: Internal Server Error or Service Unavailable.

### 2.2 List / Search Conversations (Duplicate & Thread Continuity Pre-Check)
- **Endpoint:** `GET /api/conversations`
- **Query Parameters:**
  - `mailboxId` (`integer`, optional): Filter by mailbox ID.
  - `status` (`string`, optional): Filter by status: `"active"`, `"pending"`, `"closed"`, `"all"`. Default: `"all"`.
  - `page` (`integer`, optional): Page number (default `1`).
- **Response JSON Schema:**
  ```json
  {
    "page": 1,
    "pages": 1,
    "count": 1,
    "items": [
      {
        "id": 12345,
        "number": 101,
        "mailboxId": 1,
        "type": "email",
        "status": "active",
        "subject": "Ticket Subject",
        "customer": {
          "id": 99,
          "email": "customer@example.com"
        },
        "threads": [
          {
            "id": 54321,
            "type": "customer",
            "body": "<!-- triage-bot:v1\nkey: em_123:freescout:create_ticket\n-->\n<p>Body</p>"
          }
        ],
        "createdAt": "2026-10-28T12:00:00Z"
      }
    ]
  }
  ```

### 2.3 Append Thread (Reply to Existing Conversation)
- **Endpoint:** `POST /api/conversations/{id}/threads`
- **Request JSON Schema:**
  ```json
  {
    "type": "customer",
    "text": "<p>Reply text with correlation marker</p>",
    "customer": {
      "email": "customer@example.com"
    },
    "status": "active"
  }
  ```
- **Responses:**
  - `201 Created`: Message appended to conversation.
  - `404 Not Found`: Conversation ID does not exist.
  - `422 Unprocessable Entity`: Invalid thread data.

## 3. Rate Limits
- FreeScout instances typically run on self-hosted Nginx/PHP-FPM or Apache.
- Standard default rate limit: 100 requests per minute per API key.
- Response on rate limit: HTTP status `429 Too Many Requests` (or `403` with rate limit message).
- Safe behavior: Exponential backoff with jitter on 429 and 503 (`AdapterTransientError`).

## 4. Output Hardening & Sanitization
- Body is stored and rendered as HTML in FreeScout.
- Untrusted customer text must be HTML-escaped (`&`, `<`, `>`, `"`, `'`) before wrapping in paragraph tags.
- Bidi override characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`) and control characters are stripped.
- The system correlation marker `<!-- triage-bot:v1\nkey: ...\n-->` is anchored strictly at index 0 of thread text.
