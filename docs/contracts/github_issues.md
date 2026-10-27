# GitHub Issues REST API Contract

Verified on 2026-10-27 from https://docs.github.com/en/rest/issues/issues and https://docs.github.com/en/rest/overview/resources-in-the-rest-api

## 1. Authentication
- **Transport Security:** HTTPS only (`https://api.github.com`). Plain HTTP or non-allowlisted hosts are rejected. Redirects are never followed for state-changing mutational calls.
- **Authorization Header:** `Authorization: Bearer <GITHUB_TOKEN>`.
- **Media Type & Headers:**
  - `Accept: application/vnd.github+json`
  - `User-Agent: Customer-Email-Triage-Automation` (Required by GitHub API policy; requests without User-Agent receive `403 Forbidden`).
  - `X-GitHub-Api-Version: 2022-11-28` (Currently documented official calendar version).
- **Token Scope & Permissions:**
  - Fine-grained Personal Access Token (PAT) scoped to the target repository with repository permission `Issues: Read and write`.
  - Classic PAT: scope `repo`.
- **Identity Resolution (`GET /user`):**
  - `GET /user` returns `200 OK` with user details (`{"login": "bot-username", ...}`) for classic tokens and user-scoped tokens.
  - **Fine-grained repo-scoped tokens and GitHub App installation tokens do not have User Account permissions and receive `403 Forbidden` on `GET /user`.**
  - **Fallback:** When `GET /user` fails or cannot be queried, the integration uses the configured `bot_login` setting to filter out self-authored issues.

## 2. Create an issue
- **Endpoint:** `POST /repos/{owner}/{repo}/issues`
- **Path Parameters:**
  - `owner` (`string`): GitHub username or organization name.
  - `repo` (`string`): Target repository name.
- **Request Body Parameters (JSON):**
  - `title` (`string`, required): Issue title (maximum 1,024 characters).
  - `body` (`string`, optional): Issue body text in Markdown (maximum 65,536 characters).
  - `labels` (`array of strings`, optional): Label names to attach to the issue. Labels are applied only if the authenticated token has push (triage/write) access to the repository; otherwise, labels are silently omitted or return an error.
- **Responses:**
  - `201 Created`: Issue successfully created. Returns issue object containing `number`, `html_url`, `id`, `node_id`, `state`, `title`, `body`, `user`, `labels`, `created_at`.
  - `400 Bad Request`: Invalid request JSON.
  - `401 Unauthorized`: Bad or expired credentials.
  - `403 Forbidden`: Insufficient permissions or primary/secondary rate limit exceeded.
  - `404 Not Found`: Repository not found or token lacks access.
  - `410 Gone`: Issues are disabled for the repository.
  - `422 Unprocessable Entity`: Validation failure (e.g., missing title, malformed labels).

## 3. List repository issues
- **Endpoint:** `GET /repos/{owner}/{repo}/issues`
- **Query Parameters:**
  - `milestone` (`string`, optional): Milestone number, `"none"`, or `"*"` (any).
  - `state` (`string`, optional): Filter by issue state: `"open"`, `"closed"`, `"all"`. Default: `"open"`.
  - `assignee` (`string`, optional): Username, `"none"`, or `"*"` (any).
  - `creator` (`string`, optional): Username of the issue creator.
  - `mentioned` (`string`, optional): Username mentioned in the issue.
  - `labels` (`string`, optional): Comma-separated list of label names (e.g. `"triage:automated,bug"`).
  - `sort` (`string`, optional): `"created"`, `"updated"`, `"comments"`. Default: `"created"`.
  - `direction` (`string`, optional): `"asc"`, `"desc"`. Default: `"desc"`.
  - `since` (`string`, optional): Only issues updated at or after this ISO 8601 timestamp (e.g. `2026-10-24T12:00:00Z`).
  - `per_page` (`integer`, optional): Results per page, maximum `100`. Default: `30`.
  - `page` (`integer`, optional): Page number of results. Default: `1`.
- **Item Fields Used:**
  - `number` (`integer`): Issue sequence number within repository.
  - `html_url` (`string`): Canonical web URL for the issue.
  - `user.login` (`string`): Username of the issue author.
  - `body` (`string` or `null`): Full issue description body (may be `null` if empty).
  - `pull_request` (`object` or absent): **Important:** GitHub Issues API returns both issues and pull requests. Items containing a `pull_request` key represent PRs and must be ignored during duplicate issue verification.

## 4. Rate limits
- **Primary Rate Limits:**
  - Standard authenticated limit: 5,000 requests per hour.
  - Exhaustion response: Status code `403 Forbidden`.
  - Headers:
    - `x-ratelimit-remaining: 0`
    - `x-ratelimit-reset: <epoch_seconds>`
- **Secondary Rate Limits:**
  - Triggered by rapid concurrent requests or burst mutational actions (`POST`/`PATCH`).
  - Status codes: `403 Forbidden` or `429 Too Many Requests`.
  - Error message in response body indicates secondary rate limit violation.
  - Header: `retry-after: <seconds>` (integer count of seconds to pause before retrying).
  - Safe behavior: Treat `429` and `403` with rate limit headers as `AdapterTransientError` and back off exponentially.

## 5. Limits
- **Issue Title:** Maximum length 1,024 characters. (Our application restricts titles to 120 characters).
- **Issue Body:** Maximum length 65,536 characters. (Our application restricts bodies to < 30,000 characters).
- **Label Name:** Maximum length 50 characters. Must not contain commas.
- **Search vs List Duplicate Strategy:**
  - Search Issues API (`GET /search/issues`) has a strict dedicated rate limit of 30 requests per minute and can have index latency.
  - The repository Issues List API (`GET /repos/{owner}/{repo}/issues?since=...&sort=created&direction=desc`) operates under standard 5,000 req/hr limits, providing immediate consistency for bot-authored duplicate detection.
