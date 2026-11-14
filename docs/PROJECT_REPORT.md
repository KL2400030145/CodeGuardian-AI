# CodeGuardian AI
## Project Report

**Project tagline:** Secure code. Ship with confidence.  
**Project type:** Python security-scanning web application  
**Academic context:** B.Tech Computer Science / Data Science project

> **Submission details to complete:** Add student name(s), roll number(s), department, institution, academic year, and supervisor before submitting this report.

## Abstract

CodeGuardian AI is a web application that helps developers review Python source code for selected security and code-quality issues. A user can submit a Python source file or ZIP archive through an authenticated interface. The FastAPI backend validates the upload, inspects source as data without executing it, invokes available static-analysis tools, records findings and scanner status, and persists the resulting scan history in SQLite. The React and TypeScript frontend presents project, scan, and dashboard views and provides JSON and PDF report downloads.

The application combines built-in pattern checks with Bandit, Ruff, and Radon. Semgrep can be used when installed. Authentication uses Argon2 password hashing, signed JWT access tokens, and rotating refresh tokens whose hashes are stored in the database and whose raw values are delivered in HttpOnly cookies. An optional OpenAI-compatible provider can explain a finding; AI is unavailable unless configured. This report describes implemented behavior and verified tests, while distinguishing optional integrations and future work from completed features.

## 1. Introduction

Security defects can enter a codebase through unsafe dynamic execution, embedded credentials, unsafe subprocess use, disabled TLS verification, and other risky patterns. Static-analysis tools can identify some of these issues early, but their output may be spread across command-line tools and may not provide durable, user-scoped history or a concise remediation workflow.

CodeGuardian AI brings selected static checks and persisted results into one local web application. It has a browser-based React frontend, a Python FastAPI API, SQLAlchemy persistence, and Alembic schema migrations. SQLite is the default database for development. The system is designed as a portfolio and learning project and is not a substitute for expert security review.

## 2. Problem Statement

Developers need a practical way to submit Python files or small repositories to static-analysis tools, understand and retain findings, and access results without executing untrusted uploads. A useful system must also protect project and scan records from other users, clearly represent scanner failures or unavailable tools, and remain usable without optional external AI services.

## 3. Objectives

1. Provide authenticated registration, sign-in, session refresh, and logout.
2. Accept `.py` files and ZIP archives containing Python files.
3. Validate uploads and archive entries, enforce configured limits, and never execute submitted source.
4. Combine built-in security rules with available static-analysis tools.
5. Persist projects, scans, findings, and report data in SQLite by default.
6. Restrict protected records to their authenticated owner.
7. Present scan statistics and recent activity in a dashboard.
8. Provide downloadable JSON and PDF reports based on stored scan results.
9. Keep AI explanations optional and explicitly unavailable when not configured.
10. Verify key flows with backend and frontend automated tests.

## 4. Existing System and Proposed System

### 4.1 Existing system

Traditional local workflows often require separate command-line invocations for each scanner. Results may be temporary, differently formatted, and disconnected from project ownership, scan history, or a common dashboard. Uploading unknown source to a service also raises concerns about execution and data handling.

### 4.2 Proposed system

CodeGuardian AI provides a single-user-facing application workflow that:

- Accepts source files and ZIP archives through an authenticated API.
- Validates archive paths and sizes and processes source as data only.
- Combines built-in checks, Bandit, Ruff, and Radon; Semgrep is optional.
- Reports scanner status and does not present unavailable or failed tools as successful.
- Stores user-scoped project and scan records in SQLite.
- Exposes dashboard and report endpoints over a protected API.
- Uses an optional OpenAI-compatible provider only when configured.

The proposed system improves workflow integration and traceability but does not guarantee complete vulnerability detection.

## 5. Requirements

### 5.1 Functional requirements

- Register an account with name, email, password, and terms acceptance.
- Authenticate with email and password; return an access token and refresh cookie.
- Refresh/rotate a valid refresh token; revoke a session at logout.
- Read and update user profile preferences, change password, list/revoke sessions, and delete an account.
- Create, list, inspect, and delete owned projects.
- Upload a Python file or ZIP archive for scanning.
- Return findings with rule, severity, file, line, snippet, description, recommendation, and source.
- Persist scans and findings, and associate scans with the authenticated owner and optional project.
- Retrieve dashboard statistics, scan history, activity, and individual scan reports.
- Download JSON and PDF reports based on stored scan results.
- Return an explicit unavailable response if AI explanation is requested without provider configuration.

### 5.2 Non-functional requirements

- **Security:** hash passwords; validate signed access tokens and active sessions; scope data by owner.
- **Untrusted-input handling:** apply upload limits and ZIP path/size/compression checks; never execute uploaded source.
- **Reliability:** expose health status including database/migration readiness; record scanner failures.
- **Maintainability:** use typed frontend code, modular FastAPI endpoints, SQLAlchemy models, and Alembic migrations.
- **Usability:** provide responsive navigation and clear finding/error feedback.
- **Portability:** support Windows local development and Docker Compose.
- **Data integrity:** use foreign keys and indexes; preserve existing scan rows through the SQLite migration.

## 6. System Architecture

The browser frontend calls the FastAPI backend over HTTP. Access tokens are sent as Bearer authorization headers, while refresh tokens use an HttpOnly cookie. The API performs authentication and owner checks before protected operations. Upload validation feeds a scanning pipeline; results are stored through SQLAlchemy in SQLite. The AI provider is an optional external integration.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for system, data-flow, scanning, and authentication Mermaid diagrams.

## 7. Module Descriptions

| Module | Responsibility |
|---|---|
| React application (`frontend/src/App.tsx`) | Routing, authentication screens, dashboard, projects, scans, reports, settings, and profile views |
| Frontend API client (`frontend/src/api.ts`) | API requests, in-memory access token, Bearer header, refresh coalescing, and session-expiration handling |
| FastAPI application (`backend/app/main.py`) | Health, authentication, user/profile, project, scan, dashboard, activity, report, and AI routes |
| Authentication/security (`backend/app/security.py`) | Argon2 password verification, JWT access tokens, refresh token generation/hash, and login attempt throttling |
| Scanner (`backend/app/scanner.py`) | Built-in pattern matching, Bandit, Ruff, Radon, optional Semgrep, status reporting, and deduplication |
| ORM models (`backend/app/models.py`) | User, Project, Scan, Finding, ScanReport, RefreshSession, and Activity entities |
| Database setup (`backend/app/db.py`) | SQLAlchemy engine/session setup and SQLite foreign-key enforcement |
| Schemas (`backend/app/schemas.py`) | Pydantic request/response validation |
| Alembic migrations (`backend/migrations`) | Versioned schema creation and SQLite-compatible legacy scan table updates |

## 8. Database Design

SQLite is the default database. `DATABASE_URL` defaults to `sqlite:///./codeguardian.db`; when Alembic and the backend are run from `backend`, the database file is `backend/codeguardian.db`. The schema is managed by Alembic.

### 8.1 Entities and relationships

- **User** has many projects, scans, refresh sessions, and activity records.
- **Project** belongs to a user and can be associated with scans.
- **Scan** belongs to a user (nullable for legacy migration compatibility) and can reference a project.
- **Finding** belongs to a scan.
- **ScanReport** belongs to a scan.
- **RefreshSession** belongs to a user; its `token_hash` is unique and indexed.
- **Activity** belongs to a user.

Deleting a user cascades to owned projects, scans, sessions, and activity according to ORM/database relationships. Deleting a project sets its scan references to null. Finding and report records cascade with their scan.

### 8.2 Principal fields

| Entity | Principal fields |
|---|---|
| User | `id`, `full_name`, `email`, `password_hash`, `theme`, `is_active`, timestamps |
| Project | `id`, `owner_id`, `name`, `description`, timestamps |
| Scan | `id`, `owner_id`, `project_id`, `filename`, `language`, `status`, `summary`, `findings_json`, `scanners_json`, `created_at` |
| Finding | `id`, `scan_id`, `rule_id`, `title`, `severity`, `file`, `line`, `snippet`, `description`, `recommendation`, `source`, `created_at` |
| ScanReport | `id`, `scan_id`, `format`, `content`, `created_at` |
| RefreshSession | `id`, `user_id`, `token_hash`, `expires_at`, `revoked_at`, `created_at`, `user_agent` |
| Activity | `id`, `owner_id`, `action`, `description`, `created_at` |

The scan model stores serialized finding/scanner data as well as normalized `Finding` records. Reports contain serialized report content. Indexes support lookups by user, scan, severity, rule, token hash, and session expiry.

### 8.3 SQLite migration notes

The initial migration creates identity/project/report-related tables and adds ownership and scanner metadata to an existing `scans` table. It uses Alembic batch table alteration for SQLite compatibility. The migration was tested against a disposable SQLite copy; the existing scan row and its pre-migration column values were verified unchanged. Before applying migrations to any database with important records, create and verify a separate backup.

## 9. Scanning Workflow

1. The authenticated client uploads a `.py` file or `.zip` archive to `POST /api/scans`.
2. The API reads at most the configured upload limit plus one byte and rejects an oversized upload.
3. ZIP inspection rejects unsafe paths, excessive file count/expanded size, unusual compression ratios, duplicate paths, and encrypted Python entries. Python files are decoded as text.
4. Source is written to temporary files for scanner input; it is not imported or executed.
5. Built-in CodeGuardian checks inspect selected patterns, including `eval`, `exec`, possible hard-coded credentials, `shell=True`, disabled TLS verification, and weak hash functions.
6. Bandit and Ruff run as Python modules; Radon reports functions/classes with cyclomatic complexity at or above the implementation threshold. Semgrep runs only if its executable is installed.
7. Findings are deduplicated by rule ID, file, line, and title. Scanner completion, absence, or failure is reflected in the scan response.
8. The API stores scan metadata, finding JSON, normalized findings, report data, and activity, then returns the scan.
9. Authenticated owners can retrieve scan details and download JSON or PDF reports.

## 10. Technologies Used

- **Frontend:** React 18, TypeScript, Vite, React Router, Axios, Recharts, Lucide.
- **Backend:** Python 3.13, FastAPI, Pydantic, SQLAlchemy.
- **Database/migrations:** SQLite, Alembic.
- **Authentication:** Argon2, JWT (`python-jose`), HttpOnly refresh cookies.
- **Analysis:** built-in Python checks, Bandit, Ruff, Radon, optional Semgrep.
- **Reports:** JSON serialization and ReportLab PDF generation.
- **Deployment:** Docker, Docker Compose.
- **Testing:** pytest, FastAPI TestClient/httpx, Vitest, Testing Library.

## 11. Implementation Details

### 11.1 Authentication

Passwords are hashed with Argon2 and are not returned in API payloads. Access tokens are signed using HS256 with user and session identifiers and an expiration. The API checks signature, token type, expiry, user activity, and the corresponding unrevoked, unexpired refresh session for protected requests.

Refresh tokens are generated from cryptographically secure randomness. Only their SHA-256 hashes are stored in `refresh_sessions`; the raw token is placed in an HttpOnly cookie. Refresh rotates the session and issues a new access token. Logout revokes the associated session and clears the cookie. The frontend keeps the access token in memory and uses a non-secret local-storage session-state marker to avoid unnecessary refresh attempts after logout.

### 11.2 Dashboard and reports

Dashboard values are computed from scans/findings belonging to the authenticated user. Security score is calculated as:

`max(0, 100 - 20*critical - 10*high - 5*medium - 1*low)`

JSON and PDF reports are generated from actual stored scan results, not hard-coded sample findings.

### 11.3 Optional AI

The AI endpoint requires an authenticated user and an `OPENAI_API_KEY`. `OPENAI_BASE_URL` and `OPENAI_MODEL` are optional configuration values. If the key is absent, the service returns an explicit unavailable response. User-provided finding text and code snippets are treated as untrusted data.

### 11.4 Configuration and execution

Backend configuration is read from environment variables and private `.env` files; `backend/.env.example` contains placeholders. SQLite is the default. Docker Compose uses a named volume for its database and runs migrations before starting the API.

## 12. Testing and Results

Only results actually verified in the project environment are reported here:

- Backend automated tests: `python -m pytest tests -q` — **7 passed**.
- Frontend automated tests: `npm.cmd test` — **10 tests passed**.
- Frontend production build: `npm.cmd run build` — **passed**, with a Vite warning that the minified JavaScript bundle exceeds 500 kB.
- Backend test coverage includes registration, duplicate registration, invalid credentials, login, protected dashboard access, refresh rotation, logout/revocation, CORS preflight, file/ZIP scanning, unsafe ZIP rejection, reports, ownership, and dashboard calculations.
- A live local API smoke test exercised disposable-account signup, login, dashboard access, refresh rotation, and logout. The disposable account was removed; existing user IDs and scan values were checked afterward.
- SQLite connectivity, integrity, migration state, and preserved scan history were verified during the audit.

These are project test results, not proof of complete security, correctness, performance, or production readiness.

## 13. Limitations

- Python is the implemented scan target; other programming languages are not scanned.
- Static analysis can produce false positives and false negatives.
- Semgrep is optional and is not included in the default backend requirements.
- AI explanations require an external provider credential and may send submitted snippets to that provider.
- Password-reset email and email verification are not implemented.
- GitHub OAuth and direct repository integration are not implemented.
- Login rate limiting is process-local, not distributed across workers.
- The Compose frontend uses Vite’s development server; the supplied setup is not a hardened production deployment.
- The application has not been presented as independently audited or penetration-tested.

## 14. Future Enhancements

1. Add browser end-to-end flows and broader integration testing to continuous integration.
2. Add explicit scanner policy configuration and richer finding triage.
3. Explore additional language scanners without executing repository code.
4. Add email verification and password reset only with a real, tested mail integration.
5. Add GitHub access only through a secure OAuth flow and least-privilege repository permissions.
6. Add production-serving containers, deployment manifests, secret management, observability, and operational documentation.
7. Improve report customization and historical trend analysis.
8. Consider externalized login throttling for multi-process deployments.

## 15. Conclusion

CodeGuardian AI demonstrates an end-to-end Python security-review workflow: authenticated upload, bounded archive validation, static analysis, persisted findings, owner-scoped dashboard access, and downloadable reports. Its design keeps SQLite convenient for local use, treats uploads as untrusted data, and makes optional scanners and AI dependencies explicit. Automated and live smoke tests verify key flows, while stated limitations make clear that the project is a development and educational aid rather than a guarantee of application security.

## References

1. FastAPI documentation. https://fastapi.tiangolo.com/
2. SQLAlchemy documentation. https://docs.sqlalchemy.org/
3. Alembic documentation. https://alembic.sqlalchemy.org/
4. SQLite documentation. https://www.sqlite.org/docs.html
5. React documentation. https://react.dev/
6. TypeScript documentation. https://www.typescriptlang.org/docs/
7. Vite documentation. https://vite.dev/guide/
8. Bandit documentation. https://bandit.readthedocs.io/
9. Ruff documentation. https://docs.astral.sh/ruff/
10. Radon documentation. https://radon.readthedocs.io/
11. Semgrep documentation. https://semgrep.dev/docs/
12. RFC 7519: JSON Web Token (JWT). https://www.rfc-editor.org/rfc/rfc7519
13. OWASP Cheat Sheet Series: Password Storage. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
14. OWASP Cheat Sheet Series: File Upload. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
