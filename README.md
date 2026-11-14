# CodeGuardian AI

**Secure code. Ship with confidence.**

CodeGuardian AI is a portfolio application for reviewing Python source code for common security and quality issues. Upload a Python file or ZIP archive, inspect findings from multiple static-analysis tools, and keep scan results in an authenticated workspace.

The project combines a React and TypeScript frontend with a FastAPI backend. SQLite is the default local database. Uploaded source code is analyzed as data and is never executed by the application.

> Automated findings are security guidance, not a guarantee that code is secure. Validate findings and proposed remediations before changing production systems.

## Contents

- [Problem and objectives](#problem-and-objectives)
- [Implemented features](#implemented-features)
- [Technology stack](#technology-stack)
- [Architecture and scanning workflow](#architecture-and-scanning-workflow)
- [Requirements](#requirements)
- [Run locally on Windows](#run-locally-on-windows)
- [Configuration](#configuration)
- [Authentication and optional AI](#authentication-and-optional-ai)
- [Docker Compose](#docker-compose)
- [SQLite database and migrations](#sqlite-database-and-migrations)
- [API overview](#api-overview)
- [Security considerations](#security-considerations)
- [Screenshots](#screenshots)
- [Tests and verification](#tests-and-verification)
- [Current limitations and future enhancements](#current-limitations-and-future-enhancements)

## Problem and objectives

Security scanners can produce findings that are difficult for developers to triage, while locally run tools often leave results disconnected from project and scan history. CodeGuardian AI provides a small, approachable workflow for:

- Scanning Python source and repository ZIP files without running uploaded code.
- Combining deterministic checks with established static-analysis tools.
- Reviewing results, severities, and remediation guidance in one interface.
- Keeping authenticated, owner-scoped project and scan records for later review.

The application is intended for learning, demonstration, and development assistance. It is not a replacement for a professional security assessment or a production security program.

## Implemented features

- Account registration, login, logout, session listing/revocation, profile preferences, password change, and account deletion.
- Argon2 password hashing and signed JWT access tokens.
- Short-lived access tokens with rotating refresh tokens stored as hashes in the database and delivered using an HttpOnly cookie.
- Authenticated, owner-scoped projects, scans, dashboard statistics, and activity.
- Python `.py` file and `.zip` repository uploads, with an upload-size limit and archive safety checks.
- Built-in CodeGuardian checks for selected risky Python patterns.
- Bandit security analysis, Ruff lint findings, and Radon cyclomatic-complexity findings when available.
- Optional Semgrep analysis when its executable is installed.
- Finding deduplication by rule, file, line, and title.
- Scanner status reporting so missing or failed scanners are not reported as successful.
- Stored scan findings with downloadable JSON and PDF reports.
- Optional AI explanations for a finding and code snippet when an OpenAI-compatible API is configured.
- A dashboard with stored scan totals, finding severities, recent scans, and a documented risk-weighted score.

The score starts at 100 and subtracts 20 per critical, 10 per high, 5 per medium, and 1 per low finding across the user’s recorded scans, with a floor of 0.

## Technology stack

| Area | Technologies |
|---|---|
| Frontend | React 18, TypeScript, Vite, React Router, Axios, Recharts, Lucide |
| Backend | Python 3.13, FastAPI, Pydantic, SQLAlchemy |
| Database | SQLite by default; Alembic migrations |
| Authentication | Argon2, JWT, hashed refresh tokens, HttpOnly cookies |
| Static analysis | CodeGuardian rules, Bandit, Ruff, Radon; optional Semgrep |
| Reports | JSON and PDF |
| Containers | Docker and Docker Compose |

## Architecture and scanning workflow

```mermaid
flowchart LR
    Browser[React + TypeScript frontend] -->|HTTP API, access token, refresh cookie| API[FastAPI]
    API --> Auth[Authentication and ownership checks]
    API --> Validate[Upload and ZIP validation]
    Validate --> Analyze[Static analysis pipeline]
    Analyze --> Rules[CodeGuardian rules]
    Analyze --> Bandit[Bandit]
    Analyze --> Ruff[Ruff]
    Analyze --> Radon[Radon complexity]
    Analyze -. optional .-> Semgrep[Semgrep]
    API --> DB[(SQLite)]
    Analyze --> Persist[Findings and report persistence]
    Persist --> DB
    API -. configured only .-> AI[OpenAI-compatible API]
```

1. The authenticated user submits a `.py` file or ZIP archive to `POST /api/scans`.
2. The API enforces the configured upload-size limit, validates archive entries, and reads Python source files. It does not import or execute the uploaded code.
3. Scanner tools analyze temporary copies of source files. The API records each scanner’s completion, missing, or failure status and deduplicates matching findings.
4. The scan, findings, report data, and activity are stored in SQLite and associated with the authenticated owner and, optionally, a project.
5. The frontend retrieves owner-scoped results through protected API endpoints.

## Requirements

- Python 3.13 (the PowerShell examples use the Windows Python launcher).
- Node.js 20+ and npm.
- Optional: Docker Desktop for the container workflow.

## Run locally on Windows

Open PowerShell in the project root and create the backend environment:

```powershell
py -3.13 -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements.txt
if (!(Test-Path backend\.env)) { Copy-Item backend\.env.example backend\.env }
```

Before using the application, edit `backend\.env` and set a private, stable, randomly generated `SECRET_KEY`. Keep this file local and do not commit it.

Apply the SQLite migration and run the API:

```powershell
Set-Location backend
python -m alembic upgrade head
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second PowerShell terminal, from the project root:

```powershell
Set-Location frontend
npm.cmd install
npm.cmd run dev
```

The frontend uses port `5174`; the API uses port `8000`.

- Frontend: http://localhost:5174
- API health: http://127.0.0.1:8000/health
- Interactive API documentation: http://127.0.0.1:8000/docs

The frontend selects the local API hostname to match the browser hostname (`localhost` or `127.0.0.1`). To specify another API URL, set `VITE_API_URL` in the frontend build/development environment. The backend CORS allowlist includes the local frontend origins on ports 5173 and 5174; `CORS_ORIGINS` can override/add configured origins, and the two CodeGuardian development origins on port 5174 are also allowed.

## Configuration

`backend\.env.example` contains placeholders and safe local defaults. Copy it to `backend\.env` and configure only the values needed for your environment.

| Variable | Purpose | Default/notes |
|---|---|---|
| `APP_ENV` | Environment mode and cookie security behavior | `development`; use `production` behind HTTPS for deployment |
| `SECRET_KEY` | Signs access tokens | Set a stable random secret; required in production |
| `DATABASE_URL` | SQLAlchemy database connection | `sqlite:///./codeguardian.db` |
| `CORS_ORIGINS` | Comma-separated browser origins | Local development origins on ports 5173 and 5174 |
| `MAX_UPLOAD_MB` | Maximum upload size | `15` |
| `ACCESS_TOKEN_MINUTES` | Access-token lifetime | `15` |
| `REFRESH_TOKEN_DAYS` | Default refresh-token lifetime | `7`; login may choose a shorter or longer session based on “Remember me” |
| `OPENAI_API_KEY` | Optional AI provider credential | Empty/unset disables AI explanations |
| `OPENAI_BASE_URL` | Optional OpenAI-compatible API endpoint | Empty uses the provider client default |
| `OPENAI_MODEL` | AI model name | `gpt-4o-mini` |

The backend loads a root `.env` first, then `backend\.env` without overriding values already loaded. Keep both files private. SQLite remains the default; `DATABASE_URL` can be set to another SQLAlchemy URL only when intentionally configuring a supported database and driver.

Optional SQLAlchemy URL formats are shown below with placeholders only; they do not change the SQLite default:

```text
postgresql+psycopg://USER:PASSWORD@localhost:5432/codeguardian
mysql+pymysql://USER:PASSWORD@localhost:3306/codeguardian
```

URL-encode special characters in a database username or password. Do not copy real credentials into this README or any tracked file.

## Authentication and optional AI

### Authentication

- Registration requires a name, valid email, password meeting the backend validation rules, and accepted terms.
- Passwords are hashed with Argon2; password hashes are not included in API responses.
- Login and registration return a short-lived access token. The frontend keeps the access token in memory and sends it as a Bearer token for protected requests.
- Refresh tokens are random, stored server-side only as hashes, and sent in an HttpOnly cookie. The refresh endpoint validates and rotates the token.
- Logout revokes the refresh session and clears the cookie. Protected routes validate the access token and its active session.
- Login attempts are rate-limited in application memory.

Email verification and password-reset email delivery are not configured. The forgot-password UI indicates that no email is sent.

### Optional AI explanations

AI explanations are disabled unless `OPENAI_API_KEY` is configured. An OpenAI-compatible service may also use `OPENAI_BASE_URL` and `OPENAI_MODEL`. Without a key, the API reports AI explanations as unavailable rather than generating a placeholder response. Treat findings and source snippets as untrusted input; the application instructs the provider not to follow embedded instructions.

## Docker Compose

Docker Compose expects `backend\.env`. Create it from the example if needed:

```powershell
if (!(Test-Path backend\.env)) { Copy-Item backend\.env.example backend\.env }
docker compose up --build
```

Compose starts the frontend on port `5174` and backend on port `8000`. The backend container applies Alembic migrations before starting Uvicorn. By default, the container database URL points to `/app/data/codeguardian.db` in the named `codeguardian_data` volume. The frontend container runs the Vite development server; this Compose setup is for local development, not a hardened production deployment.

The named volume persists database data. Do **not** use `docker compose down -v` if you want to keep it. Use `docker compose down` to stop the services without removing the volume.

## SQLite database and migrations

The default local database is `backend\codeguardian.db` when commands are run from the `backend` directory. Alembic migrations are designed to work with SQLite, including the batch table-alter operation used to add ownership and scanner metadata to an existing `scans` table.

Before applying a migration to a database with important records, make a separate backup and verify it exists:

```powershell
Set-Location backend
$backup = ".\codeguardian.db.pre-migration-$(Get-Date -Format yyyyMMdd-HHmmss).bak"
Copy-Item .\codeguardian.db $backup
Get-Item $backup
```

Then apply pending migrations:

```powershell
python -m alembic upgrade head
python -m alembic current
```

The migration adds tables and columns; it does not intentionally delete scan rows. The first registered account is associated with legacy scans that do not yet have an owner. Back up the database before migration and verify your records afterward.

## API overview

The complete interactive schema is available at `/docs` while the backend is running.

| Endpoint | Purpose | Authentication |
|---|---|---|
| `GET /health` | Database-aware service health | No |
| `POST /api/auth/register` | Register and create a session | No |
| `POST /api/auth/login` | Sign in and create a session | No |
| `POST /api/auth/refresh` | Rotate the refresh session | Refresh cookie |
| `POST /api/auth/logout` | Revoke the current refresh session | Refresh cookie |
| `GET /api/auth/me` | Current user profile | Bearer token |
| `GET /api/projects` | List owned projects | Bearer token |
| `POST /api/projects` | Create a project | Bearer token |
| `POST /api/scans` | Scan a Python file or ZIP archive | Bearer token |
| `GET /api/scans` | List owned scans | Bearer token |
| `GET /api/dashboard` | Owner-scoped dashboard totals and activity | Bearer token |
| `GET /api/scans/{id}/report.json` | Download a JSON scan report | Bearer token |
| `GET /api/scans/{id}/report.pdf` | Download a PDF scan report | Bearer token |
| `POST /api/ai/explain` | Explain a finding using a configured provider | Bearer token; API key required |

Additional endpoints for profile updates, password changes, session management, account/project deletion, activity, scan details, and AI explanations are documented in the interactive API docs.

## Security considerations

- Never commit `.env` files, API keys, database passwords, or real user data. The example environment files use placeholders.
- Use a stable, unpredictable `SECRET_KEY`; do not rely on the development fallback for deployed environments.
- Use HTTPS and `APP_ENV=production` when deploying so refresh cookies use secure transport.
- Uploaded source code is treated as data and is never executed. Scanner processes inspect temporary files only.
- Upload limits and ZIP checks mitigate oversized archives, unsafe paths, duplicate entries, and excessive compression.
- Project, scan, report, and activity access is scoped to the authenticated owner.
- Refresh tokens are stored as hashes; access tokens are validated for signature, expiry, token type, user, and active session.
- Findings may be incomplete or incorrect. Review scanner status and validate results before relying on them.
- Do not send sensitive source snippets to an external AI provider unless your organization permits it.
- The development Vite server and this project configuration should not be exposed directly as production infrastructure.

## Screenshots

Replace these placeholders with genuine screenshots captured from a running application. Avoid including real credentials, private source code, or personal data.

> **Dashboard:** Screenshot placeholder. Add a genuine capture at `docs/screenshots/dashboard.png`.
>
> **Scan findings:** Screenshot placeholder. Add a genuine capture at `docs/screenshots/scan-findings.png`.
>
> **Authentication or projects:** Screenshot placeholder. Add a genuine capture at `docs/screenshots/auth-or-projects.png`.

## Tests and verification

The following results were verified in the project environment during the latest audit:

- Backend: `python -m pytest tests -q` — **7 passed**.
- Frontend: `npm.cmd test` — **10 tests passed**.
- Frontend production build: `npm.cmd run build` — **passed**. Vite reports a warning that the minified JavaScript bundle exceeds 500 kB.
- Authentication integration coverage includes registration, duplicate registration, invalid credentials, login, protected dashboard access, refresh-token rotation, logout/revocation, and CORS preflight.
- Scanner/report coverage includes Python and ZIP upload paths, findings, JSON/PDF reports, project ownership, and dashboard statistics.
- A live signup/login/dashboard/refresh/logout smoke test was also exercised against the local API using a disposable account; the account was removed afterward, and the pre-existing scan record was verified unchanged.

Run the backend tests from `backend`:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
```

Run the frontend tests and build from `frontend`:

```powershell
npm.cmd test
npm.cmd run build
```

Test counts describe the current suite at the time of verification and may change as tests are added.

## Current limitations and future enhancements

### Current limitations

- Python is the implemented scan target; other languages are not scanned.
- Semgrep is optional and is not installed by the default backend requirements.
- AI assistance covers explaining a finding and optional snippet; it is not a general repository-wide autonomous review.
- Email verification and password-reset delivery are not implemented.
- GitHub OAuth/repository access is not implemented.
- Login rate limiting is process-local and is not a distributed rate limiter.
- The Docker Compose frontend runs Vite’s development server. Production deployment needs an appropriately hardened frontend server, HTTPS termination, secret management, and operational monitoring.

### Possible future enhancements

- Add stronger integration and browser-level end-to-end coverage to CI.
- Provide production-oriented container serving, deployment manifests, and observability.
- Add configurable scanner policies and broader language support.
- Add real email delivery and OAuth flows with secure token handling.
- Improve dashboard analytics and report customization while retaining traceability to stored findings.
