# CodeGuardian AI — Architecture

This document describes the implemented application at a component and request-flow level. SQLite is the default local database. Semgrep and AI-provider connectivity are optional.

## 1. System architecture

```mermaid
flowchart LR
    Browser["Browser UI<br/>React + TypeScript + Vite"]
    API["FastAPI application"]
    Auth["Authentication<br/>Argon2 + JWT + refresh sessions"]
    Validate["Upload validation<br/>size + ZIP safety"]
    Scan["Static analysis pipeline"]
    Rules["CodeGuardian rules"]
    Bandit["Bandit"]
    Ruff["Ruff"]
    Radon["Radon"]
    Semgrep["Semgrep<br/>(optional installation)"]
    ORM["SQLAlchemy ORM"]
    DB[("SQLite<br/>codeguardian.db")]
    Reports["JSON / PDF reports"]
    AI["OpenAI-compatible provider<br/>(optional key/configuration)"]

    Browser -->|"HTTP API; Bearer token"| API
    Browser -->|"HttpOnly refresh cookie"| API
    API --> Auth
    API --> Validate
    Validate --> Scan
    Scan --> Rules
    Scan --> Bandit
    Scan --> Ruff
    Scan --> Radon
    Scan -. optional .-> Semgrep
    API --> ORM
    Scan --> ORM
    ORM <--> DB
    API --> Reports
    API -. configured only .-> AI
    Reports --> API
    API -->|"JSON responses"| Browser
```

### Component responsibilities

- **Browser UI:** login/registration, navigation, dashboard, projects, scan submission, findings, reports, settings, and profile.
- **FastAPI:** request validation, CORS, authentication, ownership checks, scanning orchestration, dashboard aggregation, and report endpoints.
- **Authentication:** Argon2 password hashes, signed access JWTs, refresh-session records, rotation, and revocation.
- **Scanner:** deterministic checks and integrations with installed analysis tools. Scanner statuses distinguish completed, unavailable, and failed tools.
- **SQLite/SQLAlchemy:** application records and relational ownership; Alembic tracks schema revisions.
- **Optional AI:** finding explanations only when provider configuration is present; this is not required for normal scanning.

## 2. Data flow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as React frontend
    participant API as FastAPI
    participant Auth as Auth dependency
    participant Scanner as Scanner pipeline
    participant ORM as SQLAlchemy
    participant DB as SQLite

    User->>UI: Choose Python file or ZIP
    UI->>API: POST /api/scans + Bearer access token
    API->>Auth: Validate token and active session
    Auth->>DB: Load user/session
    DB-->>Auth: Active owner identity
    Auth-->>API: Authenticated user
    API->>API: Enforce upload and archive limits
    API->>Scanner: Pass decoded Python source as data
    Note over API,Scanner: Uploaded source is not executed
    Scanner->>Scanner: Built-in rules, Bandit, Ruff, Radon
    opt Semgrep installed
        Scanner->>Scanner: Run Semgrep
    end
    Scanner-->>API: Findings + per-scanner status
    API->>ORM: Create scan, findings, report, activity
    ORM->>DB: Commit owner-scoped records
    DB-->>ORM: Persisted records
    ORM-->>API: Scan result
    API-->>UI: Scan summary and findings
    UI-->>User: Display results
```

## 3. Code scanning workflow

```mermaid
flowchart TD
    Start([Authenticated upload]) --> Type{"File extension"}
    Type -->|".py"| Read["Decode as Python source text"]
    Type -->|".zip"| Zip["Inspect ZIP central directory"]
    Type -->|Other| Reject["Reject unsupported upload"]
    Zip --> Checks{"Path, count, size,<br/>compression, duplicates valid?"}
    Checks -->|No| RejectZip["Reject unsafe/oversized archive"]
    Checks -->|Yes| Extract["Read Python entries as text"]
    Read --> Limit["Enforce configured upload limit"]
    Extract --> Limit
    Limit --> Rules["Built-in CodeGuardian rules"]
    Rules --> Bandit["Bandit, if installed"]
    Bandit --> Ruff["Ruff, if installed"]
    Ruff --> Radon["Radon complexity analysis"]
    Radon --> SemgrepCheck{"Semgrep executable present?"}
    SemgrepCheck -->|Yes| Semgrep["Run Semgrep"]
    SemgrepCheck -->|No| Status["Record Semgrep not installed"]
    Semgrep --> Status
    Status --> Dedup["Deduplicate by rule, file,<br/>line, and title"]
    Dedup --> Persist["Persist scan, findings,<br/>report, activity"]
    Persist --> Result([Return status and findings])

    Reject --> Error([Return validation error])
    RejectZip --> Error
    Note["No uploaded source code is imported or executed"] -.-> Read
    Note -.-> Extract
```

The upload path applies the configured maximum byte size. ZIP validation also checks file count, path traversal/absolute paths, expanded size, unusually high compression ratio, duplicate Python paths, and encrypted Python entries. Scanner tools receive temporary source files as data. A tool that is unavailable or fails is represented in scanner status rather than silently treated as successful.

## 4. Authentication workflow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant UI as React frontend
    participant API as FastAPI
    participant Hash as Argon2 / JWT / token hash
    participant DB as SQLite

    User->>UI: Submit registration or login
    UI->>API: POST /api/auth/register or /api/auth/login
    API->>DB: Find/create user
    API->>Hash: Hash password or verify stored hash
    Hash-->>API: Password verification result
    API->>DB: Create RefreshSession with token hash
    API->>Hash: Sign short-lived access JWT
    API-->>UI: Access token + user + HttpOnly refresh cookie
    Note over UI: Access token held in memory;<br/>not persisted as plaintext

    UI->>API: Protected request + Authorization: Bearer token
    API->>Hash: Verify signature, expiry, and token type
    API->>DB: Verify active user and unrevoked session
    DB-->>API: Active session / user
    API-->>UI: Owner-scoped response

    opt Access token expired while refresh session remains valid
        UI->>API: POST /api/auth/refresh + cookie
        API->>Hash: Hash presented refresh token
        API->>DB: Find, validate, and revoke old session
        API->>DB: Store replacement token hash
        API-->>UI: New access token + replacement HttpOnly cookie
    end

    User->>UI: Log out
    UI->>API: POST /api/auth/logout + cookie
    API->>DB: Revoke refresh session
    API-->>UI: Clear refresh cookie; 204
```

Invalid, expired, or revoked access tokens are rejected by the protected-route dependency. Missing or invalid refresh cookies do not yield a successful session. The frontend coalesces concurrent refresh requests, retries a protected request at most once, and returns a logged-out user to the login route after refresh failure.

## 5. Persistence model

```mermaid
erDiagram
    USER ||--o{ PROJECT : owns
    USER ||--o{ SCAN : owns
    USER ||--o{ REFRESH_SESSION : has
    USER ||--o{ ACTIVITY : generates
    PROJECT o|--o{ SCAN : groups
    SCAN ||--o{ FINDING : contains
    SCAN ||--o{ SCAN_REPORT : produces

    USER {
        int id PK
        string full_name
        string email UK
        string password_hash
        string theme
        bool is_active
        datetime created_at
        datetime updated_at
    }
    PROJECT {
        int id PK
        int owner_id FK
        string name
        text description
        datetime created_at
        datetime updated_at
    }
    SCAN {
        int id PK
        int owner_id FK
        int project_id FK
        string filename
        string language
        string status
        text findings_json
        text scanners_json
        datetime created_at
    }
    FINDING {
        int id PK
        int scan_id FK
        string rule_id
        string severity
        string file
        int line
        string source
    }
    SCAN_REPORT {
        int id PK
        int scan_id FK
        string format
        text content
        datetime created_at
    }
    REFRESH_SESSION {
        int id PK
        int user_id FK
        string token_hash UK
        datetime expires_at
        datetime revoked_at
    }
    ACTIVITY {
        int id PK
        int owner_id FK
        string action
        string description
        datetime created_at
    }
```

## 6. Deployment and local ports

- Frontend development server: `http://localhost:5174`
- Backend API: `http://127.0.0.1:8000`
- Health endpoint: `/health`
- Interactive API documentation: `/docs`
- Local default database: `backend/codeguardian.db` when running backend commands from `backend`
- Docker Compose database: named `codeguardian_data` volume at `/app/data/codeguardian.db` by default

The Compose backend applies migrations before Uvicorn starts. The Compose frontend uses Vite's development server and is not a production-hardened deployment.
