# SecureCode

AI-assisted secure code review platform built by **CipherSquad** for **CIT-RANKATHON 2026**, targeting Problem Statement #14 (AI-Assisted Secure Code Review). 

SecureCode scans code and connected GitHub repositories for secrets, vulnerable dependencies, and misconfigurations, then uses an LLM to prioritize and explain findings.

---

## Table of contents

- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup — backend (`code-scan/`)](#setup--backend-code-scan)
- [Setup — frontend (`frontend/`)](#setup--frontend-frontend)
- [Database schema](#database-schema)
- [Environment variables](#environment-variables)
- [API reference](#api-reference)
- [Project structure](#project-structure)
- [How a repository scan works](#how-a-repository-scan-works)
- [Known limitations](#known-limitations)

---

## Architecture

```
┌─────────────────────┐         ┌──────────────────────┐         ┌─────────────┐
│   frontend/          │  HTTP   │   code-scan/           │  SQL    │   MySQL     │
│   React + Vite        │ ──────► │   Node.js + Express     │ ──────► │   Database  │
│   localhost:5173      │ ◄────── │   localhost:4000         │ ◄────── │             │
└─────────────────────┘         └──────────┬───────────┘         └─────────────┘
                                              │
                                              │ REST API + PAT
                                              ▼
                                    ┌───────────────────┐
                                    │   GitHub API        │
                                    │   (repo file fetch)  │
                                    └───────────────────┘
                                              │
                                              ▼
                                    ┌───────────────────┐
                                    │   OSV.dev              │
                                    │   (dependency CVEs)  │
                                    └───────────────────┘
```

Two independent apps that talk over HTTP:

- **`frontend/`** — React (Vite) single-page app. All panels (Code Scan, Secrets Detection, Dependency Check, AI Prioritization, Projects, Reports, etc.) live here.
- **`code-scan/`** — Node.js/Express backend. Owns the scanning pipeline, MySQL persistence, GitHub integration, and token encryption.

---

## Features

| Module | What it does |
|---|---|
| **Secrets Detection** | Pattern + entropy-based scanning for hardcoded API keys, tokens, and credentials (`detectors.js`) |
| **Dependency Check** | Cross-references `package.json` dependencies against [OSV.dev](https://osv.dev) for known CVEs (`depScanner.js`) |
| **AI Prioritization** | LLM-based semantic analysis that flags risk beyond pattern matching (`llmAnalyzer.js`) |
| **Risk Engine** | Merges pattern, LLM, and dependency findings into one prioritized report with an overall risk score (`riskEngine.js`) |
| **Projects panel** | Connect a GitHub repo once, then trigger scans that pull real files via the GitHub API and run them through the full pipeline |
| **Scan history** | Every scan (ad-hoc paste or full-repo) is persisted, so score/risk trends are visible over time |

---

## Prerequisites

- **Node.js** 18+ and npm
- **MySQL** 8.0 (tested against MySQL Workbench locally)
- A **GitHub Personal Access Token** with `repo` scope, for any project you connect through the Projects panel
- Whatever LLM API credentials `llmAnalyzer.js` expects (check that file — provider/key name isn't documented here yet)

---

## Setup — backend (`code-scan/`)

```bash
cd code-scan
npm install
```

1. **Create `code-scan/.env`** — see [Environment variables](#environment-variables) below for the full list.

2. **Generate a token encryption key** (required — GitHub PATs stored via the Projects panel are encrypted with this):
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
   Paste the output into `.env` as `TOKEN_ENCRYPTION_KEY`.

3. **Set up the MySQL database** — create the schema described in [Database schema](#database-schema) below, either by running the SQL directly or importing it via MySQL Workbench.

4. **Start the backend**:
   ```bash
   npm run dev   # or: node index.js
   ```
   You should see `SecureCode backend running on http://localhost:4000` in the terminal.

---

## Setup — frontend (`frontend/`)

```bash
cd frontend
npm install
npm run dev
```

Runs on `http://localhost:5173` by default (Vite). The frontend expects the backend at `http://localhost:4000` — this is hardcoded as `API_URL` at the top of `ProjectsPanel.jsx`; update it there if your backend runs elsewhere.

---

## Database schema

The tables below are inferred from the columns referenced in `code-scan/index.js`. **Verify this against your actual MySQL Workbench schema** — if you already have these tables, this is just documentation; if you're setting up fresh, this SQL should get you running.

```sql
CREATE TABLE projects (
  id                    INT AUTO_INCREMENT PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL,
  platform              ENUM('GitHub', 'GitLab') NOT NULL,
  repos_json            JSON NOT NULL,
  security_score        INT DEFAULT 0,
  risk_level            VARCHAR(50),
  total_issues          INT DEFAULT 0,
  critical_count        INT DEFAULT 0,
  high_count            INT DEFAULT 0,
  medium_count          INT DEFAULT 0,
  low_count             INT DEFAULT 0,
  last_scan             DATETIME,
  auto_scan_enabled     BOOLEAN DEFAULT TRUE,
  auto_scan_frequency   ENUM('on-push', 'daily', 'weekly') DEFAULT 'daily',
  encrypted_token       TEXT,
  token_iv              VARCHAR(255),
  token_auth_tag        VARCHAR(255),
  remediation_progress  INT DEFAULT 0,
  created_at            DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE project_scans (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  project_id      INT NOT NULL,
  status          ENUM('in_progress', 'completed', 'failed') DEFAULT 'in_progress',
  risk_score      INT,
  risk_level      VARCHAR(50),
  findings_json   JSON,
  critical_count  INT DEFAULT 0,
  high_count      INT DEFAULT 0,
  medium_count    INT DEFAULT 0,
  low_count       INT DEFAULT 0,
  total_findings  INT DEFAULT 0,
  scanned_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE project_prs (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  project_id  INT NOT NULL,
  title       VARCHAR(255) NOT NULL,
  status      ENUM('draft', 'open', 'merged') DEFAULT 'open',
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  merged_at   DATETIME,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE scan_history (
  id               INT AUTO_INCREMENT PRIMARY KEY,
  total_findings   INT DEFAULT 0,
  high_severity    INT DEFAULT 0,
  medium_severity  INT DEFAULT 0,
  low_severity     INT DEFAULT 0,
  findings_json    JSON,
  risk_score       INT,
  risk_level       VARCHAR(50),
  scanned_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

> `scan_history` is for the standalone paste/upload scan (`POST /scan`); `project_scans` is for repo-connected scans tied to a specific project.

---

## Environment variables

Create `code-scan/.env`:

```dotenv
PORT=4000

# MySQL connection — match your db.js config
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=securecode

# Required for encrypting/decrypting GitHub/GitLab PATs stored via the Projects panel
TOKEN_ENCRYPTION_KEY=<generate with the node -e crypto command above>

# Whatever llmAnalyzer.js expects — check that file for the exact variable name
# LLM_API_KEY=...
```

> **Never commit `.env`.** Confirm it's listed in `.gitignore` before your first commit — it holds your DB password and the encryption key protecting every stored GitHub token.

---

## API reference

Base URL: `http://localhost:4000`

### Ad-hoc scanning

| Method | Route | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/scan` | Scan pasted code or an array of `{name, content}` files. Runs pattern + LLM + dependency scans, saves to `scan_history`. |
| `GET` | `/history` | Last 50 ad-hoc scans |

### Projects

| Method | Route | Description |
|---|---|---|
| `GET` | `/projects` | List all connected projects with their latest counts and PRs |
| `POST` | `/projects` | Connect a new repo. Body: `{ name, platform, repos: [{name, url, branch}], settings: {autoScan, scanFrequency}, token }` |
| `GET` | `/projects/:projectId` | Get a single project + its PRs |
| `PATCH` | `/projects/:projectId` | Update `autoScanEnabled` and/or `autoScanFrequency` |
| `POST` | `/projects/:projectId/scan` | Trigger a real scan: fetches repo files via GitHub API, runs the full pipeline, updates DB. Responds `202` immediately; work continues in the background. |
| `GET` | `/projects/:projectId/scans` | Last 50 scans for a project — poll this after triggering a scan to see when it completes |

---

## Project structure

```
SecureScope/
├── code-scan/                  # Backend (Node.js + Express)
│   ├── index.js                 # All routes
│   ├── db.js                    # MySQL connection pool
│   ├── detectors.js             # Pattern + entropy secret detection
│   ├── llmAnalyzer.js           # LLM-based semantic analysis
│   ├── depScanner.js            # OSV.dev dependency vulnerability check
│   ├── riskEngine.js            # Merges findings into a prioritized report
│   ├── tokenCrypto.js           # AES-256-GCM encrypt/decrypt for stored PATs
│   ├── githubFetcher.js         # Fetches repo file trees + contents via GitHub API
│   ├── .env                     # Not committed — see Environment variables
│   └── package.json
│
└── frontend/                    # Frontend (React + Vite)
    ├── src/
    │   ├── App.jsx               # Root app, panel routing
    │   ├── ProjectsPanel.jsx     # Connect repos, trigger scans, view results
    │   └── components/           # Secrets Detection, Dependency Check, etc. panels
    └── package.json
```

---

## How a repository scan works

1. **Connect** — `ConnectRepoModal` in `ProjectsPanel.jsx` collects a repo URL, branch, and PAT, and `POST`s it to `/projects`. The token is encrypted (`tokenCrypto.js`) before it's written to MySQL.
2. **Trigger** — clicking "Rescan" calls `POST /projects/:id/scan`, which responds `202` immediately and continues in the background.
3. **Fetch** — `githubFetcher.js` decrypts the stored token, lists the repo's file tree via the GitHub API, and downloads up to 40 source files (skipping `node_modules`, `dist`, `.git`, and binaries).
4. **Scan** — those files run through `scanCode` (pattern/entropy), `analyzeWithLLM`, and `scanDependencies` in parallel, then `buildRiskReport` merges everything into one prioritized report.
5. **Persist** — results write to `project_scans` (the specific scan record) and `projects` (the live summary shown on the dashboard card).
6. **Poll** — the frontend polls `GET /projects/:id/scans` every 3 seconds until the latest scan leaves `in_progress`, then refreshes the project list.

---

## Known limitations

- **No automatic scanning yet.** `autoScanFrequency` is stored per project but nothing currently triggers a scan on a schedule or on GitHub push/PR events — that would need either a webhook (requires a public URL, e.g. ngrok) or a cron job hitting `POST /projects/:id/scan`.
- **Remediation tracking is heuristic, not real.** The Remediation Checklist and progress percentage are derived from severity counts (e.g. "complete if `critical === 0`"), not from tracking which individual findings were actually fixed.
- **No fix-PR automation.** The "Remediation PRs" section reads from `project_prs`, but nothing currently creates PRs automatically when issues are found — that table is populated manually or would need a future integration.
- **Dependency scan includes `devDependencies`.** This can inflate finding counts on projects with many dev tools; see `depScanner.js`'s `parsePackageJson` if you want to scope it to runtime dependencies only.
