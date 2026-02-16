# SNAP — MCP Server

**S**napshot **N**otebook **A**bide **P**ersistence

> Code analysis pipeline exposing snapshot types via Model Context Protocol (MCP). Parses code, documents, data, and config files into structured DB snapshots for targeted AI retrieval.

---

## Table of Contents

- [Quick Start](#quick-start)
- [MCP Server Setup](#mcp-server-setup)
- [LLM Permission Model](#llm-permission-model)
- [Agent Workflow](#agent-workflow)
- [Admin CLI](#admin-cli)
- [Available MCP Tools](#available-mcp-tools)
- [Snapshot Types](#snapshot-types)
- [Configuration](#configuration)
- [Logging](#logging)
- [Architecture](#architecture)
- [Security](#security)
- [Requirements](#requirements)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Install Dependencies

```bash
python -m venv .venv-1
.venv-1\Scripts\activate        # Windows
# source .venv-1/bin/activate   # Linux/Mac

pip install -e .
pip install semgrep
```

### 2. Setup PostgreSQL

```bash
docker-compose up -d postgres
# Or set SNAP_POSTGRES_DSN to an existing PostgreSQL instance
```

### 3. Configure Environment

```bash
cp .env.template .env
# Set SNAP_POSTGRES_DSN and optional auth settings
```

---

## MCP Server Setup

### Claude Code (VS Code / CLI)

```bash
claude mcp add snap --scope user "C:\Users\<username>\SNAP\run_mcp.bat"
claude mcp list
```

Or manually in `~/.claude.json`:

```json
{
  "mcpServers": {
    "snap": {
      "type": "stdio",
      "command": "C:\\Users\\<username>\\SNAP\\run_mcp.bat",
      "args": [],
      "env": {}
    }
  }
}
```

### Claude Desktop — `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "snap": {
      "command": "C:\\Users\\<username>\\SNAP\\run_mcp.bat",
      "args": []
    }
  }
}
```

### HTTP+SSE Mode

```bash
python -m app.mcp.run --sse --host 0.0.0.0 --port 8080
```

Endpoints: `GET /sse` · `POST /messages/` · `GET /health`

---

## LLM Permission Model

The LLM has strictly limited rights enforced at runtime in `app/mcp/tools.py` — not by convention or docstrings.

### Allowed — No Approval Needed

DB snapshot reads only. The LLM never reads raw files.

| Tool | Notes |
| ---- | ----- |
| `get_project_notebook` | Read assembled project snapshots from DB |
| `get_project_manifest` | Read processing stats from DB |
| `query_snapshots` | Query DB by type or file path |
| `get_system_metrics` | Read system-wide aggregated metrics |
| `list_projects` | List all projects in DB |
| `list_runs` | List processing runs for a project |

### Requires Explicit User Approval Per Call

| Tool | Notes |
| ---- | ----- |
| `clone_to_repos` | Clones GitHub repo into repos/ — repos_watcher ingests, LLM does not |
| `copy_to_staging` | Copies local dir to staging/ — staging_watcher ingests, LLM does not |
| `upload_to_staging` | Upload file content to staging |
| `get_staging_info` | File names, sizes, timestamps only — no file content |
| `clear_staging` | Delete staging files for a project |
| `kill_task` | Cancel a stuck async tool call |

### Not Allowed — Raises Immediately

| Tool | Reason |
| ---- | ------ |
| `delete_project` | No delete rights |
| `promote_run` | No write rights |
| `ingest_local_project` | No ingest rights |

### Not Allowed Actions

The LLM never: reads raw files, reads GitHub raw content, ingests files, sorts/filters files, or processes files. SNAP does all of this.

---

## Agent Workflow

SNAP is the ingest engine. The LLM stages content — SNAP ingests it.

### GitHub Repository

```text
LLM: clone_to_repos(repo_url, vendor_id)
    └─► Clones into repos/{project_id}/. project_id = repo name, derived by SNAP.
SNAP repos_watcher: detects .snap_ready → ingests → stores in DB → clears repos/
LLM (on request): query_snapshots / get_project_notebook
```

### Local Project

```text
LLM: copy_to_staging(project_id, source_path)
    └─► Copies files to staging/{project_id}/. Returns immediately.
SNAP staging_watcher: detects stable dir → ingests → stores in DB → clears staging/
LLM (on request): query_snapshots / get_project_notebook
```

**Rules:**
- LLM stages ONE operation: clone trigger (GitHub) or staging copy (local)
- LLM does NOT ingest, filter, read, or process files — ever
- All filtering and ingest happens inside SNAP
- LLM reads only structured snapshot data from DB

---

## Admin CLI

Human-only operations that bypass MCP entirely. Install with `pip install -e .` then use `snap-admin`.

```bash
# List all ingested projects with snapshot and run counts
snap-admin list-projects

# Show all runs for a project (active / superseded / failed)
snap-admin runs <project_id>

# Health check and active-run summary for a project
snap-admin manifest <project_id>

# Browse snapshots — summary by type, or drill in by type or file
snap-admin snapshots <project_id>
snap-admin snapshots <project_id> --type <snapshot_type>
snap-admin snapshots <project_id> --file <source_file_path>

# Delete a project and all its data (DB, repos, staging)
snap-admin delete-project <project_id>

# Copy a local directory into staging for a project
snap-admin upload-to-staging <project_id> <source_path>

# Clone a GitHub repo directly (no LLM involved) — repos_watcher ingests
snap-admin clone-github <repo_url>
```

Also callable as `python -m app.admin <command>`.

---

## Available MCP Tools

| Tool | Permission | Description |
| ---- | ---------- | ----------- |
| `get_project_notebook` | Allowed | Read complete project snapshots from DB |
| `get_project_manifest` | Allowed | Read processing stats from DB |
| `query_snapshots` | Allowed | Query by snapshot type or file path |
| `get_system_metrics` | Allowed | System-wide aggregated metrics |
| `list_projects` | Allowed | List all projects with snapshot counts |
| `list_runs` | Allowed | List processing runs for a project |
| `clone_to_repos` | Approval required | Clone GitHub repo → repos_watcher ingests |
| `copy_to_staging` | Approval required | Copy local directory into staging |
| `upload_to_staging` | Approval required | Upload file content to staging |
| `get_staging_info` | Approval required | List staging file names, sizes, timestamps |
| `clear_staging` | Approval required | Clear all staging files for a project |
| `kill_task` | Approval required | Cancel a stuck async tool call |
| `delete_project` | **Blocked** | LLM has no delete rights — use `snap-admin` |
| `promote_run` | **Blocked** | LLM has no write rights |
| `ingest_local_project` | **Blocked** | LLM has no ingest rights |

---

## Snapshot Types

### Code Analysis (7 types)

| Type | Parser | Description |
| ---- | ------ | ----------- |
| `file_metadata` | tree_sitter | Path, language, LOC, package info |
| `imports` | tree_sitter | External and internal module dependencies |
| `exports` | tree_sitter | Functions, classes, constants, types |
| `functions` | tree_sitter | Names, signatures, async status, decorators |
| `classes` | tree_sitter | Names, inheritance, methods, properties |
| `connections` | tree_sitter | Dependencies, function calls, instantiations |
| `repo_metadata` | tree_sitter | Primary language, entrypoints, CI pipeline |

### Security & Quality (2 types)

| Type | Parser | Description |
| ---- | ------ | ----------- |
| `security` | semgrep | Vulnerabilities, secrets, SQL injection, XSS |
| `quality` | semgrep | Antipatterns, code smells, TODOs, deprecated usage |

### Documents (3 types)

| Type | Parser | Description |
| ---- | ------ | ----------- |
| `doc_metadata` | text_extractor | Title, author, creation date, word count |
| `doc_content` | text_extractor | Extracted text, key concepts, code examples |
| `doc_analysis` | text_extractor | Requirements, decisions, risks, assumptions |

### CSV / Data (2 types)

| Type | Parser | Description |
| ---- | ------ | ----------- |
| `csv_data` | csv_parser | Raw table: headers, rows, row count |
| `csv_schema` | csv_parser | Column types, null counts, unique counts, sample rows |

### Config (1 type)

| Type | Parser | Description |
| ---- | ------ | ----------- |
| `config_metadata` | tree_sitter | Top-level keys, nested paths, env vars, API endpoints |

---

## Configuration

Environment variables use the `SNAP_` prefix.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SNAP_POSTGRES_DSN` | *required* | PostgreSQL connection string |
| `SNAP_DATA_DIR` | `data/` | Base data directory |
| `SNAP_REPOS_DIR` | `data/repos/` | GitHub cloned repositories (cleared after ingest) |
| `SNAP_LOG_LEVEL` | `INFO` | Logging level |
| `SNAP_LOG_JSON` | `true` | JSON-formatted logs |
| `SNAP_GIT_CLONE_DEPTH` | `1` | Shallow clone depth |
| `SNAP_GIT_CLONE_TIMEOUT_SECONDS` | `600` | Git clone timeout (seconds) |

### Parser Limits

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SNAP_PARSER_LIMITS_SOFT_CAP_LOC` | 1,500 | Code warning threshold (LOC) |
| `SNAP_PARSER_LIMITS_HARD_CAP_LOC` | 5,000 | Code reject threshold (LOC) |
| `SNAP_PARSER_LIMITS_SOFT_CAP_BYTES` | 500,000 | Text warning threshold (bytes) |
| `SNAP_PARSER_LIMITS_HARD_CAP_BYTES` | 10,000,000 | Text reject threshold (bytes) |

### Authentication (HTTP+SSE only, disabled by default)

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SNAP_AUTH_ENABLED` | `false` | Enable JWT/OAuth authentication |
| `SNAP_AUTH_JWT_SECRET` | *(empty)* | Secret for JWT signing |
| `SNAP_AUTH_GITHUB_CLIENT_ID` | *(empty)* | GitHub OAuth app client ID |
| `SNAP_AUTH_GITHUB_CLIENT_SECRET` | *(empty)* | GitHub OAuth app client secret |

> Stdio mode (Claude Code) is never affected by auth settings.

---

## Logging

SNAP writes structured JSON logs to three destinations simultaneously.

### Log Files

| File | Level | Rotation | Notes |
| ---- | ----- | -------- | ----- |
| `data/logs/app.log` | WARNING+ | None | Plain FileHandler — VSCode-safe, always readable |
| `data/logs/app_debug.log` | INFO+ | 5 MB × 3 | RotatingFileHandler — full debug trail |
| stderr | all levels | — | MCP-compatible; required for stdio transport |

### Log Format

Controlled by `SNAP_LOG_JSON` (default `true`). Each line is a JSON object:

```json
{"ts": "2026-02-15 12:00:00,000", "level": "INFO", "name": "snap", "msg": "Snapshot created", "snapshot_id": "...", "project_id": "...", "snapshot_type": "functions", "parser": "tree_sitter", "fields_count": 12}
```

Set `SNAP_LOG_JSON=false` for human-readable output:

```text
2026-02-15 12:00:00,000 INFO snap Snapshot created
```

### Structured Log Events

| Event | Level | Key Fields |
| ----- | ----- | ---------- |
| File parsed | DEBUG | `path`, `tag`, `size`, `language`, `parse_duration_ms`, `snapshots_created`, `parsers` |
| Snapshot created | INFO | `snapshot_id`, `snapshot_type`, `parser`, `fields_count` |
| File categorized | INFO / WARNING / ERROR | `path`, `size`, `tag`, `reason` |
| Repo processing complete | INFO | `files_processed`, `snapshots_created`, `snapshot_types_summary`, `parsers_summary`, `total_duration_ms` |

### File Tags

| Tag | Level | Meaning |
| --- | ----- | ------- |
| `normal` | INFO | Within soft cap — processed normally |
| `large` | WARNING | Exceeds `SOFT_CAP_LOC` / `SOFT_CAP_BYTES` — processed with warning |
| `potential_god` | WARNING | Suspected god file — processed with warning |
| `rejected` | ERROR | Exceeds `HARD_CAP_LOC` / `HARD_CAP_BYTES` — skipped |

---

## Architecture

### Pipeline Flow

```text
GitHub:
clone_to_repos(repo_url)
    ↓
repos/{project_id}/     ← repos_watcher detects .snap_ready
    ↓
ingest_cloned_repo()    ← security filtering, file enumeration
    ↓
file_router → parsers → field_mapper → snapshot_builder → DB
    ↓
repos/ cleared

Local:
copy_to_staging(source_path)
    ↓
staging/{project_id}/   ← staging_watcher detects size stability
    ↓
process_project()       ← security filtering, file enumeration
    ↓
file_router → parsers → field_mapper → snapshot_builder → DB
    ↓
staging/ cleared
```

### File Structure

```text
SNAP/
├── app/
│   ├── admin.py                         # Admin CLI (human-only: delete, upload, clone, list)
│   ├── main.py                          # Orchestration pipeline
│   ├── config/
│   │   └── settings.py
│   ├── extraction/
│   │   ├── field_mapper.py              # Maps parser output to 15 snapshot types
│   │   └── snapshot_builder.py
│   ├── ingest/
│   │   ├── file_router.py               # Routes files to parsers by extension
│   │   ├── github_cloner.py             # Shallow clone → repos/
│   │   ├── local_loader.py              # stage_directory() + staging helpers
│   │   ├── repos_watcher.py             # Watches repos/, detects .snap_ready, triggers ingest
│   │   └── staging_watcher.py           # Watches staging/, triggers ingest on stability
│   ├── logging/
│   │   └── logger.py
│   ├── mcp/
│   │   ├── auth.py                      # JWT + GitHub OAuth
│   │   ├── run.py                       # Entry point: stdio or HTTP+SSE
│   │   ├── security.py                  # Input validation, path traversal prevention
│   │   ├── server.py                    # MCP server, tool registry, Starlette app
│   │   └── tools.py                     # Tool handlers + permission enforcement
│   ├── parsers/
│   │   ├── csv_parser.py
│   │   ├── semgrep_parser.py
│   │   ├── text_extractor.py
│   │   └── tree_sitter_parser.py
│   ├── schemas/
│   │   ├── master_notebook.yaml
│   │   └── snapshot_templates/          # 15 JSON templates
│   ├── security/
│   │   └── network_policy.py
│   └── storage/
│       ├── db.py
│       └── snapshot_repo.py             # CRUD, upsert, run versioning
├── data/
│   ├── logs/
│   ├── projects/                        # Project manifests
│   ├── repos/                           # GitHub clones (cleared after ingest)
│   └── staging/                         # Local file staging (cleared after ingest)
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── run_mcp.bat
└── run_mcp.sh
```

---

## Security

### LLM Autonomy Restrictions

- **No raw file reads** — LLM reads only structured DB snapshots
- **No ingest** — SNAP ingests and parses; LLM never touches files
- **No delete/write rights** — `delete_project`, `promote_run` raise immediately
- **project_id locked** — derived from repo URL on clone; LLM cannot supply or rename
- **vendor_id restricted** — alphanumeric + `_@.-` only, max 64 chars; blocks injection chars
- **Runtime enforcement** — `ALLOWED_TOOLS` / `NOT_ALLOWED_TOOLS` frozensets checked at handler entry

### Input Validation

- **Project ID**: `^[a-zA-Z0-9_-]{3,64}$`
- **Vendor ID**: `^[a-zA-Z0-9_@.\-]{1,64}$`
- **Filenames**: No path traversal (`..`, `\x00`, `~`), no backslash, reserved names blocked
- **Repo URLs**: HTTPS GitHub URLs only
- **Symlinks**: Rejected at staging time

### Staging Filters (`stage_directory`)

All filtering enforced by SNAP at copy time — LLM has no role.

**Pruned directories** (never traversed):
`node_modules` · `.git` · `.svn` · `.hg` · `__pycache__` · `.venv` · `venv` · `.next` · `.nuxt` · `.expo` · `.gradle` · `build` · `dist` · `target` · `Pods` · `.terraform` · `vendor`

**Ignored file patterns:**

| Category | Patterns |
| -------- | -------- |
| Secrets / credentials | `*.pem`, `*.key`, `*.p12`, `.env`, `.env.*`, `*.token`, `serviceAccountKey.json` |
| Cloud configs | `.aws/`, `.azure/`, `.gcloud/` |
| Build artifacts | `*.min.js`, `*.min.css`, `*.pyc`, `*.class`, `*.so`, `*.dll`, `*.exe` |
| Coverage / logs | `coverage/`, `*.log`, `*.lock` |

### Parse-Time Injection Protection

- **Prompt injection** — 30+ patterns blocked: instruction overrides, role hijacking, jailbreak triggers, exfiltration probes
- **Secret redaction** — AWS keys, GitHub tokens, JWTs, API keys auto-redacted in all field values
- **AST-level filtering** — tree-sitter nodes scanned for imperative patterns; flagged as `[FILTERED:IMPERATIVE]`
- **Content safety** — high-entropy detection, base64 blocks, hex-encoded data flagged before DB insertion

---

## Requirements

| Dependency | Version | Purpose |
| ---------- | ------- | ------- |
| Python | 3.11+ | Runtime |
| PostgreSQL | 14+ | Snapshot storage |
| mcp | ≥ 1.0.0 | Model Context Protocol |
| tree-sitter | ≥ 0.22.0 | AST parsing |
| semgrep | ≥ 1.50.0 | Security analysis |
| defusedxml | ≥ 0.7.0 | XML XXE protection |
| pydantic | ≥ 2.0.0 | Settings validation |
| sqlalchemy | ≥ 2.0.0 | Database ORM |
| starlette | ≥ 0.27.0 | HTTP+SSE transport |

---

## Troubleshooting

### MCP Server Won't Connect

1. **Logs must go to stderr** (not stdout):
   ```python
   handler = logging.StreamHandler(sys.stderr)
   ```

2. **Use the wrapper script** — Claude Code does not respect cwd:
   ```batch
   @echo off
   cd /d C:\Users\<username>\SNAP
   "C:\Users\<username>\SNAP\.venv-1\Scripts\python.exe" -m app.mcp.run %*
   ```

3. **Verify connection**:
   ```bash
   claude mcp list
   # snap: ... - ✓ Connected
   ```

### Missing postgres_dsn

```env
SNAP_POSTGRES_DSN=postgresql://user:pass@localhost:5432/snap
```

### Semgrep Not Running

SNAP auto-installs and upgrades semgrep on startup. If auto-install fails:

```bash
.venv-1\Scripts\python.exe -m pip install --upgrade semgrep
```

---

&copy; CLL Automata
