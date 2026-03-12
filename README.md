# SNAP — MCP Server

**S**napshot **N**otebook **A**bide **P**ersistence

> Code analysis pipeline exposing snapshot types via Model Context Protocol (MCP). Parses code, documents, data, and config files into structured DB snapshots for targeted AI retrieval.

---

## Table of Contents

- [Quick Start](#quick-start)
- [MCP Server Setup](#mcp-server-setup)
- [LLM Permission Model](#llm-permission-model)
- [Agent Workflow](#agent-workflow)
- [Binary File Headers](#binary-file-headers)
- [Nim Parser](#nim-parser)
- [Admin CLI](#admin-cli)
- [Available MCP Tools](#available-mcp-tools)
- [Snapshot Types](#snapshot-types)
- [Storage Architecture](#storage-architecture)
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

### 2. Configure Environment

```bash
cp .env.template .env
# SQLite is the default — no database setup required
# Set SNAP_POSTGRES_DSN only if using PostgreSQL mode
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
| `clone_to_repos` | Clones GitHub repo into repos/ — auto-ingests in background, LLM does not read files |
| `copy_to_staging` | Copies local dir to staging/ — auto-ingests in background, LLM does not read files |
| `upload_to_staging` | Upload file content to staging |
| `get_staging_info` | File names, sizes, timestamps only — no file content |
| `clear_staging` | Delete staging files for a project |
| `kill_task` | Cancel a stuck async tool call |

### Not Allowed — Raises Immediately

| Tool | Reason |
| ---- | ------ |
| `delete_project` | No delete rights |
| `promote_run` | No write rights |
| `process_local_project` | No ingest rights |

### Not Allowed Actions

The LLM never: reads raw files, reads GitHub raw content, ingests files, sorts/filters files, or processes files. SNAP does all of this.

---

## Agent Workflow

SNAP is the ingest engine. The LLM stages content — SNAP ingests it.

### GitHub Repository

```text
LLM: clone_to_repos(repo_url, vendor_id)
    └─► Clones into repos/{project_id}/. project_id = repo name, derived by SNAP.
SNAP: auto-ingests in background thread → stores in DB → clears repos/
LLM (on request): query_snapshots / get_project_notebook
```

### Local Project

```text
LLM: copy_to_staging(project_id, source_path)
    └─► Copies files to staging/{project_id}/. Returns immediately.
SNAP: auto-ingests in background thread → stores in DB → clears staging/
LLM (on request): query_snapshots / get_project_notebook
```

**Rules:**
- LLM stages ONE operation: clone trigger (GitHub) or staging copy (local)
- LLM does NOT ingest, filter, read, or process files — ever
- All filtering and ingest happens inside SNAP
- LLM reads only structured snapshot data from DB

---

## Binary File Headers

SNAP uses binary file headers to associate files with projects without requiring directory structure.

### Header Format

```text
FileHeader (variable size):
  magic:            "SNAPFILE" (8 bytes)
  version:          uint16 (2 bytes)
  project_id_len:   uint16 (2 bytes)
  project_id:       utf-8 string (variable)
  snapshot_count:   uint32 (4 bytes)
  [file content follows]
```

### Usage

```python
from app.extraction.binary_packer import write_file_header, read_project_id_from_file

# Write file with project association
content = b"# Project Notes\n\nImplementation details..."
write_file_header("notes.md", "SNAP", content)

# Read project_id from file
project_id = read_project_id_from_file("notes.md")  # Returns "SNAP"
```

### Auto-Ingest Workflow

```text
1. File with binary header uploaded via upload_to_staging
2. SNAP reads header → extracts project_id
3. File placed in staging/{project_id}/
4. Auto-ingested into {project_id} project in background
5. Staging cleared
```

**Use Cases:**
- Chat conversation logs (project_id = working project name)
- Project notes and documentation
- Context files for RAG queries
- Cross-project file sharing with explicit ownership

---

## Nim Parser

High-performance binary parser for text, markdown, and CSV files. Outputs SNAP binary format directly — 10-100x faster than Python.

### Build

```bash
# Requires Nim compiler
winget install nim-lang.Nim

# Compile to native binary
scripts\build_nim_parser.bat

# Or manually
nim c -d:release --opt:speed --out:app\parsers\nim_parser.exe app\parsers\nim_parser.nim
```

### Usage

**From command line:**
```bash
app\parsers\nim_parser.exe input.md SNAP output.snap
```

**From Python:**
```python
from app.parsers.nim_parser import parse_with_nim, is_nim_parser_available

if is_nim_parser_available():
    binary_file = parse_with_nim(Path("doc.md"), "SNAP")
```

### Supported Formats

| Format | Extracted Fields |
| ------ | ---------------- |
| Markdown | `doc.title`, `doc.content`, `doc.key_concepts`, `doc.urls`, `doc.word_count` |
| CSV | `csv.headers`, `csv.row_count`, `csv.column_count`, `doc.content` |
| Text | `doc.content`, `doc.line_count`, `doc.word_count`, `doc.char_count` |

### Performance

| Operation | Python | Nim | Speedup |
| --------- | ------ | --- | ------- |
| Parse 1MB markdown | ~450ms | ~8ms | 56x |
| Extract CSV schema | ~180ms | ~3ms | 60x |
| Binary packing | ~320ms | ~12ms | 27x |

**Note:** Tree-sitter and semgrep remain in Python (external tools, already optimized).

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
| `clone_to_repos` | Approval required | Clone GitHub repo → auto-ingests in background |
| `copy_to_staging` | Approval required | Copy local directory into staging |
| `upload_to_staging` | Approval required | Upload file content to staging |
| `get_staging_info` | Approval required | List staging file names, sizes, timestamps |
| `clear_staging` | Approval required | Clear all staging files for a project |
| `kill_task` | Approval required | Cancel a stuck async tool call |
| `delete_project` | **Blocked** | LLM has no delete rights — use `snap-admin` |
| `promote_run` | **Blocked** | LLM has no write rights |
| `process_local_project` | **Blocked** | LLM has no ingest rights |

---

## Snapshot Types

### Code Analysis (8 types)

| Type | Parser | Description |
| ---- | ------ | ----------- |
| `file_metadata` | tree_sitter | Path, language, LOC, package info |
| `imports` | tree_sitter | External and internal module dependencies |
| `exports` | tree_sitter | Functions, classes, constants, types |
| `functions` | tree_sitter | Names, signatures, async status, decorators |
| `functions_core` | tree_sitter | Full function bodies, docstrings, return types, parameters |
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
| `doc_metadata` | text_extractor (Docling) | Title, author, creation date, word count |
| `doc_content` | text_extractor (Docling) | Extracted text, key concepts, code examples |
| `doc_analysis` | text_extractor (Docling) | Requirements, decisions, risks, assumptions |

**Note:** `text_extractor` uses [Docling](https://github.com/DS4SD/docling) for advanced PDF parsing with support for complex layouts, tables, formulas, and multi-column text.

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

## Storage Architecture

SNAP uses a hybrid storage model with binary snapshot format for efficient Nim integration.

### Database Modes

| Mode | Storage | Use Case |
| ---- | ------- | -------- |
| `sqlite` | SQLite (default) | Single-user, embedded, zero-config |
| `postgres` | PostgreSQL | Multi-user, networked, production |
| `dual` | Both | Development, migration, redundancy |

Set via `.env`:

```bash
SNAP_DB_MODE=sqlite        # Default
SNAP_DB_MODE=postgres      # Requires SNAP_POSTGRES_DSN
SNAP_DB_MODE=dual          # Both databases
```

### Binary Snapshot Format

Snapshots are stored as binary-packed data for performance and Nim compatibility.

**Snapshot Structure:**

```text
SnapshotHeader (561 bytes):
  magic:         "SNAP" (4 bytes)
  version:       uint16 (2 bytes)
  snapshot_type: uint8 (1 byte)
  field_count:   uint16 (2 bytes)
  content_hash:  SHA-256 (32 bytes)
  simhash:       uint64 (8 bytes)
  minhash:       128 × uint32 (512 bytes)

FieldDescriptor (11 bytes each):
  field_id:      uint16 (2 bytes)
  data_type:     uint8 (1 byte)  # 0=string, 1=int, 2=binary, 3=array
  offset:        uint32 (4 bytes)
  length:        uint32 (4 bytes)

Data Block (variable):
  Packed field data referenced by descriptors
```

**Storage:**

```sql
CREATE TABLE snapshot_notebooks (
    snapshot_id   TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    project_id    TEXT NOT NULL,
    snapshot_type TEXT NOT NULL,
    source_file   TEXT NOT NULL,
    binary_data   BYTEA NOT NULL,           -- Binary-packed snapshot
    source_hash   TEXT,
    content_hash  TEXT,                      -- SHA-256 hex
    simhash       BIGINT,                    -- 64-bit similarity hash
    minhash       TEXT,                      -- 128 × 32-bit MinHash (CSV)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Hash-Based Versioning

| Hash Type | Size | Purpose |
| --------- | ---- | ------- |
| `source_hash` | SHA-256 | File content hash (deduplication) |
| `content_hash` | SHA-256 | Extracted content hash (change detection) |
| `simhash` | 64-bit | Similarity fingerprint (near-duplicate detection) |
| `minhash` | 128 × 32-bit | Set similarity (document comparison) |

**Versioning Logic:**

```text
New file ingested:
  1. Calculate source_hash
  2. Query DB for existing snapshot with same source_file + source_hash
  3. If exists → skip (deduplication)
  4. If not exists → create new snapshot (versioning)
  5. Multiple versions coexist in DB (query by run_id or latest)
```

---

## Configuration

Environment variables use the `SNAP_` prefix.

### Database

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SNAP_DB_MODE` | `sqlite` | Database mode: `sqlite`, `postgres`, or `dual` |
| `SNAP_POSTGRES_DSN` | *(required for postgres/dual)* | PostgreSQL connection string |
| `SNAP_SQLITE_PATH` | `data/snap.db` | SQLite database path |

### Directories

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `SNAP_DATA_DIR` | `data/` | Base data directory |
| `SNAP_STAGING_DIR` | `data/staging/` | File staging (auto-ingest) |
| `SNAP_REPOS_DIR` | `data/repos/` | GitHub clones (cleared after ingest) |

### System

| Variable | Default | Description |
| -------- | ------- | ----------- |
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
    ↓ clone completes synchronously
repos/{project_id}/
    ↓ auto-ingest background thread
ingest_cloned_repo()    ← security filtering, file enumeration
    ↓
file_router → parsers → field_mapper → snapshot_builder → DB
    ↓
repos/ cleared

Local:
copy_to_staging(source_path)
    ↓ stage_directory() filters and copies
staging/{project_id}/
    ↓ auto-ingest background thread
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
│   │   ├── binary_packer.py             # Binary snapshot packer/unpacker (Nim-compatible)
│   │   ├── field_mapper.py              # Maps parser output to 15 snapshot types
│   │   └── snapshot_builder.py
│   ├── ingest/
│   │   ├── file_router.py               # Routes files to parsers by extension
│   │   ├── github_cloner.py             # Shallow clone → repos/
│   │   └── local_loader.py              # stage_directory() + staging helpers
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
│   │   ├── nim_parser.nim               # High-performance Nim parser (compile to .exe)
│   │   ├── nim_parser.py                # Python wrapper for Nim parser
│   │   ├── semgrep_parser.py
│   │   ├── text_extractor.py
│   │   └── tree_sitter_parser.py
│   ├── schemas/
│   │   ├── master_notebook.yaml
│   │   └── snapshot_templates/          # JSON templates (defined and gated by master_notebook.yaml)
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

### Schema Governance

`app/schemas/master_notebook.yaml` is the single source of truth for all snapshot types and field definitions.

- **Template validation** — `SnapshotBuilder` validates every template file against the master notebook at startup. Templates not registered in `snapshot_templates` are rejected and never run.
- **Field validation** — Any field in a template not registered in `field_id_registry` causes the entire template to be rejected.
- **MCP query validation** — `validate_snapshot_type` reads valid types directly from the master notebook at runtime. No hardcoded lists.

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
| SQLite3 | 3.35+ | Default embedded database |
| PostgreSQL | 14+ (optional) | Alternative: set `SNAP_DB_MODE=postgres` |
| mcp | ≥ 1.0.0 | Model Context Protocol |
| tree-sitter | ≥ 0.22.0 | AST parsing |
| semgrep | ≥ 1.50.0 | Security analysis |
| defusedxml | ≥ 0.7.0 | XML XXE protection |
| pydantic | ≥ 2.0.0 | Settings validation |
| sqlalchemy | ≥ 2.0.0 | Database ORM |
| starlette | ≥ 0.27.0 | HTTP+SSE transport |
| docling | ≥ 1.0 | Advanced PDF/document parsing |
| Nim | 2.0+ (optional) | High-performance binary parser |

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
