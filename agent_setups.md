# SNAP — Agent & Client Setup

Setup guides for connecting SNAP to various AI agents and clients.

---

## Table of Contents

- [Claude Code (VS Code / CLI)](#claude-code-vs-code--cli)
- [Claude Desktop](#claude-desktop)
- [GitHub Copilot Chat (VS Code)](#github-copilot-chat-vs-code)
- [HTTP+SSE Mode](#httpsse-mode)
- [Azure Cloud Deployment](#azure-cloud-deployment)

---

## Claude Code (VS Code / CLI)

### Windows

Create a `run_mcp.bat` launcher in the same directory as the binary:

```batch
@echo off
cd /d C:\Users\<username>\snap
snap-mcp.exe %*
```

Then register:

```bash
claude mcp add snap --scope user "C:\Users\<username>\snap\run_mcp.bat"
claude mcp list
```

Or manually in `~/.claude.json`:

```json
{
  "mcpServers": {
    "snap": {
      "type": "stdio",
      "command": "C:\\Users\\<username>\\snap\\run_mcp.bat",
      "args": [],
      "env": {}
    }
  }
}
```

### Linux / macOS

```json
{
  "mcpServers": {
    "snap": {
      "type": "stdio",
      "command": "/home/<username>/snap/snap-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

---

## Claude Desktop

`%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "snap": {
      "command": "C:\\Users\\<username>\\snap\\run_mcp.bat",
      "args": []
    }
  }
}
```

macOS `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "snap": {
      "command": "/home/<username>/snap/snap-mcp",
      "args": []
    }
  }
}
```

---

## GitHub Copilot Chat (VS Code)

Requires VS Code 1.99+.

Create `.vscode/mcp.json` in your workspace:

**Windows:**
```json
{
  "servers": {
    "snap": {
      "type": "stdio",
      "command": "C:\\Users\\<username>\\snap\\run_mcp.bat",
      "args": []
    }
  }
}
```

**Linux / macOS:**
```json
{
  "servers": {
    "snap": {
      "type": "stdio",
      "command": "/home/<username>/snap/snap-mcp",
      "args": []
    }
  }
}
```

Then in Copilot Chat, click the **Tools** button (plug icon) and enable SNAP tools.

---

## HTTP+SSE Mode

Start SNAP in SSE mode:

```bash
# Binary
./snap-mcp --sse --host 0.0.0.0 --port 8080

# Source (dev only)
python -m app.mcp.run --sse --host 0.0.0.0 --port 8080
```

Endpoints: `GET /sse` · `POST /messages/` · `GET /health`

Connect any SSE-compatible client:

```json
{
  "mcpServers": {
    "snap": {
      "type": "sse",
      "url": "http://localhost:8080/sse"
    }
  }
}
```

---

## Azure Cloud Deployment

For company/team use, deploy SNAP on Azure with PostgreSQL and JWT auth.

### Environment

```env
SNAP_DB_MODE=postgres
SNAP_POSTGRES_DSN=postgresql://user:pass@<azure-postgres-host>/snap
SNAP_AUTH_ENABLED=true
SNAP_AUTH_JWT_SECRET=<secret>
SNAP_LOG_LEVEL=INFO
SNAP_LOG_JSON=true
```

### Option 1 — Azure Container Instance (simplest)

Deploy the `snap-mcp` binary in a container exposed on port 8080 via HTTP+SSE mode.

### Option 2 — Azure App Service

Auto-scaling, SSL termination, custom domain. Recommended for team use.

### Option 3 — Azure Kubernetes Service

For large teams requiring high availability and horizontal scaling.

### Client Connection (SSE)

```json
{
  "mcpServers": {
    "snap": {
      "type": "sse",
      "url": "https://your-snap-instance.azurewebsites.net/sse"
    }
  }
}
```
