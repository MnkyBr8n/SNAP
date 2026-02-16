# app/mcp/server.py
"""
MCP Server definition for SNAP.

Exposes SNAP's code analysis functionality as MCP tools using
the official mcp Python SDK with HTTP+SSE transport.
"""

from __future__ import annotations

import json

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from app.mcp.tools import (
    handle_clone_to_repos,
    handle_get_project_notebook,
    handle_delete_project,
    handle_list_projects,
    handle_list_runs,
    handle_promote_run,
    handle_get_staging_info,
    handle_upload_to_staging,
    handle_clear_staging,
    handle_copy_to_staging,
    handle_get_project_manifest,
    handle_query_snapshots,
    handle_get_system_metrics,
    handle_kill_task,
    ToolError,
)

from app.mcp.security import SecurityError, ValidationError
from app.mcp.auth import (
    AuthMiddleware,
    github_login_redirect,
    github_callback,
    issue_token,
)
from app.logging.logger import get_logger
from app.config.settings import get_settings

logger = get_logger("mcp.server")

# Create MCP server instance
server = Server("snap-mcp")


# =============================================================================
# Tool Definitions
# =============================================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    """Return list of available MCP tools."""
    return [
        Tool(
            name="clone_to_repos",
            description="Clone a GitHub repository into repos/. SNAP repos_watcher ingests automatically after clone. project_id is derived from the repo name — cannot be supplied.",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "GitHub repository URL (https://github.com/owner/repo)",
                    },
                    "vendor_id": {
                        "type": "string",
                        "description": "Your identifier for audit logging",
                    },
                    "branch": {
                        "type": "string",
                        "description": "Optional branch to clone (default: default branch)",
                    },
                },
                "required": ["repo_url", "vendor_id"],
            },
        ),
        Tool(
            name="get_project_notebook",
            description="Retrieve the complete analysis notebook for a project, including all snapshots organized by type and file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                    "vendor_id": {
                        "type": "string",
                        "description": "Your identifier for audit logging",
                    },
                },
                "required": ["project_id", "vendor_id"],
            },
        ),
        Tool(
            name="delete_project",
            description="Delete a project and all its snapshots. This is irreversible.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier to delete",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="get_staging_info",
            description="Get information about the staging area for a project, including list of uploaded files.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="upload_to_staging",
            description="Upload a file to the project staging area. Use this before process_local_project.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Relative filename (e.g., 'main.py' or 'src/utils.py')",
                    },
                    "content": {
                        "type": "string",
                        "description": "File content (text or base64-encoded)",
                    },
                    "encoding": {
                        "type": "string",
                        "enum": ["utf-8", "base64"],
                        "description": "Content encoding: 'utf-8' for text, 'base64' for binary",
                        "default": "utf-8",
                    },
                },
                "required": ["project_id", "filename", "content"],
            },
        ),
        Tool(
            name="clear_staging",
            description="Clear all files from the project staging area.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="copy_to_staging",
            description="Copy a local file or directory into the project staging area.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                    "source_path": {
                        "type": "string",
                        "description": "Absolute path to a file or directory on the local filesystem",
                    },
                },
                "required": ["project_id", "source_path"],
            },
        ),
        Tool(
            name="get_project_manifest",
            description="Get processing statistics for a project (files processed, snapshots created, etc.).",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="query_snapshots",
            description="Query snapshots by type or file. Use to find specific information like 'all security issues' or 'imports for main.py'.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                    "snapshot_type": {
                        "type": "string",
                        "enum": [
                            "file_metadata", "imports", "exports", "functions",
                            "classes", "connections", "repo_metadata", "security",
                            "quality", "doc_metadata", "doc_content", "doc_analysis",
                            "config_metadata"
                        ],
                        "description": "Filter by snapshot type",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Filter by source file path",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="list_projects",
            description="List all ingested projects with snapshot counts and last processed timestamps. Use this to verify the exact project_id before querying.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="list_runs",
            description="List all processing runs for a project, newest first. Shows run status (running/draft/active/failed/superseded), file and snapshot counts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="promote_run",
            description="Manually promote a draft run to active. Use this when process_project left a run in 'draft' status due to critical validation (file count dropped >50%). Verify the run is correct before promoting.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "Project identifier",
                    },
                    "run_id": {
                        "type": "string",
                        "description": "Run ID to promote (must be in draft status)",
                    },
                },
                "required": ["project_id", "run_id"],
            },
        ),
        Tool(
            name="get_system_metrics",
            description="Get overall system metrics including total projects, files processed, and snapshot statistics.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="kill_task",
            description="Cancel a running tool task by ID. Use to stop a stuck or interrupted async operation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "ID of the task to cancel",
                    },
                },
                "required": ["task_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls from MCP clients."""
    logger.info("MCP tool call: %s", name, extra={"arguments": arguments})

    try:
        if name == "clone_to_repos":
            result = await handle_clone_to_repos(
                repo_url=arguments["repo_url"],
                vendor_id=arguments["vendor_id"],
                branch=arguments.get("branch"),
            )

        elif name == "get_project_notebook":
            result = await handle_get_project_notebook(
                project_id=arguments["project_id"],
                vendor_id=arguments["vendor_id"],
            )

        elif name == "delete_project":
            result = await handle_delete_project(
                project_id=arguments["project_id"],
            )

        elif name == "list_projects":
            result = await handle_list_projects()

        elif name == "list_runs":
            result = await handle_list_runs(
                project_id=arguments["project_id"],
            )

        elif name == "promote_run":
            result = await handle_promote_run(
                project_id=arguments["project_id"],
                run_id=arguments["run_id"],
            )

        elif name == "get_staging_info":
            result = await handle_get_staging_info(
                project_id=arguments["project_id"],
            )

        elif name == "upload_to_staging":
            result = await handle_upload_to_staging(
                project_id=arguments["project_id"],
                filename=arguments["filename"],
                content=arguments["content"],
                encoding=arguments.get("encoding", "utf-8"),
            )

        elif name == "clear_staging":
            result = await handle_clear_staging(
                project_id=arguments["project_id"],
            )

        elif name == "copy_to_staging":
            result = await handle_copy_to_staging(
                project_id=arguments["project_id"],
                source_path=arguments["source_path"],
            )

        elif name == "get_project_manifest":
            result = await handle_get_project_manifest(
                project_id=arguments["project_id"],
            )

        elif name == "query_snapshots":
            result = await handle_query_snapshots(
                project_id=arguments["project_id"],
                snapshot_type=arguments.get("snapshot_type"),
                file_path=arguments.get("file_path"),
            )

        elif name == "get_system_metrics":
            result = await handle_get_system_metrics()

        elif name == "kill_task":
            result = await handle_kill_task(
                task_id=arguments["task_id"],
            )

        else:
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Unknown tool: {name}"}),
            )]

        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2, default=str),
        )]

    except ValidationError as e:
        logger.warning("Validation error in %s: %s", name, e)
        return [TextContent(
            type="text",
            text=json.dumps({"error": "validation_error", "message": str(e)}),
        )]

    except SecurityError as e:
        logger.error("Security error in %s: %s", name, e)
        return [TextContent(
            type="text",
            text=json.dumps({"error": "security_error", "message": str(e)}),
        )]

    except ToolError as e:
        logger.error("Tool error in %s: %s", name, e)
        return [TextContent(
            type="text",
            text=json.dumps({"error": "tool_error", "message": str(e)}),
        )]

    except Exception as e:
        logger.exception("Unexpected error in %s: %s", name, e)
        return [TextContent(
            type="text",
            text=json.dumps({"error": "internal_error", "message": str(e)}),
        )]


# =============================================================================
# HTTP+SSE Transport
# =============================================================================

def create_app() -> Starlette:
    """
    Create Starlette application with MCP SSE transport.

    Returns:
        Configured Starlette app ready to serve MCP over HTTP+SSE
    """
    sse_transport = SseServerTransport("/messages/")

    async def handle_sse(request):
        """Handle SSE connection for MCP protocol."""
        async with sse_transport.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    async def handle_messages(request):
        """Handle POST messages for MCP protocol."""
        return await sse_transport.handle_post_message(
            request.scope,
            request.receive,
            request._send,
        )

    async def health_check(_request):
        """Health check endpoint."""
        return JSONResponse({
            "status": "healthy",
            "service": "snap-mcp",
            "version": "1.0.0",
        })

    # Configure CORS middleware
    settings = get_settings()
    origins = settings.cors_allowed_origins or ["*"]
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=origins != ["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        ),
        Middleware(AuthMiddleware),
    ]

    # Base routes
    routes = [
        Route("/health", health_check, methods=["GET"]),
        Route("/sse", handle_sse, methods=["GET"]),
        Route("/messages/", handle_messages, methods=["POST"]),
    ]

    # Auth routes (always registered; middleware self-disables when auth.enabled=False)
    routes.extend([
        Route("/auth/github/login", github_login_redirect, methods=["GET"]),
        Route("/auth/github/callback", github_callback, methods=["GET"]),
        Route("/auth/token", issue_token, methods=["POST"]),
    ])

    app = Starlette(
        debug=False,
        routes=routes,
        middleware=middleware,
    )

    return app
