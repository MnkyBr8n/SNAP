# app/mcp/run.py
"""
Entry point for running the SNAP MCP server.

Usage (stdio mode - for Claude Code integration):
    python -m app.mcp.run

Usage (HTTP+SSE mode - for remote clients):
    python -m app.mcp.run --sse --port 8080
"""

from __future__ import annotations

import argparse
import sys
import asyncio
import logging


def _configure_logging_for_stdio():
    """Ensure ALL loggers output to stderr, not stdout (required for MCP)."""
    # Configure root logger to stderr
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)


def run_stdio():
    """Run MCP server in stdio mode (for Claude Code integration)."""
    # Disable stdout buffering for proper MCP communication
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)

    # MUST configure logging to stderr BEFORE any other imports
    _configure_logging_for_stdio()

    from mcp.server.stdio import stdio_server
    from app.main import startup
    from app.mcp.server import server
    from app.logging.logger import get_logger
    from app.ingest.staging_watcher import start_watcher as start_staging_watcher
    from app.ingest.repos_watcher import start_watcher as start_repos_watcher

    logger = get_logger("mcp.run")

    # Initialize SNAP
    logger.info("Initializing SNAP for stdio mode...")
    try:
        startup()
    except Exception as e:
        logger.error(f"Failed to initialize SNAP: {e}")
        sys.exit(1)

    # Start watchers: staging (local) and repos (GitHub)
    logger.info("Starting staging watcher (local ingest)...")
    start_staging_watcher()
    logger.info("Starting repos watcher (GitHub ingest)...")
    start_repos_watcher()

    logger.info("Starting SNAP MCP server (stdio mode)")

    async def run_server():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    asyncio.run(run_server())


def run_sse(host: str, port: int, log_level: str, reload: bool):
    """Run MCP server in HTTP+SSE mode (for remote clients)."""
    import uvicorn
    from app.main import startup
    from app.mcp.server import create_app
    from app.logging.logger import get_logger
    from app.ingest.staging_watcher import start_watcher as start_staging_watcher
    from app.ingest.repos_watcher import start_watcher as start_repos_watcher

    logger = get_logger("mcp.run")

    # Initialize SNAP
    logger.info("Initializing SNAP for SSE mode...")
    try:
        startup()
    except Exception as e:
        logger.error(f"Failed to initialize SNAP: {e}")
        sys.exit(1)

    # Start watchers: staging (local) and repos (GitHub)
    logger.info("Starting staging watcher (local ingest)...")
    start_staging_watcher()
    logger.info("Starting repos watcher (GitHub ingest)...")
    start_repos_watcher()

    logger.info(f"Starting SNAP MCP server on http://{host}:{port}")
    logger.info(f"SSE endpoint: http://{host}:{port}/sse")
    logger.info(f"Health check: http://{host}:{port}/health")

    app = create_app()

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level,
        reload=reload,
    )


def main():
    """Run the SNAP MCP server."""
    parser = argparse.ArgumentParser(
        description="Run the SNAP MCP server"
    )
    parser.add_argument(
        "--sse",
        action="store_true",
        help="Run in HTTP+SSE mode instead of stdio",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to in SSE mode (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on in SSE mode (default: 8080)",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development (SSE mode only)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Log level (default: info)",
    )

    args = parser.parse_args()

    if args.sse:
        run_sse(args.host, args.port, args.log_level, args.reload)
    else:
        run_stdio()


if __name__ == "__main__":
    main()
