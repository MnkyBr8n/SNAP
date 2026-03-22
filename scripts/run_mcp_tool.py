#!/usr/bin/env python
"""Run MCP tool handler for processing a GitHub repo.

Usage:
    python scripts/run_mcp_tool.py --repo REPO_URL --project PROJECT_ID --vendor VENDOR_ID [--branch BRANCH]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from app.mcp.tools import handle_process_github_repo, ToolError


async def _main(args: argparse.Namespace) -> int:
    try:
        result = await handle_process_github_repo(
            repo_url=args.repo,
            project_id=args.project,
            vendor_id=args.vendor,
            branch=args.branch,
        )
        # Print JSON to stdout for easy parsing
        print(json.dumps(result, indent=2))
        return 0
    except ToolError as e:
        print(f"ToolError: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", required=True, help="GitHub repo URL (https://github.com/owner/repo)")
    p.add_argument("--project", required=True, help="Project identifier (3-64 chars)")
    p.add_argument("--vendor", required=True, help="Vendor/caller identifier for audit logging")
    p.add_argument("--branch", required=False, help="Optional branch name")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    raise SystemExit(asyncio.run(_main(args)))
