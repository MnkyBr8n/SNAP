#!/bin/bash
# Get the directory where this script is located
ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$ROOT_DIR"

# Path to the venv python (Linux/Mac use 'bin' instead of 'Scripts')
VENV_PYTHON="./.venv/bin/python"

if [ -f "$VENV_PYTHON" ]; then
    "$VENV_PYTHON" -m app.mcp.run "$@"
else
    echo "[ERROR] Virtual environment not found at $VENV_PYTHON"
    echo "Please ensure you have created the venv using: python3 -m venv .venv"
    exit 1
fi
