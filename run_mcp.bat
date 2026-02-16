@echo off
SETLOCAL
SET "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

IF EXIST ".venv-1\Scripts\python.exe" (
    SET "PATH=%ROOT_DIR%.venv-1\Scripts;%ROOT_DIR%.venv-1\Lib\site-packages\semgrep\bin;%PATH%"
    ".venv-1\Scripts\python.exe" -m app.mcp.run %*
) ELSE (
    echo Error: Virtual environment not found at .venv-1
    pause
    exit /b 1
)
ENDLOCAL
