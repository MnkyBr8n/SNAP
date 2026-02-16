"""
Semgrep parser for security vulnerability and code quality detection.

Supports 14 languages, same as tree_sitter.
Outputs only authorized fields: code.security.*, code.quality.*
"""

from pathlib import Path
from typing import Dict, Any, Optional, List
import subprocess
import json
import re
import time
import sys
import os

from app.logging.logger import get_logger
from app.config.settings import get_settings

logger = get_logger("parsers.semgrep")


def _find_semgrep_core_bin() -> Optional[str]:
    """Find semgrep-core bin directory for PATH injection."""
    core_bin = Path(sys.executable).parent.parent / "Lib" / "site-packages" / "semgrep" / "bin"
    if core_bin.is_dir() and (core_bin / "semgrep-core.exe").is_file():
        return str(core_bin)
    # Unix layout
    core_bin_unix = Path(sys.executable).parent.parent / "lib" / "python" + f"{sys.version_info.major}.{sys.version_info.minor}" / "site-packages" / "semgrep" / "bin"
    if core_bin_unix.is_dir():
        return str(core_bin_unix)
    return None


def _build_semgrep_env() -> Dict[str, str]:
    """Build environment dict that lets semgrep find semgrep-core."""
    env = os.environ.copy()
    core_bin = _find_semgrep_core_bin()
    if core_bin:
        env["PATH"] = core_bin + os.pathsep + env.get("PATH", "")
    # Force UTF-8 mode for Python (required for "auto" ruleset on Windows)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


# Build env once at import time
_SEMGREP_ENV: Dict[str, str] = _build_semgrep_env()

# Semgrep timeouts — pulled from settings at call time for monorepo scalability.

# Code context lines before/after findings
CONTEXT_LINES = 3

# Semgrep rulesets
DEFAULT_RULESETS = [
    "p/security-audit",
    "p/owasp-top-10",
    "auto"
]


def parse_code_semgrep(
    path: Optional[Path] = None,
    content: Optional[str] = None,
    language: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parse code file using semgrep static analysis.
    
    Args:
        path: File path (if parsing from file)
        content: File content (if parsing from string, e.g., god parser shard)
        language: Language/extension (py, ts, js, etc.)
    
    Returns:
        Dict with field_id keys matching master_notebook.yaml
        
    Raises:
        RuntimeError: if semgrep execution fails
        ValueError: if required arguments are missing
    """
    start_time = time.time()
    
    # Get file path for semgrep execution
    if path is None and content is None:
        raise ValueError("Either path or content must be provided")

    # Initialize temp_path before try block to avoid NameError in finally
    temp_path: Optional[Path] = None
    is_temp = False

    if content is not None:
        # For god parser shards: write to temp file
        import tempfile
        safe_lang = re.sub(r'[^a-zA-Z0-9]', '', language or '') or 'tmp'
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{safe_lang}', delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)
        file_path = temp_path
        is_temp = True
    else:
        file_path = path

    try:
        # Execute semgrep CLI
        findings = _run_semgrep(file_path, language)
        
        # Extract code context for findings
        file_lines = _read_file_lines(file_path)
        findings_with_context = _add_code_context(findings, file_lines)
        
        # Map to field_ids
        result = _map_findings_to_fields(findings_with_context)
        
        duration_ms = (time.time() - start_time) * 1000
        
        logger.info("Semgrep scan complete", extra={
            "file": str(file_path),
            "language": language,
            "scan_duration_ms": duration_ms,
            "findings_total": len(findings),
            "vulnerabilities": len(result.get("code.security.vulnerabilities", [])),
            "quality_issues": len(result.get("code.quality.code_smells", []))
        })
        
        return result
        
    finally:
        # Clean up temp file
        if is_temp and temp_path is not None and temp_path.exists():
            temp_path.unlink()


def _semgrep_cmd(extra_args: List[str]) -> List[str]:
    """Build semgrep command using venv Python + CLI entry point."""
    config_args: List[str] = []
    for ruleset in DEFAULT_RULESETS:
        config_args.extend(["--config", ruleset])
    return [
        sys.executable, "-c",
        "from semgrep.cli import cli; cli()",
        "--json",
        "--metrics=on",
        "--disable-version-check",
    ] + config_args + extra_args


def _run_semgrep(file_path: Path, language: Optional[str]) -> List[Dict[str, Any]]:
    """Execute semgrep CLI and parse JSON output."""
    lang_args = ["--lang", language] if language else []
    cmd = _semgrep_cmd(lang_args + [str(file_path)])

    _timeout = get_settings().parser_limits.semgrep_timeout_per_file
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_timeout,
            env=_SEMGREP_ENV
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Semgrep timed out after {_timeout}s on {file_path}"
        ) from exc

    # Semgrep returns non-zero on findings, which is not an error
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep execution failed (returncode={result.returncode}) on {file_path}: "
            f"{result.stderr[:500]}"
        )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Semgrep produced invalid JSON for {file_path}: {e}") from e

    findings = output.get("results", [])

    logger.debug("Semgrep execution complete", extra={
        "file": str(file_path),
        "findings_count": len(findings)
    })

    return findings


def _read_file_lines(file_path: Path) -> List[str]:
    """Read file into line array for context extraction."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.readlines()


def _add_code_context(
    findings: List[Dict[str, Any]],
    file_lines: List[str]
) -> List[Dict[str, Any]]:
    """Add code context (lines before/after) to each finding."""
    findings_with_context = []
    
    for finding in findings:
        # Get line number (1-indexed)
        start_line = finding.get("start", {}).get("line", 0)
        
        if start_line == 0 or not file_lines:
            # No line number or no file content
            finding["code_context"] = None
            findings_with_context.append(finding)
            continue
        
        # Extract context (convert to 0-indexed)
        line_idx = start_line - 1
        before_start = max(0, line_idx - CONTEXT_LINES)
        after_end = min(len(file_lines), line_idx + CONTEXT_LINES + 1)
        
        before_lines = [line.rstrip() for line in file_lines[before_start:line_idx]]
        match_line = file_lines[line_idx].rstrip() if line_idx < len(file_lines) else ""
        after_lines = [line.rstrip() for line in file_lines[line_idx + 1:after_end]]
        
        finding["code_context"] = {
            "before": before_lines,
            "match": match_line,
            "after": after_lines
        }
        
        findings_with_context.append(finding)
    
    return findings_with_context


def _map_findings_to_fields(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Map semgrep findings to field_ids.
    
    Severity mapping:
    - ERROR/WARNING → vulnerabilities, with categorization
    - INFO → code_smells, todos, deprecated_usage
    """
    result = {
        "code.security.vulnerabilities": [],
        "code.security.hardcoded_secrets": [],
        "code.security.sql_injection_risks": [],
        "code.security.xss_risks": [],
        "code.quality.antipatterns": [],
        "code.quality.code_smells": [],
        "code.quality.todos": [],
        "code.quality.deprecated_usage": []
    }
    
    for finding in findings:
        severity = finding.get("extra", {}).get("severity", "INFO")
        rule_id = finding.get("check_id", "")
        message = finding.get("extra", {}).get("message", "")
        line = finding.get("start", {}).get("line", 0)
        code_context = finding.get("code_context")
        
        finding_data = {
            "rule_id": rule_id,
            "severity": severity,
            "line": line,
            "message": message,
            "code_context": code_context
        }
        
        # Categorize by severity and rule pattern
        if severity in ("ERROR", "WARNING"):
            # Security vulnerabilities
            if "secret" in rule_id.lower() or "password" in rule_id.lower() or "token" in rule_id.lower():
                result["code.security.hardcoded_secrets"].append(finding_data)
            elif "sql" in rule_id.lower() or "injection" in rule_id.lower():
                result["code.security.sql_injection_risks"].append(finding_data)
            elif "xss" in rule_id.lower() or "cross-site" in rule_id.lower():
                result["code.security.xss_risks"].append(finding_data)
            else:
                result["code.security.vulnerabilities"].append(finding_data)
        else:
            # Code quality issues (INFO)
            if "todo" in message.lower() or "fixme" in message.lower():
                # Extract TODO text
                result["code.quality.todos"].append(f"{message} (line {line})")
            elif "deprecated" in message.lower():
                result["code.quality.deprecated_usage"].append(finding_data)
            elif "anti" in message.lower() or "pattern" in message.lower():
                result["code.quality.antipatterns"].append(finding_data)
            else:
                result["code.quality.code_smells"].append(finding_data)
    
    return result


def batch_semgrep_scan(file_paths: List[Path]) -> Dict[str, Dict[str, Any]]:
    """
    Run semgrep ONCE on all files, return per-file mapped results.

    Instead of spawning one subprocess per file (N cold starts, N rule downloads),
    this passes all files to a single semgrep invocation and splits the output.

    Args:
        file_paths: List of code file paths to scan

    Returns:
        Dict mapping str(file_path) -> field_id result dict
    """
    if not file_paths:
        raise ValueError("batch_semgrep_scan requires at least one file path")

    start_time = time.time()

    cmd = _semgrep_cmd([str(p) for p in file_paths])

    _timeout = get_settings().parser_limits.semgrep_batch_timeout_seconds
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_timeout,
            env=_SEMGREP_ENV
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Batch semgrep timed out after {_timeout}s "
            f"for {len(file_paths)} files"
        ) from exc

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Batch semgrep failed (returncode={result.returncode}): "
            f"{result.stderr[:500] if result.stderr else ''}"
        )

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Batch semgrep produced invalid JSON: {e}") from e

    all_findings = output.get("results", [])

    # Group findings by source file
    findings_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for finding in all_findings:
        fpath = finding.get("path", "")
        if fpath not in findings_by_file:
            findings_by_file[fpath] = []
        findings_by_file[fpath].append(finding)

    # Map each file's findings to field_ids with code context
    results: Dict[str, Dict[str, Any]] = {}
    for file_path in file_paths:
        fp_str = str(file_path)
        file_findings = findings_by_file.get(fp_str, [])

        if file_findings:
            file_lines = _read_file_lines(file_path)
            findings_with_ctx = _add_code_context(file_findings, file_lines)
            results[fp_str] = _map_findings_to_fields(findings_with_ctx)
        else:
            results[fp_str] = _map_findings_to_fields([])

    duration_ms = (time.time() - start_time) * 1000
    logger.info("Batch semgrep complete", extra={
        "files_scanned": len(file_paths),
        "total_findings": len(all_findings),
        "duration_ms": round(duration_ms, 1)
    })

    return results


def _check_semgrep_version() -> tuple[bool, str]:
    """
    Run semgrep --version and return (compatible, version_string).
    Returns (False, "") if semgrep is not installed or fails to run.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-c", "from semgrep.cli import cli; cli(['--version'])"],
            capture_output=True,
            text=True,
            timeout=10,
            env=_SEMGREP_ENV,
            check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, ""

    if result.returncode != 0:
        return False, ""

    version_output = result.stdout.strip()
    try:
        version_parts = version_output.split()[0].split('.')
        major = int(version_parts[0])
        minor = int(version_parts[1])
    except (ValueError, IndexError):
        return False, version_output

    compatible = (major > 1) or (major == 1 and minor >= 50)
    return compatible, version_output


def validate_semgrep_installation() -> None:
    """
    Validate semgrep CLI on startup. Auto-installs/upgrades if missing or incompatible.

    Raises:
        RuntimeError: if semgrep cannot be installed or validated after auto-install
    """
    compatible, version = _check_semgrep_version()

    if not compatible:
        logger.info("Semgrep not found or incompatible — auto-installing latest...")
        install = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "semgrep"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )
        if install.returncode != 0:
            raise RuntimeError(
                f"Semgrep auto-install failed — manual fix: pip install semgrep\n"
                f"{install.stderr.strip()}"
            )
        logger.info("Semgrep installed. Re-validating...")
        compatible, version = _check_semgrep_version()
        if not compatible:
            raise RuntimeError(
                "Semgrep validation failed after auto-install — require >=1.50.0\n"
                "Manual fix: pip install --upgrade semgrep"
            )

    logger.info(f"Semgrep validated: {version}")
