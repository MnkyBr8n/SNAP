# app/mcp/security.py
"""
Staging security validators for MCP server.

Provides path traversal prevention, project isolation, and input validation
for all staging operations exposed via MCP tools.
"""

from __future__ import annotations

import re
import math
import fnmatch
from pathlib import Path
from typing import Dict, Any, Tuple

from app.config.settings import get_settings
from app.ingest.local_loader import IGNORE_PATTERNS


class SecurityError(Exception):
    """Raised when a security validation fails."""


class ValidationError(Exception):
    """Raised when input validation fails."""


# Project ID: alphanumeric, underscore, hyphen, 3-64 chars
VALID_PROJECT_ID = re.compile(r'^[a-zA-Z0-9_-]{3,64}$')

# Vendor ID: alphanumeric, underscore, hyphen, dot, @, 1-64 chars — no injection chars
VALID_VENDOR_ID = re.compile(r'^[a-zA-Z0-9_@.\-]{1,64}$')

# Filename: alphanumeric, dot, underscore, hyphen, forward slash (for subdirs)
# No backslash, no leading/trailing slashes
VALID_FILENAME = re.compile(r'^[a-zA-Z0-9._-][a-zA-Z0-9._/-]{0,254}$')

# Forbidden patterns in any path component
FORBIDDEN_PATTERNS = ['..', '\x00', '~', ':', '*', '?', '"', '<', '>', '|']

# Reserved names (Windows)
RESERVED_NAMES = {
    'con', 'prn', 'aux', 'nul',
    'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
    'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
}


def validate_project_id(project_id: str) -> str:
    """
    Validate project_id format and content.

    Rules:
    - Pattern: ^[a-zA-Z0-9_-]{3,64}$
    - Not reserved names
    - Not starting with: -, .

    Args:
        project_id: Project identifier to validate

    Returns:
        Validated project_id (stripped)

    Raises:
        ValidationError: If invalid
    """
    if not project_id:
        raise ValidationError("project_id is required")

    project_id = project_id.strip().lower()

    if not VALID_PROJECT_ID.match(project_id):
        raise ValidationError(
            f"Invalid project_id format: must be 3-64 alphanumeric characters, "
            f"underscores, or hyphens. Got: {project_id!r}"
        )

    if project_id.startswith('-') or project_id.startswith('.'):
        raise ValidationError(
            f"project_id cannot start with '-' or '.'. Got: {project_id!r}"
        )

    if project_id.lower() in RESERVED_NAMES:
        raise ValidationError(
            f"project_id cannot be a reserved name. Got: {project_id!r}"
        )

    return project_id


def validate_filename(filename: str) -> str:
    """
    Validate and sanitize uploaded filename.

    Rules:
    - Pattern: ^[a-zA-Z0-9._-][a-zA-Z0-9._/-]{0,254}$
    - No path separators (backslash)
    - No null bytes or forbidden characters
    - No leading/trailing slashes
    - Not matching IGNORE_PATTERNS

    Args:
        filename: Filename to validate

    Returns:
        Validated filename

    Raises:
        ValidationError: If invalid
    """
    if not filename:
        raise ValidationError("filename is required")

    filename = filename.strip()

    # Normalize path separators to forward slash
    filename = filename.replace('\\', '/')

    # Remove leading/trailing slashes
    filename = filename.strip('/')

    if not filename:
        raise ValidationError("filename cannot be empty after normalization")

    # Check for forbidden patterns
    for pattern in FORBIDDEN_PATTERNS:
        if pattern in filename:
            raise SecurityError(
                f"Forbidden pattern in filename: {pattern!r}"
            )

    # Check regex pattern
    if not VALID_FILENAME.match(filename):
        raise ValidationError(
            f"Invalid filename format: {filename!r}"
        )

    # Check each path component
    for part in filename.split('/'):
        if not part:
            raise ValidationError("Empty path component in filename")

        if part.lower() in RESERVED_NAMES:
            raise ValidationError(
                f"Reserved name in path: {part!r}"
            )

        if part.startswith('.') and part not in ('.gitignore', '.gitattributes'):
            # Allow common dotfiles but reject hidden directories
            if '.' not in part[1:]:  # It's a hidden dir like .git
                raise ValidationError(
                    f"Hidden directory not allowed: {part!r}"
                )

    # Check against ignore patterns (secrets, credentials, etc.)
    if _matches_ignore_pattern(filename):
        raise ValidationError(
            f"File matches ignore pattern (secrets/credentials): {filename!r}"
        )

    return filename


def _matches_ignore_pattern(filename: str) -> bool:
    """Check if filename matches any IGNORE_PATTERNS."""
    path = Path(filename)

    for pattern in IGNORE_PATTERNS:
        # Check each part of the path
        for part in path.parts:
            if fnmatch.fnmatch(part, pattern):
                return True

        # Check full path
        if fnmatch.fnmatch(filename, pattern):
            return True

        # Check filename only
        if fnmatch.fnmatch(path.name, pattern):
            return True

    return False


def get_safe_staging_path(project_id: str, filename: str) -> Path:
    """
    Return validated path within staging/{project_id}/.

    Security:
    1. Validates project_id
    2. Validates filename
    3. Constructs path
    4. Resolves and verifies within staging root
    5. Checks for symlinks

    Args:
        project_id: Project identifier
        filename: Relative filename within staging

    Returns:
        Safe absolute Path within staging directory

    Raises:
        SecurityError: If path traversal detected
        ValidationError: If inputs invalid
    """
    # Validate inputs
    project_id = validate_project_id(project_id)
    filename = validate_filename(filename)

    settings = get_settings()
    staging_root = settings.data_dir / "staging"
    project_staging = staging_root / project_id

    # Create staging directories first (required for resolve() on Windows)
    staging_root.mkdir(parents=True, exist_ok=True)
    project_staging.mkdir(parents=True, exist_ok=True)

    # Resolve all paths to absolute for consistent Windows/Unix handling
    # Now that dirs exist, resolve() works correctly on all platforms
    staging_root_resolved = staging_root.resolve()
    project_staging_resolved = project_staging.resolve()

    # Construct target path and resolve
    target = project_staging / filename

    # Resolve to absolute path
    try:
        resolved = target.resolve()
    except (OSError, ValueError) as e:
        raise SecurityError(f"Invalid path: {e}") from e

    # Verify path is within project staging
    try:
        resolved.relative_to(project_staging_resolved)
    except ValueError as exc:
        raise SecurityError(
            f"Path traversal detected: {filename!r} escapes staging directory"
        ) from exc

    # Check if any parent is a symlink (symlink attack prevention)
    # Use resolved paths for consistent comparison on Windows
    current = resolved.parent
    while current != staging_root_resolved:
        if current.is_symlink():
            raise SecurityError(
                f"Symlink detected in path: {current}"
            )
        if current == current.parent:  # Reached filesystem root
            break
        current = current.parent

    return resolved


def validate_vendor_id(vendor_id: str) -> str:
    """
    Validate vendor_id format.

    Args:
        vendor_id: Vendor identifier to validate

    Returns:
        Validated vendor_id (stripped)

    Raises:
        ValidationError: If invalid
    """
    if not vendor_id:
        raise ValidationError("vendor_id is required")

    vendor_id = vendor_id.strip()

    if not VALID_VENDOR_ID.match(vendor_id):
        raise ValidationError(
            "vendor_id must be 1-64 characters: alphanumeric, underscore, hyphen, dot, or @"
        )

    return vendor_id


def validate_repo_url(repo_url: str) -> str:
    """
    Validate GitHub repository URL.

    Args:
        repo_url: Repository URL to validate

    Returns:
        Validated URL

    Raises:
        ValidationError: If invalid
    """
    if not repo_url:
        raise ValidationError("repo_url is required")

    repo_url = repo_url.strip()

    # Must be HTTPS GitHub URL
    if not repo_url.startswith('https://github.com/'):
        raise ValidationError(
            "repo_url must be an HTTPS GitHub URL (https://github.com/...)"
        )

    # Basic format check
    parts = repo_url.replace('https://github.com/', '').rstrip('/').split('/')
    if len(parts) < 2:
        raise ValidationError(
            "repo_url must include owner and repo name"
        )

    return repo_url


def _load_valid_snapshot_types() -> set:
    """
    Derive valid snapshot types from app/schemas/snapshot_templates/*.json.
    master_notebook.yaml + snapshot_templates/ are the single source of truth.
    No hardcoded list — adding a template file makes the type valid automatically.
    """
    settings = get_settings()
    templates_dir = settings.schemas_dir / "snapshot_templates"
    if not templates_dir.exists():
        # Fallback: empty set causes ValidationError with useful message
        return set()
    return {p.stem for p in templates_dir.glob("*.json")}


# Cached at import time — reset by restarting the server
_VALID_SNAPSHOT_TYPES: set = set()


def validate_snapshot_type(snapshot_type: str) -> str:
    """
    Validate snapshot type against registered snapshot_templates/.

    Valid types are derived from app/schemas/snapshot_templates/*.json.
    To add a new type: create the template file and restart the server.

    Args:
        snapshot_type: Snapshot type to validate

    Returns:
        Validated (lowercased) snapshot type

    Raises:
        ValidationError: If type is not registered in templates
    """
    global _VALID_SNAPSHOT_TYPES
    if not _VALID_SNAPSHOT_TYPES:
        _VALID_SNAPSHOT_TYPES = _load_valid_snapshot_types()

    if not snapshot_type:
        raise ValidationError("snapshot_type is required")

    snapshot_type = snapshot_type.strip().lower()

    if not _VALID_SNAPSHOT_TYPES:
        raise ValidationError(
            "Cannot validate snapshot_type: no templates found in "
            "app/schemas/snapshot_templates/"
        )

    if snapshot_type not in _VALID_SNAPSHOT_TYPES:
        raise ValidationError(
            f"Invalid snapshot_type: {snapshot_type!r}. "
            f"Must be one of: {', '.join(sorted(_VALID_SNAPSHOT_TYPES))}. "
            f"To add a new type, create app/schemas/snapshot_templates/{snapshot_type}.json first."
        )

    return snapshot_type


# =============================================================================
# Content Safety Validation
# =============================================================================

# Content limits
MAX_FIELD_LENGTH = 50_000          # 50KB per field
MAX_TOTAL_CONTENT_LENGTH = 500_000  # 500KB total per snapshot
HIGH_ENTROPY_THRESHOLD = 0.85       # Shannon entropy threshold (0-1)
MIN_LENGTH_FOR_ENTROPY_CHECK = 500  # Only check entropy on strings > 500 chars

# Patterns indicating potentially malicious/minified content
SUSPICIOUS_CONTENT_PATTERNS = [
    r'[a-zA-Z0-9+/=]{100,}',        # Long base64-like strings
    r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){20,}',  # Hex-encoded data
    r'%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2}){20,}',      # URL-encoded data
    r'[^\s]{500,}',                 # Very long strings without whitespace
]

def _calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    High entropy (>0.85) indicates:
    - Minified/obfuscated code
    - Encoded/encrypted data
    - Random/generated content

    Args:
        data: String to analyze

    Returns:
        Entropy value between 0 and 1 (normalized)
    """
    if not data:
        return 0.0

    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    # Calculate Shannon entropy
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    # Normalize to 0-1 range (max entropy for ASCII is ~7 bits)
    max_entropy = math.log2(min(len(freq), 256))
    if max_entropy > 0:
        return entropy / max_entropy

    return 0.0


def _check_suspicious_patterns(content: str) -> list:
    """
    Check content for suspicious patterns.

    Args:
        content: String to check

    Returns:
        List of matched pattern descriptions
    """
    matches = []

    if re.search(r'[a-zA-Z0-9+/=]{100,}', content):
        matches.append("base64-like-block")

    if re.search(r'(?:\\x[0-9a-fA-F]{2}){20,}', content):
        matches.append("hex-encoded-data")

    if re.search(r'(?:%[0-9a-fA-F]{2}){20,}', content):
        matches.append("url-encoded-data")

    if re.search(r'[^\s\n]{500,}', content):
        matches.append("long-unbroken-string")

    return matches


def validate_content_safety(
    field_values: Dict[str, Any],
    strict: bool = False
) -> Tuple[Dict[str, Any], list]:
    """
    Validate content safety before database insertion.

    Checks:
    1. Individual field length limits
    2. Total content size limits
    3. High-entropy detection (minified/obfuscated code)
    4. Suspicious pattern detection (encoded payloads)

    Args:
        field_values: Dict of field_id -> value to validate
        strict: If True, raise on violations. If False, truncate/flag.

    Returns:
        Tuple of (sanitized_fields, warnings_list)

    Raises:
        SecurityError: If strict=True and violations found
    """
    warnings = []
    sanitized = {}
    total_size = 0

    for field_id, value in field_values.items():
        # Convert to string for analysis
        if value is None:
            sanitized[field_id] = value
            continue

        if isinstance(value, (list, dict)):
            # For complex types, serialize and check total size
            import json
            str_value = json.dumps(value)
        else:
            str_value = str(value)

        field_size = len(str_value)
        total_size += field_size

        # Check individual field length
        if field_size > MAX_FIELD_LENGTH:
            warning = f"Field '{field_id}' exceeds {MAX_FIELD_LENGTH} chars ({field_size})"
            warnings.append(warning)

            if strict:
                raise SecurityError(warning)

            # Truncate with marker
            if isinstance(value, str):
                sanitized[field_id] = value[:MAX_FIELD_LENGTH] + f"[TRUNCATED:{field_size}]"
            else:
                sanitized[field_id] = value  # Keep complex types, warn only
            continue

        # Check entropy on long strings
        if isinstance(value, str) and len(value) > MIN_LENGTH_FOR_ENTROPY_CHECK:
            entropy = _calculate_entropy(value)

            if entropy > HIGH_ENTROPY_THRESHOLD:
                warning = f"Field '{field_id}' has high entropy ({entropy:.2f}) - possible minified/encoded content"
                warnings.append(warning)

                if strict:
                    raise SecurityError(warning)

                # Flag but don't truncate (might be legitimate minified code)
                sanitized[field_id] = f"[HIGH_ENTROPY:{entropy:.2f}] " + value[:1000] + f"[...{len(value)} chars]"
                continue

        # Check suspicious patterns
        if isinstance(value, str):
            suspicious = _check_suspicious_patterns(value)
            if suspicious:
                warning = f"Field '{field_id}' contains suspicious patterns: {', '.join(suspicious)}"
                warnings.append(warning)

                if strict:
                    raise SecurityError(warning)

                # Add flag prefix
                sanitized[field_id] = f"[SUSPICIOUS:{','.join(suspicious)}] " + value
                continue

        # No issues - pass through
        sanitized[field_id] = value

    # Check total content size
    if total_size > MAX_TOTAL_CONTENT_LENGTH:
        warning = f"Total content size ({total_size}) exceeds limit ({MAX_TOTAL_CONTENT_LENGTH})"
        warnings.append(warning)

        if strict:
            raise SecurityError(warning)

    return sanitized, warnings


def sanitize_for_database(field_values: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience wrapper for validate_content_safety in non-strict mode.

    Args:
        field_values: Dict of field_id -> value

    Returns:
        Sanitized field_values dict (warnings logged but not returned)
    """
    from app.logging.logger import get_logger
    logger = get_logger("mcp.security")

    sanitized, warnings = validate_content_safety(field_values, strict=False)

    for warning in warnings:
        logger.warning(f"Content safety warning: {warning}")

    return sanitized
