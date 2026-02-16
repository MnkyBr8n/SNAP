#app/extraction/field_mapper.py
"""
Purpose: Map parser outputs into 15 categorized snapshot types.

Architecture:
- Accepts dict outputs from parsers (field_id → value mapping)
- Categorizes fields into 15 snapshot types
- Returns categorized field map for snapshot builder
- Merges outputs from multiple parsers (tree_sitter + semgrep)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Any, List

from app.logging.logger import get_logger


class FieldMappingError(Exception):
    pass


# =============================================================================
# Sensitive Data Masking
# =============================================================================

# Fields that may contain raw secrets - ALWAYS redact values
SENSITIVE_FIELD_IDS = {
    "code.security.hardcoded_secrets",
}

# Patterns to detect secrets in any string value
# Format: (pattern, description) - description used in logs
SECRET_PATTERNS = [
    # API Keys (generic)
    (re.compile(r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?'), "api_key"),
    # AWS Access Keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key"),
    # AWS Secret Keys
    (re.compile(r'(?i)(aws[_-]?secret|secret[_-]?key)["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?'), "aws_secret"),
    # GitHub tokens
    (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "github_token"),
    # Generic tokens/secrets
    (re.compile(r'(?i)(token|secret|password|passwd|pwd)["\s:=]+["\']?([^\s"\']{8,})["\']?'), "generic_secret"),
    # Bearer tokens
    (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+'), "bearer_token"),
    # JWT tokens
    (re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'), "jwt_token"),
    # Private keys
    (re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'), "private_key"),
    # Connection strings with passwords
    (re.compile(r'(?i)(mongodb|postgres|mysql|redis)://[^:]+:[^@]+@'), "connection_string"),
]


# =============================================================================
# Prompt Injection Detection
# =============================================================================

# Content-based injection patterns — scanned on ALL string field values
# regardless of file type. Extension-based trust is meaningless; any file
# can carry injected instructions in comments, strings, or free-form text.
INJECTION_PATTERNS = [
    # Instruction override
    (re.compile(r'(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier|your|my)\s+instructions?\b'), "override_instructions"),
    (re.compile(r'(?i)\bdisregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+instructions?\b'), "disregard_instructions"),
    (re.compile(r'(?i)\bforget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|context|rules?)\b'), "forget_instructions"),
    (re.compile(r'(?i)\boverride\s+(your\s+)?(instructions?|rules?|guidelines?|constraints?|safety|alignment)\b'), "override_rules"),
    (re.compile(r'(?i)\byour\s+(new|real|true|actual|updated)\s+instructions?\s*(are\s*:|:|\bfollow\b)'), "replace_instructions"),
    (re.compile(r'(?i)\bnew\s+instructions?\s*(:|are|follow)\b'), "new_instructions"),

    # System prompt injection markers
    (re.compile(r'(?i)\[\s*(SYSTEM|INST|SYS|INSTRUCTION|PROMPT|OPERATOR)\s*\]'), "system_bracket_tag"),
    (re.compile(r'(?i)<\s*(SYSTEM|INST|SYS|INSTRUCTION|PROMPT)\s*>'), "system_angle_tag"),
    (re.compile(r'(?i)\bSYSTEM\s+(PROMPT|MESSAGE|INSTRUCTION|CONTEXT)\s*:'), "system_prompt_label"),
    (re.compile(r'(?im)^#+\s*(SYSTEM|INSTRUCTION|PROMPT)\s*$'), "markdown_system_header"),

    # Identity / role hijacking
    (re.compile(r'(?i)\byou\s+are\s+now\s+(a\s+|an\s+)?(different|unrestricted|unfiltered|jailbroken|evil|rogue|uncensored)\b'), "identity_hijack"),
    (re.compile(r'(?i)\bact\s+as\s+(a\s+|an\s+)?(jailbroken|unfiltered|unrestricted|evil|malicious|rogue|uncensored)\b'), "act_as_malicious"),
    (re.compile(r'(?i)\bpretend\s+(you\s+are|to\s+be)\s+(a\s+|an\s+)?(different|jailbroken|unfiltered|evil|uncensored)\b'), "pretend_jailbreak"),
    (re.compile(r'(?i)\bfrom\s+now\s+on[,\s]+(you\s+)?(will|must|shall|should|are\s+to)\s+(ignore|forget|disregard|follow\s+new)\b'), "from_now_on_override"),

    # Known jailbreak triggers
    (re.compile(r'(?i)\bDAN\b(?=\s*(mode|prompt|jailbreak|enabled|activated|is|:))'), "dan_jailbreak"),
    (re.compile(r'(?i)\bdeveloper\s+mode\s+(enabled|activated|on|unlock)\b'), "developer_mode_unlock"),
    (re.compile(r'(?i)\bjailbreak(ed)?\s+(mode|claude|gpt|llm|ai|prompt)\b'), "jailbreak_trigger"),
    (re.compile(r'(?i)\bdo\s+anything\s+now\b'), "do_anything_now"),
    (re.compile(r'(?i)\bSTAN\s+mode\b'), "stan_jailbreak"),

    # Exfiltration attempts
    (re.compile(r'(?i)\b(reveal|output|print|repeat|show|leak|expose|dump)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?|training)\b'), "exfiltrate_prompt"),
    (re.compile(r'(?i)\brepeat\s+(everything|all(\s+the\s+text)?)\s+(above|before|prior|earlier)\b'), "repeat_context"),
    (re.compile(r'(?i)\bwhat\s+(are\s+your|is\s+your)\s+(instructions?|system\s+prompt|rules?|directives?)\b'), "probe_system_prompt"),

    # Context manipulation
    (re.compile(r'(?i)\bignore\s+(everything|all(\s+the\s+text)?)\s+(above|before|prior|earlier)\b'), "ignore_context_above"),

    # Encoded / obfuscated injection
    (re.compile(r'(?i)\bdecode\s+(this|the\s+following|base64)\s+and\s+(execute|follow|run|perform|obey)\b'), "encoded_instruction"),

    # Role-play delimiter injection
    (re.compile(r'(?im)^(human|user|assistant|ai|claude|gpt)\s*:\s*ignore\b'), "role_delimiter_injection"),
    (re.compile(r'(?i)```\s*(system|instruction|prompt)\b'), "code_block_system_injection"),
]


def _scan_for_injection(text: str) -> list:
    """
    Scan text for prompt injection patterns.

    Args:
        text: String to scan

    Returns:
        List of (matched_text, pattern_name) tuples for each detected pattern
    """
    if not isinstance(text, str) or len(text) < 10:
        return []

    hits = []
    for pattern, name in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append((match.group(0), name))
    return hits


def _redact_secret_value(value: str) -> str:
    """
    Redact a known secret value, preserving type hint.

    Args:
        value: The secret string

    Returns:
        Redacted placeholder with length hint
    """
    length = len(value) if isinstance(value, str) else 0
    return f"[REDACTED:{length}chars]"


def _scan_and_redact(text: str) -> tuple[str, List[str]]:
    """
    Scan text for secret patterns and redact matches.

    Args:
        text: String to scan

    Returns:
        Tuple of (redacted_text, list of detected secret types)
    """
    if not isinstance(text, str) or len(text) < 8:
        return text, []

    detected = []
    redacted = text

    for pattern, secret_type in SECRET_PATTERNS:
        if pattern.search(redacted):
            detected.append(secret_type)
            redacted = pattern.sub(f"[REDACTED:{secret_type}]", redacted)

    return redacted, detected


def _redact_field_value(field_id: str, value: Any, logger) -> Any:
    """
    Redact sensitive data from a field value.

    Args:
        field_id: The field identifier
        value: The field value (string, list, or dict)
        logger: Logger instance for warnings

    Returns:
        Redacted value
    """
    # Fields that are ALWAYS fully redacted
    if field_id in SENSITIVE_FIELD_IDS:
        if isinstance(value, list):
            redacted_count = len(value)
            logger.warning(f"Redacting {redacted_count} secrets from {field_id}")
            return [_redact_secret_value(v) if isinstance(v, str) else "[REDACTED]" for v in value]
        elif isinstance(value, str):
            logger.warning(f"Redacting secret from {field_id}")
            return _redact_secret_value(value)
        elif isinstance(value, dict):
            logger.warning(f"Redacting secrets dict from {field_id}")
            return {k: _redact_secret_value(str(v)) for k, v in value.items()}
        return "[REDACTED]"

    # For other fields, scan for secrets and prompt injection
    if isinstance(value, str):
        redacted, detected_secrets = _scan_and_redact(value)
        if detected_secrets:
            logger.warning(f"Auto-redacted secrets in {field_id}: {detected_secrets}")

        injection_hits = _scan_for_injection(redacted)
        if injection_hits:
            for matched_text, pattern_name in injection_hits:
                logger.error(
                    f"PROMPT INJECTION BLOCKED in field '{field_id}': "
                    f"pattern='{pattern_name}' matched='{matched_text[:80]}'"
                )
            for matched_text, pattern_name in injection_hits:
                redacted = redacted.replace(matched_text, f"[INJECTION_BLOCKED:{pattern_name}]")

        return redacted

    elif isinstance(value, list):
        redacted_list = []
        for item in value:
            if isinstance(item, str):
                redacted_item, detected_secrets = _scan_and_redact(item)
                if detected_secrets:
                    logger.warning(f"Auto-redacted secrets in {field_id} list item: {detected_secrets}")

                injection_hits = _scan_for_injection(redacted_item)
                if injection_hits:
                    for matched_text, pattern_name in injection_hits:
                        logger.error(
                            f"PROMPT INJECTION BLOCKED in field '{field_id}' list: "
                            f"pattern='{pattern_name}' matched='{matched_text[:80]}'"
                        )
                    for matched_text, pattern_name in injection_hits:
                        redacted_item = redacted_item.replace(matched_text, f"[INJECTION_BLOCKED:{pattern_name}]")

                redacted_list.append(redacted_item)
            else:
                redacted_list.append(item)
        return redacted_list

    return value


# 15 snippet categories mapping
SNIPPET_CATEGORIES = {
    "file_metadata": [
        "code.file.path",
        "code.file.language",
        "code.file.loc",
        "code.file.package"
    ],
    "imports": [
        "code.imports.modules",
        "code.imports.from_files",
        "code.imports.external",
        "code.imports.internal"
    ],
    "exports": [
        "code.exports.functions",
        "code.exports.classes",
        "code.exports.constants",
        "code.exports.types"
    ],
    "functions": [
        "code.functions.names",
        "code.functions.signatures",
        "code.functions.async",
        "code.functions.decorators"
    ],
    "classes": [
        "code.classes.names",
        "code.classes.inheritance",
        "code.classes.methods",
        "code.classes.properties",
        "code.classes.interfaces"
    ],
    "connections": [
        "code.connections.depends_on",
        "code.connections.depended_by",
        "code.connections.function_calls",
        "code.connections.instantiates"
    ],
    "repo_metadata": [
        "repo.primary_language",
        "repo.entrypoints",
        "repo.modules",
        "repo.test_framework",
        "repo.ci_pipeline"
    ],
    "security": [
        "code.security.vulnerabilities",
        "code.security.hardcoded_secrets",
        "code.security.sql_injection_risks",
        "code.security.xss_risks"
    ],
    "quality": [
        "code.quality.antipatterns",
        "code.quality.code_smells",
        "code.quality.todos",
        "code.quality.deprecated_usage"
    ],
    "config_metadata": [
        "config.file.path",
        "config.file.format",
        "config.structure.toplevel_keys",
        "config.structure.nested_paths",
        "config.structure.depth",
        "config.settings.parameter_names",
        "config.settings.env_vars",
        "config.database.connection_strings",
        "config.api.endpoints",
        "config.api.hosts"
    ],
    "doc_metadata": [
        "doc.title",
        "doc.author",
        "doc.date",
        "doc.version",
        "doc.language"
    ],
    "doc_content": [
        "doc.summary",
        "doc.key_concepts",
        "doc.technical_terms",
        "doc.acronyms",
        "doc.urls",
        "doc.code_snippets"
    ],
    "doc_analysis": [
        "doc.key_requirements",
        "doc.entities",
        "doc.references",
        "doc.related_files",
        "doc.api_endpoints",
    ],
    "csv_schema": [
        "csv.schema.column_names",
        "csv.schema.column_types",
        "csv.schema.column_count",
    ],
    "csv_data": [
        "csv.stats.row_count",
        "csv.stats.null_counts",
        "csv.stats.unique_counts",
        "csv.sample.first_rows"
    ],
}

# Reverse mapping: field_id → snippet_type
FIELD_TO_SNIPPET_TYPE = {}
for snippet_type, field_ids in SNIPPET_CATEGORIES.items():
    for field_id in field_ids:
        FIELD_TO_SNIPPET_TYPE[field_id] = snippet_type


@dataclass
class CategorizedFields:
    """Field map categorized by snippet type."""
    snippets: Dict[str, Dict[str, Any]]  # snippet_type → {field_id: value}
    parser: str  # Parser that generated these fields


class FieldMapper:
    def __init__(self, *, master_schema: Dict[str, Any]) -> None:
        """
        Args:
            master_schema: Loaded master_notebook.yaml
        """
        self.master_schema = master_schema
        self.logger = get_logger("extraction.field_mapper")
        
        # Build allowed field set from schema
        self.allowed_field_ids = self._build_allowed_fields()
    
    def _build_allowed_fields(self) -> set:
        """Extract all allowed field_ids from master schema."""
        allowed = set()
        field_registry = self.master_schema.get("field_id_registry", {})
        
        for category, fields in field_registry.items():
            for field_def in fields:
                allowed.add(field_def["field_id"])
        
        return allowed
    
    def categorize_parser_output(
        self,
        parser_output: Dict[str, Any],
        parser_name: str,
        source_file: str
    ) -> CategorizedFields:
        """
        Categorize parser output dict into 15 snippet types.
        
        Args:
            parser_output: Dict with field_id → value mappings from parser
            parser_name: Name of parser (tree_sitter, semgrep, text_extractor, csv_parser)
            source_file: Source file path
        
        Returns:
            CategorizedFields with snippets organized by type
        """
        categorized = {snippet_type: {} for snippet_type in SNIPPET_CATEGORIES.keys()}
        unknown_fields = []
        
        for field_id, value in parser_output.items():
            # Validate field_id
            if field_id not in self.allowed_field_ids:
                unknown_fields.append(field_id)
                self.logger.warning(f"Unknown field_id from {parser_name}: {field_id}")
                continue
            
            # Get snippet type for this field
            snippet_type = FIELD_TO_SNIPPET_TYPE.get(field_id)
            
            if snippet_type is None:
                self.logger.warning(f"Field {field_id} not mapped to any snippet type")
                continue
            
            # Redact sensitive data before storing
            redacted_value = _redact_field_value(field_id, value, self.logger)

            # Add to appropriate snippet category
            categorized[snippet_type][field_id] = redacted_value
        
        # Remove empty snippet categories
        categorized = {k: v for k, v in categorized.items() if v}
        
        self.logger.debug("Categorized parser output", extra={
            "parser": parser_name,
            "source_file": source_file,
            "total_fields": len(parser_output),
            "snippet_types_created": len(categorized),
            "unknown_fields": len(unknown_fields)
        })
        
        return CategorizedFields(snippets=categorized, parser=parser_name)
    
    def merge_categorized_fields(
        self,
        *categorized_list: CategorizedFields
    ) -> Dict[str, Dict[str, Any]]:
        """
        Merge multiple CategorizedFields (from different parsers) into single dict.
        
        Args:
            *categorized_list: Multiple CategorizedFields from different parsers
        
        Returns:
            Merged dict: snippet_type → {field_id: value}
        """
        merged = {snippet_type: {} for snippet_type in SNIPPET_CATEGORIES.keys()}
        
        for categorized in categorized_list:
            for snippet_type, fields in categorized.snippets.items():
                # Merge fields, later values overwrite earlier
                merged[snippet_type].update(fields)
        
        # Remove empty snippet categories
        merged = {k: v for k, v in merged.items() if v}
        
        self.logger.debug("Merged categorized fields", extra={
            "parsers_merged": len(categorized_list),
            "snippet_types_total": len(merged)
        })
        
        return merged
