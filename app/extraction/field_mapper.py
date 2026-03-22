#app/extraction/field_mapper.py
"""
Purpose: Map parser outputs into categorized snapshot types.

Architecture:
- Snippet categories loaded from snapshot_templates/*.json at startup (no hardcoding)
- Accepts dict outputs from parsers (field_id → value mapping)
- Categorizes fields into snapshot types defined by templates
- Returns categorized field map for snapshot builder
- Merges outputs from multiple parsers (tree_sitter + semgrep)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List

from app.logging.logger import get_logger
from app.extraction.binary_packer import field_id as fnv_field_id, build_field_reverse_map


class FieldMappingError(Exception):
    pass


# =============================================================================
# Sensitive Data Masking
# =============================================================================

SENSITIVE_FIELD_IDS = {
    "code.security.hardcoded_secrets",
}

SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?'), "api_key"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key"),
    (re.compile(r'(?i)(aws[_-]?secret|secret[_-]?key)["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?'), "aws_secret"),
    (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "github_token"),
    (re.compile(r'(?i)(token|secret|password|passwd|pwd)["\s:=]+["\']?([^\s"\']{8,})["\']?'), "generic_secret"),
    (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+'), "bearer_token"),
    (re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'), "jwt_token"),
    (re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----'), "private_key"),
    (re.compile(r'(?i)(mongodb|postgres|mysql|redis)://[^:]+:[^@]+@'), "connection_string"),
]


# =============================================================================
# Prompt Injection Detection
# =============================================================================

INJECTION_PATTERNS = [
    (re.compile(r'(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier|your|my)\s+instructions?\b'), "override_instructions"),
    (re.compile(r'(?i)\bdisregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+instructions?\b'), "disregard_instructions"),
    (re.compile(r'(?i)\bforget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|context|rules?)\b'), "forget_instructions"),
    (re.compile(r'(?i)\boverride\s+(your\s+)?(instructions?|rules?|guidelines?|constraints?|safety|alignment)\b'), "override_rules"),
    (re.compile(r'(?i)\byour\s+(new|real|true|actual|updated)\s+instructions?\s*(are\s*:|:|\bfollow\b)'), "replace_instructions"),
    (re.compile(r'(?i)\bnew\s+instructions?\s*(:|are|follow)\b'), "new_instructions"),
    (re.compile(r'(?i)\[\s*(SYSTEM|INST|SYS|INSTRUCTION|PROMPT|OPERATOR)\s*\]'), "system_bracket_tag"),
    (re.compile(r'(?i)<\s*(SYSTEM|INST|SYS|INSTRUCTION|PROMPT)\s*>'), "system_angle_tag"),
    (re.compile(r'(?i)\bSYSTEM\s+(PROMPT|MESSAGE|INSTRUCTION|CONTEXT)\s*:'), "system_prompt_label"),
    (re.compile(r'(?im)^#+\s*(SYSTEM|INSTRUCTION|PROMPT)\s*$'), "markdown_system_header"),
    (re.compile(r'(?i)\byou\s+are\s+now\s+(a\s+|an\s+)?(different|unrestricted|unfiltered|jailbroken|evil|rogue|uncensored)\b'), "identity_hijack"),
    (re.compile(r'(?i)\bact\s+as\s+(a\s+|an\s+)?(jailbroken|unfiltered|unrestricted|evil|malicious|rogue|uncensored)\b'), "act_as_malicious"),
    (re.compile(r'(?i)\bpretend\s+(you\s+are|to\s+be)\s+(a\s+|an\s+)?(different|jailbroken|unfiltered|evil|uncensored)\b'), "pretend_jailbreak"),
    (re.compile(r'(?i)\bfrom\s+now\s+on[,\s]+(you\s+)?(will|must|shall|should|are\s+to)\s+(ignore|forget|disregard|follow\s+new)\b'), "from_now_on_override"),
    (re.compile(r'(?i)\bDAN\b(?=\s*(mode|prompt|jailbreak|enabled|activated|is|:))'), "dan_jailbreak"),
    (re.compile(r'(?i)\bdeveloper\s+mode\s+(enabled|activated|on|unlock)\b'), "developer_mode_unlock"),
    (re.compile(r'(?i)\bjailbreak(ed)?\s+(mode|claude|gpt|llm|ai|prompt)\b'), "jailbreak_trigger"),
    (re.compile(r'(?i)\bdo\s+anything\s+now\b'), "do_anything_now"),
    (re.compile(r'(?i)\bSTAN\s+mode\b'), "stan_jailbreak"),
    (re.compile(r'(?i)\b(reveal|output|print|repeat|show|leak|expose|dump)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?|training)\b'), "exfiltrate_prompt"),
    (re.compile(r'(?i)\brepeat\s+(everything|all(\s+the\s+text)?)\s+(above|before|prior|earlier)\b'), "repeat_context"),
    (re.compile(r'(?i)\bwhat\s+(are\s+your|is\s+your)\s+(instructions?|system\s+prompt|rules?|directives?)\b'), "probe_system_prompt"),
    (re.compile(r'(?i)\bignore\s+(everything|all(\s+the\s+text)?)\s+(above|before|prior|earlier)\b'), "ignore_context_above"),
    (re.compile(r'(?i)\bdecode\s+(this|the\s+following|base64)\s+and\s+(execute|follow|run|perform|obey)\b'), "encoded_instruction"),
    (re.compile(r'(?im)^(human|user|assistant|ai|claude|gpt)\s*:\s*ignore\b'), "role_delimiter_injection"),
    (re.compile(r'(?i)```\s*(system|instruction|prompt)\b'), "code_block_system_injection"),
]


def _scan_for_injection(text: str) -> list:
    if not isinstance(text, str) or len(text) < 10:
        return []
    return [(m.group(0), name) for pattern, name in INJECTION_PATTERNS if (m := pattern.search(text))]


def _redact_secret_value(value: str) -> str:
    length = len(value) if isinstance(value, str) else 0
    return f"[REDACTED:{length}chars]"


def _scan_and_redact(text: str) -> tuple[str, List[str]]:
    if not isinstance(text, str) or len(text) < 8:
        return text, []
    detected = []
    redacted = text
    for pattern, secret_type in SECRET_PATTERNS:
        if pattern.search(redacted):
            detected.append(secret_type)
            redacted = pattern.sub(f"[REDACTED:{secret_type}]", redacted)
    return redacted, detected


def _redact_field_value(fid: str, value: Any, logger) -> Any:
    if fid in SENSITIVE_FIELD_IDS:
        if isinstance(value, list):
            logger.warning(f"Redacting {len(value)} secrets from {fid}")
            return [_redact_secret_value(v) if isinstance(v, str) else "[REDACTED]" for v in value]
        if isinstance(value, str):
            logger.warning(f"Redacting secret from {fid}")
            return _redact_secret_value(value)
        if isinstance(value, dict):
            logger.warning(f"Redacting secrets dict from {fid}")
            return {k: _redact_secret_value(str(v)) for k, v in value.items()}
        return "[REDACTED]"

    if isinstance(value, str):
        redacted, detected_secrets = _scan_and_redact(value)
        if detected_secrets:
            logger.warning(f"Auto-redacted secrets in {fid}: {detected_secrets}")
        for matched_text, pattern_name in _scan_for_injection(redacted):
            logger.error(f"PROMPT INJECTION BLOCKED in field '{fid}': pattern='{pattern_name}' matched='{matched_text[:80]}'")
            redacted = redacted.replace(matched_text, f"[INJECTION_BLOCKED:{pattern_name}]")
        return redacted

    if isinstance(value, list):
        result = []
        for item in value:
            if not isinstance(item, str):
                result.append(item)
                continue
            redacted_item, detected_secrets = _scan_and_redact(item)
            if detected_secrets:
                logger.warning(f"Auto-redacted secrets in {fid} list item: {detected_secrets}")
            for matched_text, pattern_name in _scan_for_injection(redacted_item):
                logger.error(f"PROMPT INJECTION BLOCKED in field '{fid}' list: pattern='{pattern_name}' matched='{matched_text[:80]}'")
                redacted_item = redacted_item.replace(matched_text, f"[INJECTION_BLOCKED:{pattern_name}]")
            result.append(redacted_item)
        return result

    return value


def load_snippet_categories(templates_dir: Path) -> Dict[str, List[str]]:
    """
    Load snippet_type → [field_ids] from schemas/master_notebook.yaml "field_id_registry" section and snapshot_templates/*.json "fields" keys.
    Single source of truth — no hardcoding.
    """
    categories = {}
    if not templates_dir.exists():
        return categories
    for path in templates_dir.glob("*.json"):
        try:
            with open(path, encoding="utf-8") as f:
                template = json.load(f)
            categories[path.stem] = list(template.get("fields", {}).keys())
        except (OSError, json.JSONDecodeError):
            pass
    return categories


@dataclass
class CategorizedFields:
    """Field map categorized by snippet type."""
    snippets: Dict[str, Dict[str, Any]]  # snippet_type → {field_id: value}
    parser: str


class FieldMapper:
    def __init__(self, *, master_schema: Dict[str, Any], templates_dir: Path) -> None:
        self.master_schema = master_schema
        self.logger = get_logger("extraction.field_mapper")

        self.snippet_categories = load_snippet_categories(templates_dir)

        # Reverse map: field_id → snippet_type
        self.field_to_snippet_type: Dict[str, str] = {
            fid: stype
            for stype, fids in self.snippet_categories.items()
            for fid in fids
        }

        self.allowed_field_ids = self._build_allowed_fields()

        # Build reverse map for binary unpacker: fnv1a(field_name) → field_name
        self.id_to_name = build_field_reverse_map(self.allowed_field_ids)
        self.name_to_id = {name: fnv_field_id(name) for name in self.allowed_field_ids}

    def _build_allowed_fields(self) -> set:
        allowed = set()
        for fields in self.master_schema.get("field_id_registry", {}).values():
            for field_def in fields:
                allowed.add(field_def["field_id"])
        return allowed

    def get_field_id_mappings(self) -> tuple:
        return self.name_to_id, self.id_to_name

    def categorize_parser_output(
        self,
        parser_output: Dict[str, Any],
        parser_name: str,
        source_file: str
    ) -> CategorizedFields:
        categorized: Dict[str, Dict[str, Any]] = {stype: {} for stype in self.snippet_categories}
        unknown_fields = []

        for fid, value in parser_output.items():
            if fid not in self.allowed_field_ids:
                unknown_fields.append(fid)
                self.logger.warning(f"Unknown field_id from {parser_name}: {fid}")
                continue

            stype = self.field_to_snippet_type.get(fid)
            if stype is None:
                self.logger.warning(f"Field {fid} not mapped to any snippet type")
                continue

            categorized[stype][fid] = _redact_field_value(fid, value, self.logger)

        categorized = {k: v for k, v in categorized.items() if v}

        self.logger.debug("Categorized parser output", extra={
            "parser": parser_name,
            "source_file": source_file,
            "total_fields": len(parser_output),
            "snippet_types_created": len(categorized),
            "unknown_fields": len(unknown_fields),
        })

        return CategorizedFields(snippets=categorized, parser=parser_name)

    def merge_categorized_fields(self, *categorized_list: CategorizedFields) -> Dict[str, Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {stype: {} for stype in self.snippet_categories}

        for categorized in categorized_list:
            for stype, fields in categorized.snippets.items():
                merged[stype].update(fields)

        merged = {k: v for k, v in merged.items() if v}

        self.logger.debug("Merged categorized fields", extra={
            "parsers_merged": len(categorized_list),
            "snippet_types_total": len(merged),
        })

        return merged
