# snap/app/extraction/snapshot_builder.py
"""
Build categorized snapshots per file for RAG notebook system.

Uses snapshot_templates/ for snapshot category definitions.
Creates up to 15 snapshot types: file_metadata, imports, exports, functions, classes,
connections, repo_metadata, security, quality, config_metadata,
doc_metadata, doc_content, doc_analysis, csv_data, csv_schema
"""

from __future__ import annotations

from typing import Dict, List, Any, Optional
from datetime import datetime
from uuid import uuid4
from pathlib import Path
import json

from app.logging.logger import get_logger
from app.storage.snapshot_repo import SnapshotRepository


class SnapshotBuilderError(Exception):
    pass


def compute_simhash(text: str, hash_bits: int = 64) -> str:
    """
    Compute SimHash for fast similarity detection.

    Args:
        text: Input text to hash
        hash_bits: Number of bits in hash (default 64)

    Returns:
        Hex string representation of SimHash (16 chars for 64-bit)
    """
    import hashlib
    import re

    # Tokenize (simple whitespace + alphanumeric)
    tokens = re.findall(r'\w+', text.lower())
    if not tokens:
        return "0" * 16

    # Initialize bit vector
    v = [0] * hash_bits

    # For each token, hash and update bit vector
    for token in tokens:
        # Hash token to get bit pattern
        h = hashlib.md5(token.encode()).digest()

        # Convert bytes to bits and update vector
        for i in range(hash_bits):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx < len(h):
                if (h[byte_idx] >> bit_idx) & 1:
                    v[i] += 1
                else:
                    v[i] -= 1

    # Convert vector to hash
    simhash = 0
    for i in range(hash_bits):
        if v[i] > 0:
            simhash |= (1 << i)

    # Return as hex string (16 chars for 64-bit)
    return f"{simhash:016x}"


def compute_minhash(text: str, num_perm: int = 128) -> str:
    """
    Compute MinHash for semantic similarity (Jaccard estimation).

    Args:
        text: Input text to hash
        num_perm: Number of hash permutations (default 128)

    Returns:
        Comma-separated hex string of MinHash signature values
    """
    import hashlib
    import re

    # Tokenize into shingles (3-grams of words)
    tokens = re.findall(r'\w+', text.lower())
    if not tokens:
        return ",".join(["0"] * num_perm)

    # Create shingles (overlapping 3-grams)
    shingles = set()
    for i in range(len(tokens) - 2):
        shingle = ' '.join(tokens[i:i+3])
        shingles.add(shingle)

    if not shingles:
        shingles = set(tokens)  # Fallback to individual tokens

    # MinHash signature
    signature = [float('inf')] * num_perm

    for shingle in shingles:
        for i in range(num_perm):
            # Create unique hash for each permutation
            h = hashlib.sha256(f"{i}:{shingle}".encode()).digest()
            hash_val = int.from_bytes(h[:4], 'big')  # Use first 4 bytes as int
            signature[i] = min(signature[i], hash_val)

    # Convert to hex strings (8 chars for 32-bit ints)
    hex_values = [f"{int(s):08x}" if s != float('inf') else "00000000" for s in signature]
    return ",".join(hex_values)


def compute_content_hash(snapshot_type: str, source_file: str, field_values: Dict[str, Any]) -> str:
    """
    Compute SHA-256 content hash for exact versioning.

    Args:
        snapshot_type: Type of snapshot
        source_file: Source file path
        field_values: Snapshot field values

    Returns:
        Hex string of SHA-256 hash
    """
    import hashlib

    # Create deterministic representation
    data = f"{snapshot_type}|{source_file}|{json.dumps(field_values, sort_keys=True)}"
    return hashlib.sha256(data.encode()).hexdigest()


class SnapshotBuilder:
    def __init__(self, master_schema: Dict[str, Any]) -> None:
        """
        Args:
            master_schema: Loaded master_notebook.yaml schema
        """
        self.master_schema = master_schema
        self.logger = get_logger("extraction.snapshot_builder")
        self.snapshot_repo = SnapshotRepository()

        # Template directory path
        self.templates_dir = Path("app/schemas/snapshot_templates")

        # Cache templates to avoid repeated disk reads
        self._template_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        self._preload_templates()

    def _registered_templates(self) -> set:
        """Return snapshot type names registered in master_schema."""
        return set(self.master_schema.get("snapshot_templates", {}).keys())

    def _registered_field_ids(self) -> set:
        """Return all field_ids registered in master_schema field_id_registry."""
        ids = set()
        for section in self.master_schema.get("field_id_registry", {}).values():
            for field in section:
                ids.add(field["field_id"])
        return ids

    def _validate_template(self, snapshot_type: str, template: Dict[str, Any]) -> bool:
        """
        Validate template against master_schema.
        Rejects if snapshot_type not registered or any field not in field_id_registry.
        """
        registered_types = self._registered_templates()
        if snapshot_type not in registered_types:
            self.logger.error(
                f"Template '{snapshot_type}' rejected: not registered in master_notebook snapshot_templates",
                extra={"snapshot_type": snapshot_type}
            )
            return False

        registered_ids = self._registered_field_ids()
        unknown_fields = [f for f in template.get("fields", {}) if f not in registered_ids]
        if unknown_fields:
            self.logger.error(
                f"Template '{snapshot_type}' rejected: unregistered fields {unknown_fields}",
                extra={"snapshot_type": snapshot_type, "unknown_fields": unknown_fields}
            )
            return False

        return True

    def _preload_templates(self) -> None:
        """Preload all templates into cache on init. Only caches templates validated against master_notebook."""
        if not self.templates_dir.exists():
            self.logger.warning(f"Templates directory not found: {self.templates_dir}")
            return

        loaded = 0
        rejected = 0
        for template_path in self.templates_dir.glob("*.json"):
            snapshot_type = template_path.stem
            try:
                with open(template_path, encoding="utf-8") as f:
                    template = json.load(f)
                if self._validate_template(snapshot_type, template):
                    self._template_cache[snapshot_type] = template
                    loaded += 1
                else:
                    self._template_cache[snapshot_type] = None
                    rejected += 1
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
                self.logger.error(f"Failed to preload template {snapshot_type}: {e}")
                self._template_cache[snapshot_type] = None
                rejected += 1

        self.logger.info(f"Preloaded {loaded} templates, rejected {rejected}")

    def _load_template(self, snapshot_type: str) -> Optional[Dict[str, Any]]:
        """Get template from cache. Only returns templates validated against master_notebook."""
        if snapshot_type in self._template_cache:
            return self._template_cache[snapshot_type]

        template_path = self.templates_dir / f"{snapshot_type}.json"

        if not template_path.exists():
            self._template_cache[snapshot_type] = None
            return None

        try:
            with open(template_path, encoding="utf-8") as f:
                template = json.load(f)
            if self._validate_template(snapshot_type, template):
                self._template_cache[snapshot_type] = template
                return template
            self._template_cache[snapshot_type] = None
            return None
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            self.logger.error(f"Failed to load template {snapshot_type}: {e}")
            self._template_cache[snapshot_type] = None
            return None
    
    def create_snapshots(
        self,
        project_id: str,
        run_id: str,
        file_path: str,
        categorized_fields: Dict[str, Dict[str, Any]],
        parsers_used: List[str],
        source_hash: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Create categorized snapshots for a single file within a run.

        Args:
            project_id: Project identifier
            run_id: Active run_id — all snapshots scoped to this run
            file_path: Relative source file path from project root
            categorized_fields: Dict of snapshot_type → {field_id: value}
            parsers_used: List of parsers that generated fields
            source_hash: SHA256 of file content

        Returns:
            List of created snapshot dicts
        """
        self.logger.debug("Creating snapshots", extra={
            "project_id": project_id,
            "run_id": run_id,
            "file_path": file_path,
            "snapshot_types": len(categorized_fields),
            "parsers": parsers_used,
        })

        snapshots = []
        snapshot_ids = []
        snapshot_types = []

        for snapshot_type, fields in categorized_fields.items():
            template = self._load_template(snapshot_type)

            # Skip empty snapshots unless always_create
            if not fields:
                if template and not template.get("always_create", False):
                    self.logger.debug(f"Skipping empty snapshot type: {snapshot_type}")
                    continue

            snapshot_id = str(uuid4())

            # Compute three-layer hashes
            field_text = json.dumps(fields, sort_keys=True)
            content_hash = compute_content_hash(snapshot_type, file_path, fields)
            simhash = compute_simhash(field_text)
            minhash = compute_minhash(field_text)

            self.logger.debug("Attempting snapshot creation", extra={
                "snapshot_id": snapshot_id,
                "snapshot_type": snapshot_type,
                "file_path": file_path,
                "fields_count": len(fields),
            })

            snapshot_record = self.snapshot_repo.upsert(
                run_id=run_id,
                project_id=project_id,
                snapshot_type=snapshot_type,
                source_file=file_path,
                field_values=fields,
                snapshot_id=snapshot_id,
                source_hash=source_hash,
                content_hash=content_hash,
                simhash=simhash,
                minhash=minhash,
            )

            snapshot = {
                "snapshot_id": snapshot_record.snapshot_id,
                "run_id": run_id,
                "project_id": project_id,
                "file_path": file_path,
                "snapshot_type": snapshot_type,
                "parsers": parsers_used,
                "fields": fields,
                "created_at": (snapshot_record.created_at if isinstance(snapshot_record.created_at, str) else snapshot_record.created_at.isoformat() + "Z"),
                "source_hash": snapshot_record.source_hash,
            }
            
            snapshots.append(snapshot)
            snapshot_ids.append(snapshot_record.snapshot_id)
            snapshot_types.append(snapshot_type)
            
            self.logger.debug("Created snapshot", extra={
                "snapshot_id": snapshot_record.snapshot_id,
                "snapshot_type": snapshot_type,
                "fields_count": len(fields)
            })
        
        self.logger.debug("Snapshots created", extra={
            "project_id": project_id,
            "file_path": file_path,
            "snapshots_created": len(snapshots),
            "snapshot_types": snapshot_types,
            "snapshot_ids": snapshot_ids
        })
        
        return snapshots
    
    def get_file_snapshots(
        self,
        project_id: str,
        file_path: str
    ) -> List[Dict[str, Any]]:
        """Retrieve all snapshots for a specific file."""
        snapshot_records = self.snapshot_repo.get_by_file(project_id, file_path)
        
        snapshots = []
        for record in snapshot_records:
            snapshots.append({
                "snapshot_id": record.snapshot_id,
                "project_id": record.project_id,
                "file_path": record.source_file,
                "snapshot_type": record.snapshot_type,
                "fields": record.field_values,
                "created_at": record.created_at if isinstance(record.created_at, str) else record.created_at.isoformat() + "Z"
            })
        
        self.logger.info("Retrieved file snapshots", extra={
            "project_id": project_id,
            "file_path": file_path,
            "snapshots_count": len(snapshots)
        })
        
        return snapshots
    
    def get_project_snapshots_by_type(
        self,
        project_id: str,
        snapshot_type: str
    ) -> List[Dict[str, Any]]:
        """
        Retrieve all snapshots of a specific type across project.
        
        RAG query method: "Show all imports", "Find all security issues"
        """
        snapshot_records = self.snapshot_repo.get_by_type(project_id, snapshot_type)
        
        snapshots = []
        for record in snapshot_records:
            snapshots.append({
                "snapshot_id": record.snapshot_id,
                "project_id": record.project_id,
                "file_path": record.source_file,
                "snapshot_type": record.snapshot_type,
                "fields": record.field_values,
                "created_at": record.created_at if isinstance(record.created_at, str) else record.created_at.isoformat() + "Z"
            })
        
        self.logger.info("Retrieved project snapshots by type", extra={
            "project_id": project_id,
            "snapshot_type": snapshot_type,
            "snapshots_count": len(snapshots)
        })
        
        return snapshots
    
    def assemble_file_notebook(
        self,
        project_id: str,
        file_path: str
    ) -> Dict[str, Any]:
        """
        Assemble all snapshots for a file into single notebook structure.
        
        Useful for displaying complete file analysis.
        """
        snapshots = self.get_file_snapshots(project_id, file_path)
        
        notebook = {
            "meta": {
                "project_id": project_id,
                "file_path": file_path,
                "schema_id": self.master_schema.get("schema_id", "notebook_schema"),
                "assembled_at": datetime.utcnow().isoformat() + "Z"
            },
            "snapshots": {},
            "summary": {
                "total_snapshots": len(snapshots),
                "snapshot_types": []
            }
        }
        
        for snapshot in snapshots:
            notebook["snapshots"][snapshot["snapshot_type"]] = {
                "snapshot_id": snapshot["snapshot_id"],
                "fields": snapshot["fields"],
                "created_at": snapshot["created_at"]
            }
            notebook["summary"]["snapshot_types"].append(snapshot["snapshot_type"])
        
        self.logger.info("Assembled file notebook", extra={
            "project_id": project_id,
            "file_path": file_path,
            "snapshots": len(snapshots)
        })
        
        return notebook
    
    def assemble_project_notebook(
        self,
        project_id: str
    ) -> Dict[str, Any]:
        """
        Assemble all snapshots across entire project.
        
        Organized by snapshot type for RAG queries.
        """
        self.logger.info("Assembling project notebook", extra={
            "project_id": project_id
        })
        
        all_snapshot_records = self.snapshot_repo.get_by_project(project_id)
        
        notebook = {
            "meta": {
                "project_id": project_id,
                "schema_id": self.master_schema.get("schema_id", "notebook_schema"),
                "assembled_at": datetime.utcnow().isoformat() + "Z"
            },
            "snapshots_by_type": {},
            "snapshots_by_file": {},
            "summary": {
                "total_snapshots": len(all_snapshot_records),
                "total_files": 0,
                "snapshot_type_counts": {}
            }
        }
        
        # Organize by type
        for record in all_snapshot_records:
            snapshot_type = record.snapshot_type
            if snapshot_type not in notebook["snapshots_by_type"]:
                notebook["snapshots_by_type"][snapshot_type] = []
            
            notebook["snapshots_by_type"][snapshot_type].append({
                "snapshot_id": record.snapshot_id,
                "file_path": record.source_file,
                "fields": record.field_values
            })
        
        # Organize by file
        for record in all_snapshot_records:
            file_path = record.source_file
            if file_path not in notebook["snapshots_by_file"]:
                notebook["snapshots_by_file"][file_path] = []
            
            notebook["snapshots_by_file"][file_path].append({
                "snapshot_id": record.snapshot_id,
                "snapshot_type": record.snapshot_type,
                "fields": record.field_values
            })
        
        # Calculate summary
        notebook["summary"]["total_files"] = len(notebook["snapshots_by_file"])
        for snapshot_type, snapshots in notebook["snapshots_by_type"].items():
            notebook["summary"]["snapshot_type_counts"][snapshot_type] = len(snapshots)
        
        self.logger.info("Assembled project notebook", extra={
            "project_id": project_id,
            "total_snapshots": len(all_snapshot_records),
            "total_files": notebook["summary"]["total_files"],
            "snapshot_types": len(notebook["snapshots_by_type"])
        })
        
        return notebook
    
    def get_snapshot_stats(self, project_id: str) -> Dict[str, Any]:
        """Get statistics about project snapshots."""
        all_snapshot_records = self.snapshot_repo.get_by_project(project_id)
        
        stats = {
            "total_snapshots": len(all_snapshot_records),
            "by_type": {},
            "by_file": {},
            "storage_estimate_kb": 0
        }
        
        for record in all_snapshot_records:
            # Count by type
            snapshot_type = record.snapshot_type
            stats["by_type"][snapshot_type] = stats["by_type"].get(snapshot_type, 0) + 1
            
            # Count by file
            file_path = record.source_file
            stats["by_file"][file_path] = stats["by_file"].get(file_path, 0) + 1
            
            # Rough storage estimate
            snapshot_size = len(json.dumps(record.field_values))
            stats["storage_estimate_kb"] += snapshot_size / 1024

        stats["files_count"] = len(stats["by_file"])

        self.logger.info("Calculated snapshot stats", extra={
            "project_id": project_id,
            "total_snapshots": stats["total_snapshots"],
            "files_count": stats["files_count"],
            "storage_kb": round(stats["storage_estimate_kb"], 2)
        })

        return stats
