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

    def _preload_templates(self) -> None:
        """Preload all templates into cache on init."""
        if not self.templates_dir.exists():
            self.logger.warning(f"Templates directory not found: {self.templates_dir}")
            return

        for template_path in self.templates_dir.glob("*.json"):
            snapshot_type = template_path.stem
            try:
                with open(template_path, encoding="utf-8") as f:
                    self._template_cache[snapshot_type] = json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to preload template {snapshot_type}: {e}")
                self._template_cache[snapshot_type] = None

        self.logger.info(f"Preloaded {len(self._template_cache)} templates")

    def _load_template(self, snapshot_type: str) -> Optional[Dict[str, Any]]:
        """Get template from cache."""
        if snapshot_type in self._template_cache:
            return self._template_cache[snapshot_type]

        # Fallback: load from disk if not cached (shouldn't happen)
        template_path = self.templates_dir / f"{snapshot_type}.json"

        if not template_path.exists():
            self._template_cache[snapshot_type] = None
            return None

        try:
            with open(template_path, encoding="utf-8") as f:
                template = json.load(f)
                self._template_cache[snapshot_type] = template
                return template
        except Exception as e:
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
            )

            snapshot = {
                "snapshot_id": snapshot_record.snapshot_id,
                "run_id": run_id,
                "project_id": project_id,
                "file_path": file_path,
                "snapshot_type": snapshot_type,
                "parsers": parsers_used,
                "fields": fields,
                "created_at": snapshot_record.created_at.isoformat() + "Z",
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
                "created_at": record.created_at.isoformat() + "Z"
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
                "created_at": record.created_at.isoformat() + "Z"
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
