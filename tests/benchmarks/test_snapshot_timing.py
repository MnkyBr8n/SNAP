# tests/benchmarks/test_snapshot_timing.py
"""
REAL benchmark tests for SNAP snapshot create vs update timing.

Uses actual:
- SnapshotRepository (real DB operations)
- parse_code_tree_sitter (real tree-sitter parsing)
- Files from this codebase

Run: pytest tests/benchmarks/test_snapshot_timing.py -v -s
"""

from __future__ import annotations

import time
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any
from datetime import datetime, timezone

import pytest

from app.storage.snapshot_repo import SnapshotRepository, SnapshotRecord
from app.parsers.tree_sitter_parser import parse_code_tree_sitter
from app.extraction.field_mapper import FieldMapper, SNIPPET_CATEGORIES
from app.ingest.file_router import route_file


@dataclass
class TimingResult:
    """Single timing measurement."""
    test_id: str
    snapshot_type: str
    operation: str  # "create" or "update"
    existing_id: str | None
    duration_ms: float
    rows_written: int
    rows_updated: int
    conflicts: int
    file_path: str
    file_size: int
    stage: str  # "parse", "map", "db_write", "db_read"


class TimingCollector:
    """Collects real timing data."""

    def __init__(self):
        self.results: List[TimingResult] = []

    def record(self, result: TimingResult):
        self.results.append(result)

    def report(self) -> str:
        """Generate timing report."""
        if not self.results:
            return "No results"

        lines = [
            "=" * 70,
            "SNAP SNAPSHOT TIMING REPORT",
            "=" * 70,
            f"Total measurements: {len(self.results)}",
            "",
        ]

        # Group by stage
        by_stage: Dict[str, List[float]] = {}
        for r in self.results:
            by_stage.setdefault(r.stage, []).append(r.duration_ms)

        lines.append("--- By Stage ---")
        for stage, times in sorted(by_stage.items()):
            avg = sum(times) / len(times)
            lines.append(f"  {stage:15s}: avg={avg:8.2f}ms  min={min(times):8.2f}ms  max={max(times):8.2f}ms  n={len(times)}")

        # Group by operation
        creates = [r for r in self.results if r.operation == "create"]
        updates = [r for r in self.results if r.operation == "update"]

        if creates:
            create_times = [r.duration_ms for r in creates]
            lines.append(f"\nCREATE ops: avg={sum(create_times)/len(create_times):.2f}ms  n={len(creates)}")

        if updates:
            update_times = [r.duration_ms for r in updates]
            lines.append(f"UPDATE ops: avg={sum(update_times)/len(update_times):.2f}ms  n={len(updates)}")

        # Bottlenecks (slowest operations)
        sorted_results = sorted(self.results, key=lambda r: r.duration_ms, reverse=True)
        lines.append("\n--- SLOWEST OPERATIONS ---")
        for r in sorted_results[:5]:
            lines.append(f"  {r.duration_ms:8.2f}ms | {r.stage:10s} | {r.operation:6s} | {r.snapshot_type:15s} | {Path(r.file_path).name}")

        lines.append("=" * 70)
        return "\n".join(lines)

    def to_json(self) -> str:
        """Export results to JSON."""
        return json.dumps([
            {
                "test_id": r.test_id,
                "snapshot_type": r.snapshot_type,
                "operation": r.operation,
                "existing_id": r.existing_id,
                "duration_ms": r.duration_ms,
                "rows_written": r.rows_written,
                "rows_updated": r.rows_updated,
                "conflicts": r.conflicts,
                "file_path": r.file_path,
                "file_size": r.file_size,
                "stage": r.stage,
            }
            for r in self.results
        ], indent=2)


# Test files from this codebase (real files)
TEST_FILES = [
    Path("app/parsers/tree_sitter_parser.py"),  # Large file
    Path("app/storage/snapshot_repo.py"),        # Medium file
    Path("app/storage/db.py"),                   # Small file
    Path("app/config/settings.py"),              # Config file
    Path("app/mcp/tools.py"),                    # MCP tools
]


@pytest.fixture
def collector():
    return TimingCollector()


@pytest.fixture
def repo():
    """Real snapshot repository."""
    return SnapshotRepository()


@pytest.fixture
def test_project_id():
    """Unique project ID for test isolation."""
    return f"benchmark_test_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"


class TestRealParserTiming:
    """Benchmark REAL tree-sitter parsing."""

    def test_parse_real_files(self, collector):
        """Time tree-sitter parsing on real codebase files."""
        base_path = Path(__file__).parent.parent.parent

        for rel_path in TEST_FILES:
            file_path = base_path / rel_path
            if not file_path.exists():
                continue

            file_size = file_path.stat().st_size

            # Time parsing
            start = time.perf_counter()
            try:
                result = parse_code_tree_sitter(path=file_path)
                duration_ms = (time.perf_counter() - start) * 1000

                collector.record(TimingResult(
                    test_id=f"parse_{file_path.name}",
                    snapshot_type="file_metadata",
                    operation="create",
                    existing_id=None,
                    duration_ms=duration_ms,
                    rows_written=0,
                    rows_updated=0,
                    conflicts=0,
                    file_path=str(rel_path),
                    file_size=file_size,
                    stage="parse",
                ))
            except Exception as e:
                print(f"Parse failed for {file_path}: {e}")

        print("\n" + collector.report())


class TestRealCRUDTiming:
    """Benchmark REAL database CRUD operations."""

    def test_snapshot_create(self, collector, repo, test_project_id):
        """Time REAL snapshot creation (INSERT)."""
        base_path = Path(__file__).parent.parent.parent

        for rel_path in TEST_FILES:
            file_path = base_path / rel_path
            if not file_path.exists():
                continue

            file_size = file_path.stat().st_size

            # Parse file
            try:
                parsed = parse_code_tree_sitter(path=file_path)
            except Exception:
                continue

            # Time DB insert for each snapshot type
            for snapshot_type in ["file_metadata", "imports", "functions", "classes"]:
                field_values = {k: v for k, v in parsed.items() if k.startswith(f"code.{snapshot_type.split('_')[0]}")}
                if not field_values:
                    field_values = {"code.file.path": str(rel_path)}

                start = time.perf_counter()
                record = repo.upsert(
                    project_id=test_project_id,
                    snapshot_type=snapshot_type,
                    source_file=str(rel_path),
                    field_values=field_values,
                )
                duration_ms = (time.perf_counter() - start) * 1000

                collector.record(TimingResult(
                    test_id=f"create_{file_path.name}_{snapshot_type}",
                    snapshot_type=snapshot_type,
                    operation="create",
                    existing_id=None,
                    duration_ms=duration_ms,
                    rows_written=1,
                    rows_updated=0,
                    conflicts=0,
                    file_path=str(rel_path),
                    file_size=file_size,
                    stage="db_write",
                ))

        print("\n" + collector.report())

        # Cleanup
        repo.delete_by_project(test_project_id)

    def test_snapshot_update(self, collector, repo, test_project_id):
        """Time REAL snapshot update (UPDATE on existing row)."""
        base_path = Path(__file__).parent.parent.parent

        for rel_path in TEST_FILES[:2]:  # Just 2 files for update test
            file_path = base_path / rel_path
            if not file_path.exists():
                continue

            file_size = file_path.stat().st_size

            try:
                parsed = parse_code_tree_sitter(path=file_path)
            except Exception:
                continue

            for snapshot_type in ["file_metadata", "functions"]:
                field_values = {"code.file.path": str(rel_path), "test": "initial"}

                # First: CREATE
                record = repo.upsert(
                    project_id=test_project_id,
                    snapshot_type=snapshot_type,
                    source_file=str(rel_path),
                    field_values=field_values,
                )
                existing_id = record.snapshot_id

                # Second: UPDATE (same key, different values)
                field_values["test"] = "updated"
                field_values["extra"] = "new_field"

                start = time.perf_counter()
                updated_record = repo.upsert(
                    project_id=test_project_id,
                    snapshot_type=snapshot_type,
                    source_file=str(rel_path),
                    field_values=field_values,
                )
                duration_ms = (time.perf_counter() - start) * 1000

                # Check if it was actually an update (same snapshot_id)
                was_update = updated_record.snapshot_id == existing_id

                collector.record(TimingResult(
                    test_id=f"update_{file_path.name}_{snapshot_type}",
                    snapshot_type=snapshot_type,
                    operation="update" if was_update else "create",
                    existing_id=existing_id,
                    duration_ms=duration_ms,
                    rows_written=0 if was_update else 1,
                    rows_updated=1 if was_update else 0,
                    conflicts=1 if was_update else 0,
                    file_path=str(rel_path),
                    file_size=file_size,
                    stage="db_write",
                ))

        print("\n" + collector.report())

        # Cleanup
        repo.delete_by_project(test_project_id)

    def test_snapshot_read(self, collector, repo, test_project_id):
        """Time REAL snapshot read operations."""
        base_path = Path(__file__).parent.parent.parent

        # Setup: create some snapshots
        created_ids = []
        for rel_path in TEST_FILES[:3]:
            file_path = base_path / rel_path
            if not file_path.exists():
                continue

            record = repo.upsert(
                project_id=test_project_id,
                snapshot_type="file_metadata",
                source_file=str(rel_path),
                field_values={"code.file.path": str(rel_path)},
            )
            created_ids.append(record.snapshot_id)

        # Time: get_by_snapshot_id
        for sid in created_ids:
            start = time.perf_counter()
            record = repo.get_by_snapshot_id(sid, test_project_id)
            duration_ms = (time.perf_counter() - start) * 1000

            collector.record(TimingResult(
                test_id=f"read_by_id_{sid[:8]}",
                snapshot_type=record.snapshot_type if record else "unknown",
                operation="read",
                existing_id=sid,
                duration_ms=duration_ms,
                rows_written=0,
                rows_updated=0,
                conflicts=0,
                file_path=record.source_file if record else "",
                file_size=0,
                stage="db_read",
            ))

        # Time: get_by_project
        start = time.perf_counter()
        records = repo.get_by_project(test_project_id)
        duration_ms = (time.perf_counter() - start) * 1000

        collector.record(TimingResult(
            test_id="read_by_project",
            snapshot_type="all",
            operation="read",
            existing_id=None,
            duration_ms=duration_ms,
            rows_written=0,
            rows_updated=0,
            conflicts=0,
            file_path=f"{len(records)} records",
            file_size=0,
            stage="db_read",
        ))

        # Time: get_by_type
        start = time.perf_counter()
        records = repo.get_by_type(test_project_id, "file_metadata")
        duration_ms = (time.perf_counter() - start) * 1000

        collector.record(TimingResult(
            test_id="read_by_type",
            snapshot_type="file_metadata",
            operation="read",
            existing_id=None,
            duration_ms=duration_ms,
            rows_written=0,
            rows_updated=0,
            conflicts=0,
            file_path=f"{len(records)} records",
            file_size=0,
            stage="db_read",
        ))

        print("\n" + collector.report())

        # Cleanup
        repo.delete_by_project(test_project_id)


class TestFullPipelineTiming:
    """Benchmark REAL end-to-end pipeline."""

    def test_file_to_snapshot_pipeline(self, collector, repo, test_project_id):
        """Time complete file -> parse -> map -> db pipeline."""
        base_path = Path(__file__).parent.parent.parent

        for rel_path in TEST_FILES[:3]:
            file_path = base_path / rel_path
            if not file_path.exists():
                continue

            file_size = file_path.stat().st_size
            total_start = time.perf_counter()

            # Stage 1: Route
            start = time.perf_counter()
            route = route_file(file_path)
            route_ms = (time.perf_counter() - start) * 1000

            collector.record(TimingResult(
                test_id=f"pipeline_{file_path.name}_route",
                snapshot_type="routing",
                operation="create",
                existing_id=None,
                duration_ms=route_ms,
                rows_written=0,
                rows_updated=0,
                conflicts=0,
                file_path=str(rel_path),
                file_size=file_size,
                stage="route",
            ))

            if not route:
                continue

            # Stage 2: Parse
            start = time.perf_counter()
            try:
                parsed = parse_code_tree_sitter(path=file_path)
                parse_ms = (time.perf_counter() - start) * 1000

                collector.record(TimingResult(
                    test_id=f"pipeline_{file_path.name}_parse",
                    snapshot_type="parsing",
                    operation="create",
                    existing_id=None,
                    duration_ms=parse_ms,
                    rows_written=0,
                    rows_updated=0,
                    conflicts=0,
                    file_path=str(rel_path),
                    file_size=file_size,
                    stage="parse",
                ))
            except Exception as e:
                print(f"Parse failed: {e}")
                continue

            # Stage 3: DB Write (multiple snapshot types)
            for snapshot_type in ["file_metadata", "imports", "functions"]:
                field_values = {k: v for k, v in parsed.items()}

                start = time.perf_counter()
                record = repo.upsert(
                    project_id=test_project_id,
                    snapshot_type=snapshot_type,
                    source_file=str(rel_path),
                    field_values=field_values,
                )
                db_ms = (time.perf_counter() - start) * 1000

                collector.record(TimingResult(
                    test_id=f"pipeline_{file_path.name}_db_{snapshot_type}",
                    snapshot_type=snapshot_type,
                    operation="create",
                    existing_id=None,
                    duration_ms=db_ms,
                    rows_written=1,
                    rows_updated=0,
                    conflicts=0,
                    file_path=str(rel_path),
                    file_size=file_size,
                    stage="db_write",
                ))

            total_ms = (time.perf_counter() - total_start) * 1000
            print(f"Pipeline for {file_path.name}: {total_ms:.2f}ms total")

        print("\n" + collector.report())

        # Save results
        results_path = base_path / "data" / "benchmarks"
        results_path.mkdir(parents=True, exist_ok=True)
        with open(results_path / "timing_results.json", "w") as f:
            f.write(collector.to_json())
        print(f"\nResults saved to: {results_path / 'timing_results.json'}")

        # Cleanup
        repo.delete_by_project(test_project_id)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
