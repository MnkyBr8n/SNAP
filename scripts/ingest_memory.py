"""Re-ingest CLAUDE-MEMORY: MEMORY.md + recent/small compacted JSONL files."""
import sys
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

PROJECTS_DIR = Path(r"C:\Users\yxyel\.claude\projects\c--Users-yxyel-PANS")
MEMORY_DIR = PROJECTS_DIR / "memory"
MAX_JSONL_BYTES = 5 * 1024 * 1024  # 5 MB cap — excludes monster files like 26MB 0c0c25f4.jsonl
MAX_AGE_DAYS = 14

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.main import startup, process_project

cutoff_ts = datetime.now().timestamp() - MAX_AGE_DAYS * 86400

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)

    # Always include MEMORY.md
    mem_src = MEMORY_DIR / "MEMORY.md"
    if mem_src.exists():
        shutil.copy2(mem_src, tmp_path / "MEMORY.md")

    # Include JSONL files that are recent AND under size cap
    for jf in PROJECTS_DIR.glob("*.jsonl"):
        st = jf.stat()
        if st.st_size <= MAX_JSONL_BYTES and st.st_mtime >= cutoff_ts:
            shutil.copy2(jf, tmp_path / jf.name)

    startup()
    process_project(
        project_id="CLAUDE-MEMORY",
        vendor_id="claude",
        local_path=tmp_path,
    )
