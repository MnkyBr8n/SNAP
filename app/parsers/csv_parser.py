"""
CSV parser that preserves table structure (headers + rows) for exact reassembly.

Output format:
- csv.table_data: {headers: List[str], rows: List[List[str]], row_count: int, column_count: int}
- csv.file.path: str
- csv.file.rows: int
"""

from pathlib import Path
from typing import Dict, Any, List
import csv
import time

from app.logging.logger import get_logger

logger = get_logger("parsers.csv")

# CSV limits
CSV_HARD_CAP_FILE_SIZE_MB = 50
CSV_HARD_CAP_ROWS = 500_000
CSV_HARD_CAP_CELL_CHARS = 5_000

CSV_SOFT_CAP_FILE_SIZE_MB = 5
CSV_SOFT_CAP_ROWS = 50_000


def parse_csv_file(path: Path) -> Dict[str, Any]:
    """
    Parse CSV file preserving table structure.
    
    Args:
        path: Path to CSV file
    
    Returns:
        Dict with field_id keys matching master_notebook.yaml
        
    Raises:
        Exception if parsing fails or limits exceeded
    """
    start_time = time.time()
    
    # Check file size
    file_size_mb = path.stat().st_size / (1024 * 1024)
    
    if file_size_mb > CSV_HARD_CAP_FILE_SIZE_MB:
        raise ValueError(f"CSV file exceeds hard cap: {file_size_mb:.2f} MB > {CSV_HARD_CAP_FILE_SIZE_MB} MB")
    
    if file_size_mb > CSV_SOFT_CAP_FILE_SIZE_MB:
        logger.warning("CSV file exceeds soft cap", extra={
            "file": str(path),
            "size_mb": file_size_mb,
            "soft_cap_mb": CSV_SOFT_CAP_FILE_SIZE_MB
        })
    
    # Parse CSV
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            
            # Read headers (first row)
            try:
                headers = next(reader)
            except StopIteration:
                # Empty CSV
                headers = []
            
            # Read data rows
            rows = []
            for row in reader:
                # Check row limit
                if len(rows) >= CSV_HARD_CAP_ROWS:
                    raise ValueError(f"CSV exceeds row hard cap: {CSV_HARD_CAP_ROWS} rows")
                
                # Truncate cells exceeding character limit
                truncated_row = []
                for cell in row:
                    if len(cell) > CSV_HARD_CAP_CELL_CHARS:
                        logger.warning("CSV cell truncated", extra={
                            "file": str(path),
                            "row": len(rows) + 1,
                            "original_length": len(cell),
                            "truncated_to": CSV_HARD_CAP_CELL_CHARS
                        })
                        truncated_row.append(cell[:CSV_HARD_CAP_CELL_CHARS])
                    else:
                        truncated_row.append(cell)
                
                rows.append(truncated_row)
            
            # Check soft row limit
            if len(rows) > CSV_SOFT_CAP_ROWS:
                logger.warning("CSV exceeds soft row cap", extra={
                    "file": str(path),
                    "rows": len(rows),
                    "soft_cap_rows": CSV_SOFT_CAP_ROWS
                })
            
            # Build result
            row_count = len(rows)
            column_count = len(headers) if headers else 0
            
            result = {
                "csv.table_data": {
                    "headers": headers,
                    "rows": rows,
                    "row_count": row_count,
                    "column_count": column_count
                },
                "csv.file.path": str(path),
                "csv.file.rows": row_count
            }
            
            duration_ms = (time.time() - start_time) * 1000
            
            logger.info("CSV parse complete", extra={
                "file": str(path),
                "rows": row_count,
                "columns": column_count,
                "parse_duration_ms": duration_ms,
                "size_mb": file_size_mb
            })
            
            return result
            
    except UnicodeDecodeError as e:
        logger.error("CSV encoding error", extra={
            "file": str(path),
            "error": str(e)
        })
        raise
    except csv.Error as e:
        logger.error("CSV parse error", extra={
            "file": str(path),
            "error": str(e)
        })
        raise
    except Exception as e:
        logger.error("CSV parser failure", extra={
            "file": str(path),
            "error": str(e)
        })
        raise


def reassemble_csv(table_data: Dict[str, Any]) -> str:
    """
    Reassemble CSV file from table_data structure.
    
    Args:
        table_data: Dict with headers and rows
    
    Returns:
        CSV file content as string
    """
    import io
    
    headers = table_data.get("headers", [])
    rows = table_data.get("rows", [])
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    if headers:
        writer.writerow(headers)
    
    # Write rows
    for row in rows:
        writer.writerow(row)
    
    return output.getvalue()
