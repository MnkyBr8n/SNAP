# SNAP/app/config/settings.py
"""
Purpose: Centralized, validated configuration for the SNAP service (limits, paths, DB, network allowlist).
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SnapLimits(BaseModel):
    # Ingest limits
    max_repo_bytes: int = Field(default=2 * 1024 * 1024 * 1024, ge=1)  # 2 GB (increased for large repos)
    max_repo_files: int = Field(default=100_000, ge=1)  # Increased for large repos
    max_repo_depth: int = Field(default=12, ge=1)

    # File limits
    max_pdf_bytes: int = Field(default=50 * 1024 * 1024, ge=1)  # 50 MB
    max_text_bytes: int = Field(default=10 * 1024 * 1024, ge=1)  # 10 MB
    max_code_file_bytes: int = Field(default=5 * 1024 * 1024, ge=1)  # 5 MB (increased for large files)

    # PDF limits
    max_pdf_pages_per_file: int = Field(default=300, ge=1)
    max_pdf_pages_per_job: int = Field(default=1000, ge=1)

    # Runtime limits
    max_job_seconds: int = Field(default=15 * 60, ge=1)  # 15 minutes
    max_project_run_seconds: int = Field(default=60 * 60, ge=1)  # 60 minutes
    idle_timeout_seconds: int = Field(default=24 * 60 * 60, ge=1)  # 24 hours

    # Snapshot notebook limits
    snapshot_notebook_cap_bytes: int = Field(default=500 * 1024 * 1024, ge=1)  # 500 MB (increased for multiple snapshots per file)


class ParserLimits(BaseModel):
    """Limits and thresholds for file parsers."""

    # Code file size thresholds (LOC)
    soft_cap_loc: int = Field(default=1500, ge=1)  # Warn, refactor recommended
    large_file_loc: int = Field(default=3999, ge=1)  # Large file warning
    potential_god_loc: int = Field(default=4000, ge=1)  # Potential god file (for future)
    hard_cap_loc: int = Field(default=5000, ge=1)  # Reject files >= 5000 LOC

    # Text file size thresholds (bytes)
    soft_cap_bytes: int = Field(default=500_000, ge=1)  # 500KB - warn, large text file
    potential_god_bytes: int = Field(default=5_000_000, ge=1)  # 5MB - potential god doc
    hard_cap_bytes: int = Field(default=10_000_000, ge=1)  # 10MB - reject text files >= 10MB
    
    # Tree-sitter timeouts (milliseconds)
    tree_sitter_timeout_interactive: int = Field(default=500, ge=1)
    tree_sitter_timeout_initial: int = Field(default=2000, ge=1)
    
    # Semgrep settings
    semgrep_timeout_per_file: int = Field(default=60, ge=1)    # seconds, single-file mode
    semgrep_batch_timeout_seconds: int = Field(default=3600, ge=60)  # seconds, batch mode (1 hr default — scales for monorepos)
    semgrep_code_context_lines: int = Field(default=3, ge=0)
    
    # CSV limits
    csv_hard_cap_file_size_mb: int = Field(default=50, ge=1)
    csv_hard_cap_rows: int = Field(default=500_000, ge=1)
    csv_hard_cap_cell_chars: int = Field(default=5_000, ge=1)
    csv_soft_cap_file_size_mb: int = Field(default=5, ge=1)
    csv_soft_cap_rows: int = Field(default=50_000, ge=1)


class AuthConfig(BaseModel):
    """JWT and GitHub OAuth configuration."""
    enabled: bool = False
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expiry_hours: int = 24
    github_client_id: str = ""
    github_client_secret: str = ""
    github_allowed_orgs: List[str] = Field(default_factory=list)


class NetworkPolicy(BaseModel):
    outbound_enabled: bool = True
    domain_allowlist: List[str] = Field(default_factory=lambda: ["github.com", "raw.githubusercontent.com"])

    @field_validator("domain_allowlist")
    @classmethod
    def _dedupe_and_strip(cls, v: List[str]) -> List[str]:
        cleaned: List[str] = []
        for item in v:
            item = (item or "").strip().lower()
            if item and item not in cleaned:
                cleaned.append(item)
        return cleaned


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SNAP_", case_sensitive=False, env_file=".env", extra="ignore")

    # Environment
    environment: str = Field(default="dev")
    service_name: str = Field(default="snap")
    version: str = Field(default="0.1.0")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080, ge=1, le=65535)

    # CORS settings (set via SNAP_CORS_ALLOWED_ORIGINS env var)
    cors_allowed_origins: List[str] = Field(default_factory=list)

    # Storage paths (inside container)
    data_dir: Path = Field(default=Path("data"))
    repos_dir: Path = Field(default=Path("data/repos"))  # GitHub cloned repos (repos_watcher ingests, then clears)
    schemas_dir: Path = Field(default=Path("app/schemas"))

    # Schema reference
    notebook_schema_path: Path = Field(default=Path("app/schemas/master_notebook.yaml"))

    # Database (no default - must be set via SNAP_POSTGRES_DSN env var)
    postgres_dsn: str = Field(
        description="SQLAlchemy-compatible DSN (required, set via SNAP_POSTGRES_DSN)",
    )

    # GitHub ingest (HTTPS clone)
    git_clone_timeout_seconds: int = Field(default=900, ge=1)  # 15 minutes per attempt
    git_clone_depth: int = Field(default=1, ge=1)  # Shallow clone depth
    git_max_concurrent_clones: int = Field(default=2, ge=1)
    
    # HTTP request timeout
    http_request_timeout_seconds: int = Field(default=300, ge=1)  # 5 minutes for outbound HTTP requests

    # Policies
    limits: SnapLimits = Field(default_factory=SnapLimits)
    parser_limits: ParserLimits = Field(default_factory=ParserLimits)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    auth: AuthConfig = Field(default_factory=AuthConfig)

    # Logging config
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=True)


    @field_validator("environment")
    @classmethod
    def _env_normalize(cls, v: str) -> str:
        v = (v or "").strip().lower()
        return v or "dev"

    @model_validator(mode='after')
    def _resolve_paths(self) -> 'Settings':
        """Resolve all Path fields to absolute paths relative to cwd."""
        self.data_dir = self.data_dir.resolve()
        self.repos_dir = self.repos_dir.resolve()
        self.schemas_dir = self.schemas_dir.resolve()
        self.notebook_schema_path = self.notebook_schema_path.resolve()
        return self

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.schemas_dir.mkdir(parents=True, exist_ok=True)


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        s = Settings()
        s.ensure_dirs()
        _settings = s
    return _settings
