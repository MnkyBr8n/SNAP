# SNAP/docker/Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files and install dependencies via pyproject.toml
COPY pyproject.toml .
COPY app/ ./app/
RUN pip install --no-cache-dir .

# Always upgrade parsers and grammar packages to latest at build time
RUN pip install --upgrade semgrep tree-sitter \
    tree-sitter-swift tree-sitter-kotlin tree-sitter-scala

# Create data directories
RUN mkdir -p data/uploads data/repos data/projects data/staging

# Set Python path
ENV PYTHONPATH=/app

# Default environment variables (credentials must be provided via env/secrets)
ENV SNAP_ENVIRONMENT=production
ENV SNAP_LOG_LEVEL=INFO
ENV SNAP_LOG_JSON=true
# SNAP_POSTGRES_DSN must be set at runtime via environment variable

# Expose port (if adding API later)
EXPOSE 8080

# Run as non-root user
RUN useradd -m -u 1000 snap && chown -R snap:snap /app
USER snap

# Default command (can be overridden)
CMD ["python", "-m", "app.mcp.run", "--sse", "--host", "0.0.0.0", "--port", "8080"]
