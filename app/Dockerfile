# snap/app/Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create data directories
RUN mkdir -p data/uploads data/repos data/projects schemas

# Copy schema files
COPY schemas/ ./schemas/

# Set Python path
ENV PYTHONPATH=/app

# Default environment variables
ENV SNAP_ENVIRONMENT=production
ENV SNAP_LOG_LEVEL=INFO
ENV SNAP_LOG_JSON=true
ENV SNAP_POSTGRES_DSN=postgresql+psycopg://snap:snap@postgres:5432/snap

# Expose port (if adding API later)
EXPOSE 8080

# Run as non-root user
RUN useradd -m -u 1000 snap && chown -R snap:snap /app
USER snap

# Default command (can be overridden)
CMD ["python", "-c", "from app.main import startup; startup(); print('Snap tool ready')"]
