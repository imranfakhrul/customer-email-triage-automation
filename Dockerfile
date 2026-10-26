# Use an official lightweight Python runtime
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Set working directory inside container
WORKDIR /app

# Install minimal system dependencies and create non-root appuser
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash appuser

# Copy dependency specifications first for Docker layer caching
COPY requirements.txt .

# Install Python packages and download the pinned spaCy lightweight local NER model
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

# Copy project source files
COPY . .

# Create volume mount directory for SQLite persistence and set permissions
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Switch to non-root appuser
USER appuser

# Default command
CMD ["python", "main.py"]
