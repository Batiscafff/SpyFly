FROM python:3.12-slim

# nmap  — required for active/full scan mode
# curl  — used by the Docker healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies (layer cached until requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application code
COPY . .

# Pre-create the scans directory (overridden by the named volume at runtime)
RUN mkdir -p scans

EXPOSE 5000

# Single worker + 4 threads: keeps all background scan threads in one process,
# which is required because status/results are shared via the filesystem and
# daemon threads are per-process.
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:5000", "run:app"]
