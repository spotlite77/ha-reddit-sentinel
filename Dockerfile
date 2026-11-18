FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel.py .

# Mount a folder containing config.yaml at /data:
# the SQLite database (sentinel.db) is created next to it.
CMD ["python", "sentinel.py", "--config", "/data/config.yaml"]
