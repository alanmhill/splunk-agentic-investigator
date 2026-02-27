# agent/Dockerfile

FROM python:3.11-slim

WORKDIR /app

# system deps (useful later for pgvector, http libs, etc)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# install python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy code
COPY . .

# start API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]