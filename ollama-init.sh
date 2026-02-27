#!/bin/sh
set -eux

echo "Waiting for Ollama API at ${OLLAMA_HOST:-http://ollama:11434}..."
until ollama list >/dev/null 2>&1; do
  sleep 2
done

echo "Pulling models..."
ollama pull nomic-embed-text
ollama pull deepseek-r1:8b

echo "Done."