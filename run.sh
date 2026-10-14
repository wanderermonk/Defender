#!/bin/bash
# Defender launcher — zero dependencies, standard library only.
set -e
cd "$(dirname "$0")"

# Optional: enable the LOCAL Ollama advisor (nothing leaves the machine)
#   export DEFENDER_OLLAMA=1
#   export DEFENDER_OLLAMA_MODEL=llama3.1

echo "[defender] launching on http://localhost:${PORT:-5050}"
python3 app.py
