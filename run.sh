#!/usr/bin/env bash
# Start Cloud Data Cleaner using the project's virtual environment.
# Usage: ./run.sh            (extra env vars work too, e.g. DEBUG=True ./run.sh)
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "No virtual environment found in .venv. Set it up first:" >&2
    echo "  python3 -m venv .venv" >&2
    echo "  .venv/bin/pip install -r requirements.txt" >&2
    echo "  .venv/bin/python -m spacy download en_core_web_sm" >&2
    exit 1
fi

source .venv/bin/activate
exec python main.py "$@"
