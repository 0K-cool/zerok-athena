#!/bin/bash
# Start 0K ATHENA Dashboard Server
# Usage: ./start.sh [--reload]

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$DIR/.venv"

if [ ! -d "$VENV" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -r "$DIR/requirements.txt"
fi

ARGS="server:app --host 0.0.0.0 --port 8080"
if [ "$1" = "--reload" ]; then
    ARGS="$ARGS --reload"
fi

echo ""
echo "  0K ATHENA Dashboard"
echo "  ───────────────────"
echo "  http://localhost:8080"
echo ""

cd "$DIR" && exec "$VENV/bin/uvicorn" $ARGS
