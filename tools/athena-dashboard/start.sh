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

ARGS="server:app --host 127.0.0.1 --port 8080"
if [ "$1" = "--reload" ]; then
    ARGS="$ARGS --reload"
fi

echo ""
echo "  0K ATHENA Dashboard"
echo "  ───────────────────"
echo "  http://localhost:8080"

# Inject Neo4j credentials from 1Password
if command -v op &>/dev/null; then
    export NEO4J_PASS=$(op read "op://Private/laespix2zshux5xuon73x7wt2y/password" 2>/dev/null)
    if [ -n "$NEO4J_PASS" ]; then
        echo "  Neo4j:      1Password ✓"
    else
        echo "  Neo4j:      1Password failed — sign in with 'op signin'"
    fi
else
    echo "  Neo4j:      op CLI not found — Neo4j auth will fail"
fi

echo ""

cd "$DIR" && exec "$VENV/bin/uvicorn" $ARGS
