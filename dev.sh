#!/usr/bin/env bash
# Start PostgreSQL (if not running) and the Django dev server.
# Ctrl-C kills the server; PostgreSQL is stopped on exit.

set -euo pipefail

WEBSITE_DIR="$(cd "$(dirname "$0")/website" && pwd)"

# ── Start PostgreSQL ──────────────────────────────────────────────────────────
PG_RUNNING=false
if brew services list | grep -q 'postgresql@14.*started'; then
    PG_RUNNING=true
    echo "[dev] PostgreSQL already running — will leave it running on exit."
else
    echo "[dev] Starting PostgreSQL..."
    brew services start postgresql@14
    PG_RUNNING=false  # we started it, so we stop it on exit
fi

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "[dev] Stopping Django server..."
    # Django is a foreground process — the trap fires after it exits
    if [ "$PG_RUNNING" = false ]; then
        echo "[dev] Stopping PostgreSQL..."
        brew services stop postgresql@14
    fi
}
trap cleanup EXIT

# ── Run Django ────────────────────────────────────────────────────────────────
echo "[dev] Starting Django at http://127.0.0.1:8000"
cd "$WEBSITE_DIR"
python3 manage.py runserver 127.0.0.1:8000
