#!/usr/bin/env bash
# Backup the memprobe PostgreSQL database.
# Saves a compressed dump to ./backups/ and keeps the last 30.
#
# Usage:
#   ./backup.sh              # manual run
#   ./backup.sh --restore backups/memprobe_2025-01-15_14-30-00.sql.gz

set -euo pipefail

BACKUP_DIR="$(cd "$(dirname "$0")" && pwd)/backups"
DB_NAME="memprobe"
DB_USER="memprobe"
KEEP=30   # number of backups to retain

mkdir -p "$BACKUP_DIR"

# ── Restore mode ──────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--restore" ]]; then
    FILE="${2:-}"
    if [[ -z "$FILE" || ! -f "$FILE" ]]; then
        echo "Usage: $0 --restore <backup-file.sql.gz>"
        exit 1
    fi
    echo "[backup] Restoring from $FILE ..."
    gunzip -c "$FILE" | psql -U "$DB_USER" -d "$DB_NAME"
    echo "[backup] Restore complete."
    exit 0
fi

# ── Backup mode ───────────────────────────────────────────────────────────────
TIMESTAMP="$(date +%Y-%m-%d_%H-%M-%S)"
OUT="$BACKUP_DIR/memprobe_${TIMESTAMP}.sql.gz"

echo "[backup] Dumping $DB_NAME → $OUT"
pg_dump -U "$DB_USER" -d "$DB_NAME" --no-password | gzip > "$OUT"

SIZE=$(du -sh "$OUT" | cut -f1)
echo "[backup] Done. Size: $SIZE"

# ── Rotate old backups (keep newest $KEEP) ────────────────────────────────────
TOTAL=$(ls -1 "$BACKUP_DIR"/memprobe_*.sql.gz 2>/dev/null | wc -l | tr -d ' ')
if (( TOTAL > KEEP )); then
    DELETE=$(( TOTAL - KEEP ))
    echo "[backup] Rotating: removing $DELETE old backup(s)..."
    ls -1t "$BACKUP_DIR"/memprobe_*.sql.gz | tail -n "$DELETE" | xargs rm -f
fi

echo "[backup] Backups kept: $(ls -1 "$BACKUP_DIR"/memprobe_*.sql.gz | wc -l | tr -d ' ')/$KEEP"
