"""Build history — PostgreSQL.

Security invariant: every function that reads or writes user-owned build data
requires a ``user_id`` argument and filters ALL queries by it.  A user can
never read or mutate another user's builds, even if they know the build ID.

Share records are keyed by an opaque random ID and are intentionally public
(that is the point of sharing).  They carry no user_id.

Requires DATABASE_URL environment variable:
    DATABASE_URL=postgres://user:pass@host:5432/dbname
"""

import json
import os
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import MemoryMap


# ── Connection pool (lazy, thread-safe) ──────────────────────────────────────

_DATABASE_URL: Optional[str] = os.environ.get('DATABASE_URL')
_pg_pool = None
_pg_pool_lock = threading.Lock()


def _get_pool():
    global _pg_pool
    if _pg_pool is None:
        with _pg_pool_lock:
            if _pg_pool is None:  # re-check inside lock
                if not _DATABASE_URL:
                    raise RuntimeError(
                        'DATABASE_URL environment variable is not set. '
                        'Set it to a PostgreSQL connection string.'
                    )
                import psycopg2.pool
                import psycopg2.extras
                _pg_pool = psycopg2.pool.ThreadedConnectionPool(
                    minconn=2,
                    maxconn=20,
                    dsn=_DATABASE_URL,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                )
    return _pg_pool


@contextmanager
def _db():
    """Yield a connection, auto-commit on success, rollback on error."""
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


# ── Query helpers ─────────────────────────────────────────────────────────────

def _exec(conn, sql: str, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur


def _fetchone(conn, sql: str, params=()) -> Optional[dict]:
    cur = _exec(conn, sql, params)
    row = cur.fetchone()
    return dict(row) if row else None


def _fetchall(conn, sql: str, params=()) -> list:
    cur = _exec(conn, sql, params)
    return [dict(r) for r in cur.fetchall()]


def _detect_git(file_path: str) -> tuple:
    cwd = str(Path(file_path).parent)
    try:
        git_hash = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=cwd,
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        git_branch = subprocess.check_output(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            cwd=cwd, stderr=subprocess.DEVNULL, text=True,
        ).strip()
        return git_hash, git_branch
    except Exception:
        return None, None


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS builds (
    id            SERIAL PRIMARY KEY,
    user_id       TEXT         NOT NULL,
    source_file   TEXT         NOT NULL,
    timestamp     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    git_hash      TEXT,
    git_branch    TEXT,
    total_flash   BIGINT       NOT NULL,
    total_ram     BIGINT       NOT NULL,
    toolchain     TEXT         NOT NULL,
    project       VARCHAR(200),
    metadata      JSONB        NOT NULL DEFAULT '{}',
    analysis_json TEXT
);

CREATE INDEX IF NOT EXISTS builds_user_id_idx      ON builds (user_id);
CREATE INDEX IF NOT EXISTS builds_user_project_idx ON builds (user_id, project)
    WHERE project IS NOT NULL;

CREATE TABLE IF NOT EXISTS shares (
    id            TEXT PRIMARY KEY,
    user_id       TEXT,
    filename      TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    analysis_json TEXT        NOT NULL
);

CREATE TABLE IF NOT EXISTS project_settings (
    user_id            TEXT         NOT NULL,
    project            VARCHAR(200) NOT NULL,
    flash_budget_bytes BIGINT,
    ram_budget_bytes   BIGINT,
    description        TEXT,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, project)
);
"""


def init_db() -> None:
    """Create tables and indexes if they don't exist. Safe to call on every startup."""
    with _db() as conn:
        _exec(conn, _SCHEMA)


# ── Per-user build functions ──────────────────────────────────────────────────

def save(
    mmap: MemoryMap,
    user_id: str,
    analysis_json: Optional[dict] = None,
    project: Optional[str] = None,
) -> int:
    """Persist a MemoryMap to the history database. Returns the new build id."""
    git_hash, git_branch = _detect_git(mmap.source_file)
    ts = mmap.timestamp or datetime.now(timezone.utc)
    with _db() as conn:
        cur = _exec(conn,
            """INSERT INTO builds
               (user_id, source_file, timestamp, git_hash, git_branch,
                total_flash, total_ram, toolchain, project, metadata, analysis_json)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (
                user_id,
                mmap.source_file,
                ts,
                git_hash,
                git_branch,
                mmap.total_flash,
                mmap.total_ram,
                mmap.toolchain,
                project.strip() if project and project.strip() else None,
                json.dumps({}),
                json.dumps(analysis_json) if analysis_json else None,
            ),
        )
        return cur.fetchone()['id']


def get_build(build_id: int, user_id: str) -> Optional[dict]:
    """Return a build by ID only if it belongs to user_id."""
    with _db() as conn:
        row = _fetchone(conn,
            "SELECT * FROM builds WHERE id = %s AND user_id = %s",
            (build_id, user_id),
        )
    if row is None:
        return None
    if row.get('analysis_json'):
        row['analysis'] = json.loads(row['analysis_json'])
    return row


def list_builds(user_id: str) -> list:
    """Return all builds for user_id, newest first."""
    with _db() as conn:
        return _fetchall(conn,
            "SELECT * FROM builds WHERE user_id = %s ORDER BY timestamp DESC",
            (user_id,),
        )


def delete_build(build_id: int, user_id: str) -> bool:
    """Delete a build. Returns True if a row was deleted."""
    with _db() as conn:
        cur = _exec(conn,
            "DELETE FROM builds WHERE id = %s AND user_id = %s",
            (build_id, user_id),
        )
        return cur.rowcount > 0


def clear(user_id: str) -> None:
    """Delete all builds belonging to user_id."""
    with _db() as conn:
        _exec(conn, "DELETE FROM builds WHERE user_id = %s", (user_id,))


def list_projects(user_id: str) -> list:
    """Return all distinct project names for user_id, alphabetically."""
    with _db() as conn:
        rows = _fetchall(conn,
            """SELECT DISTINCT project FROM builds
               WHERE user_id = %s AND project IS NOT NULL
               ORDER BY project""",
            (user_id,),
        )
    return [r['project'] for r in rows]


def list_project_summaries(user_id: str) -> list:
    """Return one summary row per project, most-recently-active first."""
    with _db() as conn:
        projects = _fetchall(conn,
            """SELECT
                   b.project,
                   COUNT(*)         AS build_count,
                   MAX(b.timestamp) AS last_build,
                   MAX(b.id)        AS latest_id
               FROM builds b
               WHERE b.user_id = %s AND b.project IS NOT NULL
               GROUP BY b.project
               ORDER BY MAX(b.timestamp) DESC""",
            (user_id,),
        )

        result = []
        for p in projects:
            latest = _fetchone(conn,
                "SELECT total_flash, total_ram, source_file FROM builds WHERE id = %s",
                (p['latest_id'],),
            ) or {}
            prev = _fetchone(conn,
                """SELECT total_flash, total_ram FROM builds
                   WHERE project = %s AND user_id = %s AND id < %s
                   ORDER BY id DESC LIMIT 1""",
                (p['project'], user_id, p['latest_id']),
            )
            lb = p['last_build']
            result.append({
                'project':     p['project'],
                'build_count': p['build_count'],
                'last_build':  lb.isoformat() if hasattr(lb, 'isoformat') else lb,
                'total_flash': latest.get('total_flash') or 0,
                'total_ram':   latest.get('total_ram') or 0,
                'source_file': latest.get('source_file') or '',
                'flash_delta': (latest.get('total_flash', 0) - prev['total_flash']) if prev else None,
                'ram_delta':   (latest.get('total_ram', 0)   - prev['total_ram'])   if prev else None,
            })
        return result


def get_trend(
    user_id: str,
    source_file: Optional[str] = None,
    project: Optional[str] = None,
    limit: int = 200,
) -> list:
    """Return time-series data for user_id ordered ascending."""
    with _db() as conn:
        if project:
            rows = _fetchall(conn,
                """SELECT id, source_file, timestamp, git_hash, git_branch,
                          total_flash, total_ram, project
                   FROM builds WHERE user_id = %s AND project = %s
                   ORDER BY timestamp ASC LIMIT %s""",
                (user_id, project, limit),
            )
        elif source_file:
            rows = _fetchall(conn,
                """SELECT id, source_file, timestamp, git_hash, git_branch,
                          total_flash, total_ram, project
                   FROM builds WHERE user_id = %s AND source_file LIKE %s
                                     AND project IS NOT NULL
                   ORDER BY timestamp ASC LIMIT %s""",
                (user_id, f'%{Path(source_file).name}%', limit),
            )
        else:
            rows = _fetchall(conn,
                """SELECT id, source_file, timestamp, git_hash, git_branch,
                          total_flash, total_ram, project
                   FROM builds WHERE user_id = %s AND project IS NOT NULL
                   ORDER BY timestamp ASC LIMIT %s""",
                (user_id, limit),
            )
    return [{
        **r,
        'basename':  Path(r['source_file']).name,
        'timestamp': r['timestamp'].isoformat() if hasattr(r.get('timestamp'), 'isoformat') else r.get('timestamp'),
    } for r in rows]


# ── Project settings ──────────────────────────────────────────────────────────

def get_project_settings(user_id: str, project: str) -> Optional[dict]:
    with _db() as conn:
        return _fetchone(conn,
            """SELECT project, flash_budget_bytes, ram_budget_bytes,
                      description, created_at, updated_at
               FROM project_settings WHERE user_id = %s AND project = %s""",
            (user_id, project),
        )


def save_project_settings(
    user_id: str,
    project: str,
    flash_budget_bytes: Optional[int] = None,
    ram_budget_bytes: Optional[int] = None,
    description: Optional[str] = None,
) -> dict:
    """Upsert settings for a project."""
    if not user_id or user_id == '__anonymous__':
        raise ValueError('user_id required.')
    if not project:
        raise ValueError('project name required.')
    now = datetime.now(timezone.utc)
    with _db() as conn:
        _exec(conn,
            """INSERT INTO project_settings
               (user_id, project, flash_budget_bytes, ram_budget_bytes,
                description, created_at, updated_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (user_id, project) DO UPDATE SET
                   flash_budget_bytes = EXCLUDED.flash_budget_bytes,
                   ram_budget_bytes   = EXCLUDED.ram_budget_bytes,
                   description        = EXCLUDED.description,
                   updated_at         = EXCLUDED.updated_at""",
            (user_id, project, flash_budget_bytes, ram_budget_bytes,
             description, now, now),
        )
    return get_project_settings(user_id, project) or {}


def delete_project(user_id: str, project: str) -> dict:
    """Delete a project's builds and settings."""
    if not user_id or user_id == '__anonymous__':
        raise ValueError('user_id required.')
    if not project:
        raise ValueError('project name required.')
    with _db() as conn:
        cur = _exec(conn,
            'DELETE FROM builds WHERE user_id = %s AND project = %s',
            (user_id, project),
        )
        builds = cur.rowcount
        cur = _exec(conn,
            'DELETE FROM project_settings WHERE user_id = %s AND project = %s',
            (user_id, project),
        )
        settings = cur.rowcount
    return {'builds_deleted': builds, 'settings_deleted': settings}


def list_projects_full(user_id: str) -> list:
    """Return rich per-project data: stats + saved settings."""
    with _db() as conn:
        proj_rows = _fetchall(conn,
            """SELECT project, COUNT(*) AS build_count,
                      MIN(timestamp) AS first_build, MAX(timestamp) AS last_build
               FROM builds
               WHERE user_id = %s AND project IS NOT NULL
               GROUP BY project
               ORDER BY MAX(timestamp) DESC""",
            (user_id,),
        )
        settings_rows = _fetchall(conn,
            """SELECT project, flash_budget_bytes, ram_budget_bytes,
                      description, created_at, updated_at
               FROM project_settings WHERE user_id = %s""",
            (user_id,),
        )
        settings_by_name = {r['project']: r for r in settings_rows}

        def _iso(v):
            return v.isoformat() if hasattr(v, 'isoformat') else v

        seen = set()
        result = []
        for r in proj_rows:
            name = r['project']
            seen.add(name)
            latest = _fetchone(conn,
                """SELECT total_flash, total_ram FROM builds
                   WHERE user_id = %s AND project = %s
                   ORDER BY timestamp DESC LIMIT 1""",
                (user_id, name),
            )
            s = settings_by_name.get(name, {})
            result.append({
                'project':             name,
                'build_count':         r['build_count'],
                'first_build':         _iso(r['first_build']),
                'last_build':          _iso(r['last_build']),
                'latest_flash':        latest['total_flash'] if latest else None,
                'latest_ram':          latest['total_ram']   if latest else None,
                'flash_budget_bytes':  s.get('flash_budget_bytes'),
                'ram_budget_bytes':    s.get('ram_budget_bytes'),
                'description':         s.get('description'),
                'settings_created_at': _iso(s.get('created_at')),
                'settings_updated_at': _iso(s.get('updated_at')),
            })

        for name, s in settings_by_name.items():
            if name in seen:
                continue
            result.append({
                'project':             name,
                'build_count':         0,
                'first_build':         None,
                'last_build':          None,
                'latest_flash':        None,
                'latest_ram':          None,
                'flash_budget_bytes':  s.get('flash_budget_bytes'),
                'ram_budget_bytes':    s.get('ram_budget_bytes'),
                'description':         s.get('description'),
                'settings_created_at': _iso(s.get('created_at')),
                'settings_updated_at': _iso(s.get('updated_at')),
            })

        return result


# ── Shares ────────────────────────────────────────────────────────────────────

def save_share(
    share_id: str,
    filename: str,
    analysis_json: str,
    user_id: Optional[str] = None,
) -> None:
    with _db() as conn:
        _exec(conn,
            """INSERT INTO shares (id, user_id, filename, created_at, analysis_json)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (id) DO UPDATE SET
                   user_id       = EXCLUDED.user_id,
                   filename      = EXCLUDED.filename,
                   analysis_json = EXCLUDED.analysis_json""",
            (share_id, user_id, filename, datetime.now(timezone.utc), analysis_json),
        )


def get_share(share_id: str) -> Optional[dict]:
    with _db() as conn:
        row = _fetchone(conn,
            "SELECT filename, created_at, analysis_json FROM shares WHERE id = %s",
            (share_id,),
        )
    if not row:
        return None
    ca = row['created_at']
    return {
        'id':         share_id,
        'filename':   row['filename'],
        'created_at': ca.isoformat() if hasattr(ca, 'isoformat') else ca,
        'data':       json.loads(row['analysis_json']),
    }


# ── Account deletion ──────────────────────────────────────────────────────────

def delete_all_for_user(user_id: str) -> dict:
    """Permanently delete all data belonging to user_id."""
    if not user_id or user_id == '__anonymous__':
        raise ValueError('Refusing to delete anonymous/missing user_id.')
    with _db() as conn:
        cur = _exec(conn, 'DELETE FROM builds WHERE user_id = %s', (user_id,))
        builds = cur.rowcount
        cur = _exec(conn, 'DELETE FROM shares WHERE user_id = %s', (user_id,))
        shares = cur.rowcount
        cur = _exec(conn, 'DELETE FROM project_settings WHERE user_id = %s', (user_id,))
        settings = cur.rowcount
    return {
        'builds_deleted':           builds,
        'shares_deleted':           shares,
        'project_settings_deleted': settings,
    }
