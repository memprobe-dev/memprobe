"""Build history — PostgreSQL.

Security model
--------------
1. Application layer: every function that reads or writes user-owned data
   requires a ``user_id`` argument and filters ALL queries by it.

2. Database layer: PostgreSQL Row Level Security (RLS) is enabled on
   ``builds``, ``project_settings``, and ``user_profiles``.  Every
   transaction sets ``app.current_user_id`` via ``set_config(..., TRUE)``
   (transaction-local, safe with connection pools).  The RLS policy then
   enforces ``user_id = current_setting('app.current_user_id', TRUE)``
   at the storage engine level, so even a future application bug that
   forgets to pass user_id would return zero rows instead of leaking data.

   Shares are intentionally public (no RLS) — the random share ID is the
   only access control, which is the point.

3. Indexes: all user-scoped tables have a leading ``user_id`` column in
   every index so queries never require a sequential scan.

Requires DATABASE_URL environment variable:
    DATABASE_URL=postgres://user:pass@host:5432/dbname
"""

from __future__ import annotations

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
def _db(user_id: Optional[str] = None):
    """Yield a connection, auto-commit on success, rollback on error.

    If ``user_id`` is provided, it is set as a transaction-local GUC
    (``app.current_user_id``) so that PostgreSQL RLS policies can enforce
    row-level isolation at the storage layer.  ``TRUE`` as the third arg
    to ``set_config`` means the setting is local to the transaction and
    resets automatically when it commits or rolls back — safe for pooled
    connections.
    """
    pool = _get_pool()
    conn = pool.getconn()
    try:
        if user_id is not None:
            cur = conn.cursor()
            cur.execute(
                "SELECT set_config('app.current_user_id', %s, TRUE)",
                (str(user_id),),
            )
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
-- ── User profiles ──────────────────────────────────────────────────────────
-- One row per registered user. Created automatically on first login via
-- Django signals. Tracks plan tier and whether the user signed up during
-- the beta period (eligible for beta-specific pricing / features).
--
-- Valid plan values: free | pro | pro_plus | canceled
-- is_beta_user is set at signup time and never changed; it marks eligibility,
-- not the current plan.

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id      TEXT         PRIMARY KEY,
    plan         VARCHAR(20)  NOT NULL DEFAULT 'free',
    plan_since   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    is_beta_user BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT user_profiles_plan_check
        CHECK (plan IN ('free', 'pro', 'pro_plus', 'canceled'))
);

-- ── Builds ─────────────────────────────────────────────────────────────────

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

-- Leading user_id on all indexes so every scoped query is an index scan.
CREATE INDEX IF NOT EXISTS builds_user_id_idx      ON builds (user_id);
CREATE INDEX IF NOT EXISTS builds_user_project_idx ON builds (user_id, project)
    WHERE project IS NOT NULL;
CREATE INDEX IF NOT EXISTS builds_user_ts_idx      ON builds (user_id, timestamp DESC);

-- ── Shares ─────────────────────────────────────────────────────────────────
-- Intentionally public: the opaque random ID is the access control.
-- No RLS on this table.

CREATE TABLE IF NOT EXISTS shares (
    id            TEXT PRIMARY KEY,
    user_id       TEXT,
    filename      TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    analysis_json TEXT        NOT NULL
);

-- ── Project settings ────────────────────────────────────────────────────────

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

# Incremental migrations: add columns that may not exist on older DBs.
_MIGRATIONS_SQL = """
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'builds' AND column_name = 'active'
    ) THEN
        ALTER TABLE builds ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'builds' AND column_name = 'sort_order'
    ) THEN
        ALTER TABLE builds ADD COLUMN sort_order INTEGER;
        -- backfill: assign sort_order based on timestamp within each project
        UPDATE builds b
        SET sort_order = sub.rn
        FROM (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY user_id, project
                       ORDER BY timestamp ASC
                   ) AS rn
            FROM builds
            WHERE project IS NOT NULL
        ) sub
        WHERE b.id = sub.id AND b.project IS NOT NULL;
    END IF;
END $$;
"""

# RLS is applied separately because it requires ALTER TABLE and CREATE POLICY,
# which need the table to already exist and the DB user to be the table owner.
# init_db() calls _apply_rls() after the schema is created; failures are
# logged but not fatal so a misconfigured Postgres (e.g. limited-privilege
# user) doesn't break startup — the application-layer user_id checks remain.
_RLS_SQL = """
-- Enable RLS on user-scoped tables.
ALTER TABLE user_profiles   ENABLE ROW LEVEL SECURITY;
ALTER TABLE builds          ENABLE ROW LEVEL SECURITY;
ALTER TABLE project_settings ENABLE ROW LEVEL SECURITY;

-- Policies: every operation must be on the calling user's own rows.
-- current_setting('app.current_user_id', TRUE) returns NULL (not error)
-- when the GUC is unset, causing the comparison to fail safely.
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'user_profiles' AND policyname = 'user_profiles_isolation'
    ) THEN
        CREATE POLICY user_profiles_isolation ON user_profiles
            USING (user_id = current_setting('app.current_user_id', TRUE));
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'builds' AND policyname = 'builds_isolation'
    ) THEN
        CREATE POLICY builds_isolation ON builds
            USING (user_id = current_setting('app.current_user_id', TRUE));
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'project_settings' AND policyname = 'project_settings_isolation'
    ) THEN
        CREATE POLICY project_settings_isolation ON project_settings
            USING (user_id = current_setting('app.current_user_id', TRUE));
    END IF;
END $$;
"""


def _apply_rls() -> None:
    """Enable RLS policies on user-scoped tables. Safe to call repeatedly."""
    import logging
    log = logging.getLogger(__name__)
    try:
        with _db() as conn:
            _exec(conn, _RLS_SQL)
        log.info('history: RLS policies applied successfully')
    except Exception as exc:
        # Non-fatal: log and continue. App-layer user_id guards still apply.
        log.warning(
            'history: could not apply RLS policies (non-fatal, app-layer guards active): %s',
            exc,
        )


def init_db() -> None:
    """Create tables, indexes, and RLS policies. Safe to call on every startup."""
    import logging
    log = logging.getLogger(__name__)
    with _db() as conn:
        _exec(conn, _SCHEMA)
        try:
            _exec(conn, _MIGRATIONS_SQL)
        except Exception as exc:
            log.warning('history: incremental migrations failed (non-fatal): %s', exc)
    _apply_rls()


# ── User profile functions ────────────────────────────────────────────────────

def create_profile(user_id: str, is_beta_user: bool = False) -> dict:
    """Create a user profile row if one doesn't exist. Idempotent.

    Call this from a Django signal on User post_save so every new account
    gets a profile immediately. ``is_beta_user`` should be set based on
    whether the signup date falls within the beta window (see signals.py).
    """
    if not user_id:
        raise ValueError('user_id required')
    now = datetime.now(timezone.utc)
    with _db(user_id=user_id) as conn:
        _exec(conn,
            """INSERT INTO user_profiles (user_id, plan, plan_since, is_beta_user, created_at, updated_at)
               VALUES (%s, 'free', %s, %s, %s, %s)
               ON CONFLICT (user_id) DO NOTHING""",
            (user_id, now, is_beta_user, now, now),
        )
        return _fetchone(conn,
            "SELECT * FROM user_profiles WHERE user_id = %s",
            (user_id,),
        ) or {}


def get_profile(user_id: str) -> Optional[dict]:
    """Return the profile row for user_id, or None if it doesn't exist."""
    if not user_id:
        return None
    with _db(user_id=user_id) as conn:
        return _fetchone(conn,
            "SELECT * FROM user_profiles WHERE user_id = %s",
            (user_id,),
        )


def update_plan(user_id: str, plan: str) -> dict:
    """Update a user's plan. ``plan`` must be one of the allowed values.

    Valid plans: free | pro | pro_plus | canceled
    """
    allowed = {'free', 'pro', 'pro_plus', 'canceled'}
    if plan not in allowed:
        raise ValueError(f'Invalid plan {plan!r}. Must be one of: {allowed}')
    if not user_id:
        raise ValueError('user_id required')
    now = datetime.now(timezone.utc)
    with _db(user_id=user_id) as conn:
        _exec(conn,
            """UPDATE user_profiles
               SET plan = %s, plan_since = %s, updated_at = %s
               WHERE user_id = %s""",
            (plan, now, now, user_id),
        )
        return _fetchone(conn,
            "SELECT * FROM user_profiles WHERE user_id = %s",
            (user_id,),
        ) or {}


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
    proj = project.strip() if project and project.strip() else None
    with _db(user_id=user_id) as conn:
        # Compute next sort_order for this project (NULL projects get NULL sort_order).
        # Use COUNT(*) as the base so pre-migration rows with null sort_order are
        # counted correctly — MAX(sort_order) returns NULL when all values are null,
        # which would make every new build get sort_order=1.
        if proj:
            row = _fetchone(conn,
                """SELECT GREATEST(COALESCE(MAX(sort_order), 0), COUNT(*)) + 1 AS next_order
                   FROM builds WHERE user_id = %s AND project = %s""",
                (user_id, proj),
            )
            next_order = int(row['next_order']) if row and row['next_order'] is not None else 1
        else:
            next_order = None
        cur = _exec(conn,
            """INSERT INTO builds
               (user_id, source_file, timestamp, git_hash, git_branch,
                total_flash, total_ram, toolchain, project, metadata, analysis_json,
                active, sort_order)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, %s)
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
                proj,
                json.dumps({}),
                json.dumps(analysis_json) if analysis_json else None,
                next_order,
            ),
        )
        return cur.fetchone()['id']


def get_build(build_id: int, user_id: str) -> Optional[dict]:
    """Return a build by ID only if it belongs to user_id."""
    with _db(user_id=user_id) as conn:
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
    """Return all builds for user_id, newest first.

    Intentionally excludes ``analysis_json`` — that column can be many MB per
    row and the list view only needs summary fields.  Use ``get_build`` to
    fetch the full analysis for a single build.
    """
    with _db(user_id=user_id) as conn:
        return _fetchall(conn,
            """SELECT id, user_id, source_file, timestamp, git_hash, git_branch,
                      total_flash, total_ram, toolchain, project, metadata,
                      (analysis_json IS NOT NULL) AS has_analysis
               FROM builds WHERE user_id = %s ORDER BY timestamp DESC""",
            (user_id,),
        )


def delete_build(build_id: int, user_id: str) -> bool:
    """Delete a build. Returns True if a row was deleted."""
    with _db(user_id=user_id) as conn:
        cur = _exec(conn,
            "DELETE FROM builds WHERE id = %s AND user_id = %s",
            (build_id, user_id),
        )
        return cur.rowcount > 0


def update_build_meta(
    build_id: int,
    user_id: str,
    *,
    active: Optional[bool] = None,
    timestamp: Optional[str] = None,
    sort_order: Optional[int] = None,
) -> bool:
    """Update mutable metadata on a build. Returns True if a row was updated."""
    sets, vals = [], []
    if active is not None:
        sets.append("active = %s"); vals.append(active)
    if timestamp is not None:
        sets.append("timestamp = %s"); vals.append(timestamp)
    if sort_order is not None:
        sets.append("sort_order = %s"); vals.append(sort_order)
    if not sets:
        return False
    vals.extend([build_id, user_id])
    with _db(user_id=user_id) as conn:
        cur = _exec(conn,
            f"UPDATE builds SET {', '.join(sets)} WHERE id = %s AND user_id = %s",
            vals,
        )
        return cur.rowcount > 0


def clear(user_id: str) -> None:
    """Delete all builds belonging to user_id."""
    with _db(user_id=user_id) as conn:
        _exec(conn, "DELETE FROM builds WHERE user_id = %s", (user_id,))


def list_projects(user_id: str) -> list:
    """Return all distinct project names for user_id (including empty ones), alphabetically."""
    with _db(user_id=user_id) as conn:
        rows = _fetchall(conn,
            """SELECT project FROM (
                   SELECT DISTINCT project FROM builds
                   WHERE user_id = %s AND project IS NOT NULL
                   UNION
                   SELECT project FROM project_settings
                   WHERE user_id = %s
               ) combined
               ORDER BY project""",
            (user_id, user_id),
        )
    return [r['project'] for r in rows]


def list_project_summaries(user_id: str) -> list:
    """Return one summary row per project (including empty ones), most-recently-active first."""
    with _db(user_id=user_id) as conn:
        projects = _fetchall(conn,
            """SELECT
                   COALESCE(b.project, ps.project) AS project,
                   COUNT(b.id)                     AS build_count,
                   MAX(b.timestamp)                AS last_build,
                   MAX(b.id)                       AS latest_id
               FROM project_settings ps
               LEFT JOIN builds b
                   ON b.user_id = ps.user_id AND b.project = ps.project
               WHERE ps.user_id = %s
               GROUP BY COALESCE(b.project, ps.project)
               ORDER BY MAX(b.timestamp) DESC NULLS LAST""",
            (user_id,),
        )

        result = []
        for p in projects:
            # Fetch the two most recent builds in chart order (sort_order DESC,
            # then timestamp DESC) so the delta reflects what the trend chart shows.
            two = _fetchall(conn,
                """SELECT total_flash, total_ram, source_file FROM builds
                   WHERE user_id = %s AND project = %s
                   ORDER BY COALESCE(sort_order, 0) DESC, timestamp DESC LIMIT 2""",
                (user_id, p['project']),
            ) if p['build_count'] else []
            latest = two[0] if two else {}
            prev   = two[1] if len(two) > 1 else None
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
    with _db(user_id=user_id) as conn:
        if project:
            rows = _fetchall(conn,
                """SELECT id, source_file, timestamp, git_hash, git_branch,
                          total_flash, total_ram, project, active, sort_order
                   FROM builds WHERE user_id = %s AND project = %s
                   ORDER BY COALESCE(sort_order, 0) ASC, timestamp ASC LIMIT %s""",
                (user_id, project, limit),
            )
        elif source_file:
            # Escape LIKE metacharacters in the filename to prevent wildcard injection.
            safe_name = Path(source_file).name.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            rows = _fetchall(conn,
                """SELECT id, source_file, timestamp, git_hash, git_branch,
                          total_flash, total_ram, project, active, sort_order
                   FROM builds WHERE user_id = %s AND source_file LIKE %s ESCAPE '\\'
                                     AND project IS NOT NULL
                   ORDER BY COALESCE(sort_order, 0) ASC, timestamp ASC LIMIT %s""",
                (user_id, f'%{safe_name}%', limit),
            )
        else:
            rows = _fetchall(conn,
                """SELECT id, source_file, timestamp, git_hash, git_branch,
                          total_flash, total_ram, project, active, sort_order
                   FROM builds WHERE user_id = %s AND project IS NOT NULL
                   ORDER BY COALESCE(sort_order, 0) ASC, timestamp ASC LIMIT %s""",
                (user_id, limit),
            )
    all_rows = [{
        **r,
        'basename':  Path(r['source_file']).name,
        'active':    r.get('active', True),
        'sort_order': r.get('sort_order'),
        'timestamp': r['timestamp'].isoformat() if hasattr(r.get('timestamp'), 'isoformat') else r.get('timestamp'),
    } for r in rows]
    # Chart only uses active builds; the full list (for the management table) is returned as-is
    return all_rows


# ── Project settings ──────────────────────────────────────────────────────────

def get_project_settings(user_id: str, project: str) -> Optional[dict]:
    with _db(user_id=user_id) as conn:
        return _fetchone(conn,
            """SELECT project, flash_budget_bytes, ram_budget_bytes,
                      description, created_at, updated_at
               FROM project_settings WHERE user_id = %s AND project = %s""",
            (user_id, project),
        )


_UNSET = object()  # sentinel distinguishing "not provided" from explicit None


def save_project_settings(
    user_id: str,
    project: str,
    flash_budget_bytes=_UNSET,
    ram_budget_bytes=_UNSET,
    description=_UNSET,
) -> dict:
    """Upsert settings for a project.

    Pass ``None`` to explicitly clear a field (e.g. remove a budget).
    Omit a parameter (or pass the sentinel) to leave the existing value unchanged.
    """
    if not user_id or user_id == '__anonymous__':
        raise ValueError('user_id required.')
    if not project:
        raise ValueError('project name required.')
    now = datetime.now(timezone.utc)

    with _db(user_id=user_id) as conn:
        # INSERT … ON CONFLICT is the simplest path for a new row.
        # For updates, build the SET clause dynamically so we only touch the
        # fields the caller explicitly provided (including explicit None clears).
        existing = _fetchone(conn,
            "SELECT flash_budget_bytes, ram_budget_bytes, description, created_at "
            "FROM project_settings WHERE user_id = %s AND project = %s",
            (user_id, project),
        )

        if existing is None:
            # New row: treat unset sentinels as NULL
            fb = None if flash_budget_bytes is _UNSET else flash_budget_bytes
            rb = None if ram_budget_bytes   is _UNSET else ram_budget_bytes
            desc = None if description      is _UNSET else description
            _exec(conn,
                """INSERT INTO project_settings
                   (user_id, project, flash_budget_bytes, ram_budget_bytes,
                    description, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (user_id, project, fb, rb, desc, now, now),
            )
        else:
            # Update: only touch fields the caller explicitly provided.
            sets, vals = [], []
            if flash_budget_bytes is not _UNSET:
                sets.append("flash_budget_bytes = %s"); vals.append(flash_budget_bytes)
            if ram_budget_bytes is not _UNSET:
                sets.append("ram_budget_bytes = %s"); vals.append(ram_budget_bytes)
            if description is not _UNSET:
                sets.append("description = %s"); vals.append(description)
            sets.append("updated_at = %s"); vals.append(now)
            vals.extend([user_id, project])
            _exec(conn,
                f"UPDATE project_settings SET {', '.join(sets)} WHERE user_id = %s AND project = %s",
                vals,
            )

    return get_project_settings(user_id, project) or {}


def delete_project(user_id: str, project: str) -> dict:
    """Delete a project's builds and settings."""
    if not user_id or user_id == '__anonymous__':
        raise ValueError('user_id required.')
    if not project:
        raise ValueError('project name required.')
    with _db(user_id=user_id) as conn:
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
    with _db(user_id=user_id) as conn:
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
            two_builds = _fetchall(conn,
                """SELECT total_flash, total_ram FROM builds
                   WHERE user_id = %s AND project = %s
                   ORDER BY COALESCE(sort_order, 0) DESC, timestamp DESC LIMIT 2""",
                (user_id, name),
            )
            latest = two_builds[0] if two_builds else None
            prev   = two_builds[1] if len(two_builds) > 1 else None
            flash_delta = None
            ram_delta   = None
            if latest and prev:
                if latest['total_flash'] is not None and prev['total_flash'] is not None:
                    flash_delta = latest['total_flash'] - prev['total_flash']
                if latest['total_ram'] is not None and prev['total_ram'] is not None:
                    ram_delta = latest['total_ram'] - prev['total_ram']
            s = settings_by_name.get(name, {})
            result.append({
                'project':             name,
                'build_count':         r['build_count'],
                'first_build':         _iso(r['first_build']),
                'last_build':          _iso(r['last_build']),
                'latest_flash':        latest['total_flash'] if latest else None,
                'latest_ram':          latest['total_ram']   if latest else None,
                'flash_delta':         flash_delta,
                'ram_delta':           ram_delta,
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
                'flash_delta':         None,
                'ram_delta':           None,
                'flash_budget_bytes':  s.get('flash_budget_bytes'),
                'ram_budget_bytes':    s.get('ram_budget_bytes'),
                'description':         s.get('description'),
                'settings_created_at': _iso(s.get('created_at')),
                'settings_updated_at': _iso(s.get('updated_at')),
            })

        return result


# ── Shares ────────────────────────────────────────────────────────────────────
# No RLS on shares — the opaque random ID is the access control.

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
    with _db(user_id=user_id) as conn:
        cur = _exec(conn, 'DELETE FROM builds WHERE user_id = %s', (user_id,))
        builds = cur.rowcount
        cur = _exec(conn, 'DELETE FROM project_settings WHERE user_id = %s', (user_id,))
        settings = cur.rowcount
        cur = _exec(conn, 'DELETE FROM user_profiles WHERE user_id = %s', (user_id,))
        profiles = cur.rowcount
    # Shares deletion does not need user_id RLS — filter by column directly.
    with _db() as conn:
        cur = _exec(conn, 'DELETE FROM shares WHERE user_id = %s', (user_id,))
        shares = cur.rowcount
    return {
        'builds_deleted':           builds,
        'shares_deleted':           shares,
        'project_settings_deleted': settings,
        'profiles_deleted':         profiles,
    }
