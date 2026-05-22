"""SQLite-backed build history tracking.

Security invariant: every function that reads or writes user-owned build data
requires a ``user_id`` argument and filters ALL queries by it.  A user can
never read or mutate another user's builds, even if they know the build ID.

Share records are keyed by an opaque random ID and are intentionally public
(that is the point of sharing).  They carry no user_id.
"""

import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import MemoryMap


# Allow the DB path to be overridden via environment variable so the web server
# can store it inside the project directory rather than ~/.memprobe/.
_DEFAULT_DB = Path(os.environ.get(
    'MEMPROBE_DB_PATH',
    str(Path.home() / '.memprobe' / 'history.db'),
))
_DB_PATH = _DEFAULT_DB

_SCHEMA = """
CREATE TABLE IF NOT EXISTS builds (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT    NOT NULL,
    source_file   TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL,
    git_hash      TEXT,
    git_branch    TEXT,
    total_flash   INTEGER NOT NULL,
    total_ram     INTEGER NOT NULL,
    toolchain     TEXT    NOT NULL,
    project       TEXT,
    metadata      JSON,
    analysis_json TEXT
);
CREATE TABLE IF NOT EXISTS shares (
    id            TEXT PRIMARY KEY,
    user_id       TEXT,
    filename      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    analysis_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS project_settings (
    user_id            TEXT    NOT NULL,
    project            TEXT    NOT NULL,
    flash_budget_bytes INTEGER,
    ram_budget_bytes   INTEGER,
    description        TEXT,
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL,
    PRIMARY KEY (user_id, project)
);
"""


def _connect(db_path: Path = _DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)

    # ── Schema migrations ──────────────────────────────────────────────────────
    cols = {r[1] for r in conn.execute("PRAGMA table_info(builds)").fetchall()}

    if 'analysis_json' not in cols:
        conn.execute("ALTER TABLE builds ADD COLUMN analysis_json TEXT")
    if 'project' not in cols:
        conn.execute("ALTER TABLE builds ADD COLUMN project TEXT")
    if 'user_id' not in cols:
        # Existing anonymous rows get a sentinel that will never match a real user
        conn.execute("ALTER TABLE builds ADD COLUMN user_id TEXT NOT NULL DEFAULT '__anonymous__'")

    # Add user_id to shares table if not present (for account-deletion cleanup)
    share_cols = {r[1] for r in conn.execute("PRAGMA table_info(shares)").fetchall()}
    if 'user_id' not in share_cols:
        conn.execute("ALTER TABLE shares ADD COLUMN user_id TEXT")

    conn.commit()
    return conn


def _detect_git(file_path: str) -> tuple[Optional[str], Optional[str]]:
    """Return (commit_hash, branch) for the repo containing file_path."""
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


# ── Per-user build functions ───────────────────────────────────────────────────
# Every function here requires user_id and scopes ALL queries to that user.


def save(
    mmap: MemoryMap,
    user_id: str,
    analysis_json: Optional[dict] = None,
    project: Optional[str] = None,
    db_path: Path = _DB_PATH,
) -> int:
    """Persist a MemoryMap to the history database. Returns the new build id."""
    conn = _connect(db_path)
    timestamp = mmap.timestamp or datetime.now(timezone.utc).isoformat()
    git_hash, git_branch = _detect_git(mmap.source_file)

    cur = conn.execute(
        """INSERT INTO builds
           (user_id, source_file, timestamp, git_hash, git_branch,
            total_flash, total_ram, toolchain, project, metadata, analysis_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id,
            mmap.source_file,
            timestamp,
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
    build_id = cur.lastrowid
    assert build_id is not None
    conn.commit()
    conn.close()
    return build_id


def get_build(build_id: int, user_id: str, db_path: Path = _DB_PATH) -> Optional[dict]:
    """Return a build by ID, only if it belongs to user_id. Returns None otherwise.

    The user_id check is not optional - callers must always provide it so that
    knowing a build ID is not sufficient to read another user's data.
    """
    conn = _connect(db_path)
    row = conn.execute(
        "SELECT * FROM builds WHERE id = ? AND user_id = ?",
        (build_id, user_id),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    if d.get('analysis_json'):
        d['analysis'] = json.loads(d['analysis_json'])
    return d


def list_builds(user_id: str, db_path: Path = _DB_PATH) -> list[dict]:
    """Return all builds for user_id, newest first."""
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT * FROM builds WHERE user_id = ? ORDER BY timestamp DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_build(build_id: int, user_id: str, db_path: Path = _DB_PATH) -> bool:
    """Delete a build. Only succeeds if the build belongs to user_id."""
    conn = _connect(db_path)
    cur = conn.execute(
        "DELETE FROM builds WHERE id = ? AND user_id = ?",
        (build_id, user_id),
    )
    conn.commit()
    conn.close()
    return cur.rowcount > 0


def clear(user_id: str, db_path: Path = _DB_PATH) -> None:
    """Delete all builds belonging to user_id."""
    conn = _connect(db_path)
    conn.execute("DELETE FROM builds WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def list_projects(user_id: str, db_path: Path = _DB_PATH) -> list[str]:
    """Return all distinct project names for user_id, alphabetically."""
    conn = _connect(db_path)
    rows = conn.execute(
        "SELECT DISTINCT project FROM builds WHERE user_id = ? AND project IS NOT NULL ORDER BY project",
        (user_id,),
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def list_project_summaries(user_id: str, db_path: Path = _DB_PATH) -> list[dict]:
    """Return one summary row per project for user_id, most-recently-active first."""
    conn = _connect(db_path)
    projects = conn.execute(
        """SELECT project,
                  COUNT(*) AS build_count,
                  MAX(timestamp) AS last_build,
                  MAX(id) AS latest_id
           FROM builds
           WHERE user_id = ? AND project IS NOT NULL
           GROUP BY project
           ORDER BY MAX(timestamp) DESC""",
        (user_id,),
    ).fetchall()

    result = []
    for p in projects:
        proj = p['project']
        latest = conn.execute(
            "SELECT total_flash, total_ram, source_file FROM builds WHERE id = ? AND user_id = ?",
            (p['latest_id'], user_id),
        ).fetchone()
        prev = conn.execute(
            """SELECT total_flash, total_ram FROM builds
               WHERE project = ? AND user_id = ? AND id < ?
               ORDER BY id DESC LIMIT 1""",
            (proj, user_id, p['latest_id']),
        ).fetchone()

        flash_delta = (latest['total_flash'] - prev['total_flash']) if prev else None
        ram_delta   = (latest['total_ram']   - prev['total_ram'])   if prev else None

        result.append({
            'project':     proj,
            'build_count': p['build_count'],
            'last_build':  p['last_build'],
            'total_flash': latest['total_flash'] if latest else 0,
            'total_ram':   latest['total_ram']   if latest else 0,
            'source_file': latest['source_file'] if latest else '',
            'flash_delta': flash_delta,
            'ram_delta':   ram_delta,
        })
    conn.close()
    return result


def get_trend(
    user_id: str,
    source_file: Optional[str] = None,
    project: Optional[str] = None,
    limit: int = 200,
    db_path: Path = _DB_PATH,
) -> list[dict]:
    """Return time-series data for user_id, ordered ascending.

    Filter priority: project name > source file basename.
    """
    conn = _connect(db_path)
    if project:
        rows = conn.execute(
            """SELECT id, source_file, timestamp, git_hash, git_branch,
                      total_flash, total_ram, project
               FROM builds WHERE user_id = ? AND project = ?
               ORDER BY timestamp ASC LIMIT ?""",
            (user_id, project, limit),
        ).fetchall()
    elif source_file:
        # Snapshots (project IS NULL) are excluded from trends in all cases.
        basename = Path(source_file).name
        rows = conn.execute(
            """SELECT id, source_file, timestamp, git_hash, git_branch,
                      total_flash, total_ram, project
               FROM builds WHERE user_id = ? AND source_file LIKE ?
                                 AND project IS NOT NULL
               ORDER BY timestamp ASC LIMIT ?""",
            (user_id, f'%{basename}%', limit),
        ).fetchall()
    else:
        # No specific filter: trend data is project builds only.
        # One-time snapshots (project IS NULL) are excluded by design.
        rows = conn.execute(
            """SELECT id, source_file, timestamp, git_hash, git_branch,
                      total_flash, total_ram, project
               FROM builds WHERE user_id = ? AND project IS NOT NULL
               ORDER BY timestamp ASC LIMIT ?""",
            (user_id, limit),
        ).fetchall()
    conn.close()
    return [
        {**dict(r), 'basename': Path(r['source_file']).name}
        for r in rows
    ]


# ── Project settings ──────────────────────────────────────────────────────────


def get_project_settings(user_id: str, project: str, db_path: Path = _DB_PATH) -> Optional[dict]:
    """Return the saved settings for a project, or None if none saved."""
    conn = _connect(db_path)
    row = conn.execute(
        """SELECT project, flash_budget_bytes, ram_budget_bytes, description,
                  created_at, updated_at
           FROM project_settings WHERE user_id = ? AND project = ?""",
        (user_id, project),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def save_project_settings(
    user_id: str,
    project: str,
    flash_budget_bytes: Optional[int] = None,
    ram_budget_bytes: Optional[int] = None,
    description: Optional[str] = None,
    db_path: Path = _DB_PATH,
) -> dict:
    """Upsert settings for a project. Pass None to clear individual fields."""
    if not user_id or user_id == '__anonymous__':
        raise ValueError('user_id required.')
    if not project:
        raise ValueError('project name required.')
    conn = _connect(db_path)
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        'SELECT created_at FROM project_settings WHERE user_id = ? AND project = ?',
        (user_id, project),
    ).fetchone()
    created_at = existing['created_at'] if existing else now
    conn.execute(
        """INSERT OR REPLACE INTO project_settings
           (user_id, project, flash_budget_bytes, ram_budget_bytes,
            description, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_id, project, flash_budget_bytes, ram_budget_bytes,
         description, created_at, now),
    )
    conn.commit()
    conn.close()
    return get_project_settings(user_id, project, db_path) or {}


def delete_project(user_id: str, project: str, db_path: Path = _DB_PATH) -> dict:
    """Delete a project: all its builds AND its settings.

    Shares are not deleted (a user may still want to share an old snapshot
    URL even after deleting the project).
    """
    if not user_id or user_id == '__anonymous__':
        raise ValueError('user_id required.')
    if not project:
        raise ValueError('project name required.')
    conn = _connect(db_path)
    builds = conn.execute(
        'DELETE FROM builds WHERE user_id = ? AND project = ?',
        (user_id, project),
    ).rowcount
    settings = conn.execute(
        'DELETE FROM project_settings WHERE user_id = ? AND project = ?',
        (user_id, project),
    ).rowcount
    conn.commit()
    conn.close()
    return {'builds_deleted': builds, 'settings_deleted': settings}


def list_projects_full(user_id: str, db_path: Path = _DB_PATH) -> list[dict]:
    """Return rich per-project data: summary stats + saved settings.

    Each row contains: project, build_count, first_build, last_build,
    total_flash (latest), total_ram (latest), flash_budget_bytes,
    ram_budget_bytes, description.
    """
    conn = _connect(db_path)
    # Distinct projects with any builds
    proj_rows = conn.execute(
        """SELECT project, COUNT(*) AS build_count,
                  MIN(timestamp) AS first_build, MAX(timestamp) AS last_build
           FROM builds
           WHERE user_id = ? AND project IS NOT NULL
           GROUP BY project
           ORDER BY MAX(timestamp) DESC""",
        (user_id,),
    ).fetchall()
    # Also list projects that have settings but no builds yet
    setting_rows = conn.execute(
        """SELECT project, flash_budget_bytes, ram_budget_bytes,
                  description, created_at, updated_at
           FROM project_settings WHERE user_id = ?""",
        (user_id,),
    ).fetchall()
    settings_by_name = {r['project']: dict(r) for r in setting_rows}

    seen = set()
    result = []
    for r in proj_rows:
        name = r['project']
        seen.add(name)
        latest = conn.execute(
            """SELECT total_flash, total_ram FROM builds
               WHERE user_id = ? AND project = ?
               ORDER BY timestamp DESC LIMIT 1""",
            (user_id, name),
        ).fetchone()
        s = settings_by_name.get(name, {})
        result.append({
            'project': name,
            'build_count': r['build_count'],
            'first_build': r['first_build'],
            'last_build': r['last_build'],
            'latest_flash': latest['total_flash'] if latest else None,
            'latest_ram':   latest['total_ram']   if latest else None,
            'flash_budget_bytes': s.get('flash_budget_bytes'),
            'ram_budget_bytes':   s.get('ram_budget_bytes'),
            'description':        s.get('description'),
            'settings_created_at': s.get('created_at'),
            'settings_updated_at': s.get('updated_at'),
        })
    # Settings-only projects (no builds yet)
    for name, s in settings_by_name.items():
        if name in seen: continue
        result.append({
            'project': name,
            'build_count': 0,
            'first_build': None,
            'last_build': None,
            'latest_flash': None,
            'latest_ram':   None,
            'flash_budget_bytes': s.get('flash_budget_bytes'),
            'ram_budget_bytes':   s.get('ram_budget_bytes'),
            'description':        s.get('description'),
            'settings_created_at': s.get('created_at'),
            'settings_updated_at': s.get('updated_at'),
        })
    conn.close()
    return result


# ── Share functions ────────────────────────────────────────────────────────────
# Shares are publicly readable (the share link is the access token), but we still
# record the creator's user_id so we can purge all of a user's shares on account
# deletion. Reading a share never reveals or requires the user_id.


def save_share(
    share_id: str,
    filename: str,
    analysis_json: str,
    user_id: Optional[str] = None,
    db_path: Path = _DB_PATH,
) -> None:
    """Persist an analysis under a share ID. Records user_id for deletion cleanup."""
    conn = _connect(db_path)
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO shares (id, user_id, filename, created_at, analysis_json) "
        "VALUES (?, ?, ?, ?, ?)",
        (share_id, user_id, filename, now, analysis_json),
    )
    conn.commit()
    conn.close()


# ── Account deletion ──────────────────────────────────────────────────────────


def delete_all_for_user(user_id: str, db_path: Path = _DB_PATH) -> dict:
    """Permanently delete ALL data belonging to user_id.

    Removes the user's build history and any share links they created.
    Returns a dict with deletion counts for confirmation/audit.
    """
    if not user_id or user_id == '__anonymous__':
        raise ValueError('Refusing to delete anonymous/missing user_id.')

    conn = _connect(db_path)
    builds = conn.execute(
        'DELETE FROM builds WHERE user_id = ?', (user_id,)
    ).rowcount
    shares = conn.execute(
        'DELETE FROM shares WHERE user_id = ?', (user_id,)
    ).rowcount
    settings = conn.execute(
        'DELETE FROM project_settings WHERE user_id = ?', (user_id,)
    ).rowcount
    conn.commit()
    conn.close()
    return {
        'builds_deleted': builds,
        'shares_deleted': shares,
        'project_settings_deleted': settings,
    }


def get_share(share_id: str, db_path: Path = _DB_PATH) -> Optional[dict]:
    """Return the stored analysis for share_id, or None."""
    conn = _connect(db_path)
    row = conn.execute(
        "SELECT filename, created_at, analysis_json FROM shares WHERE id = ?",
        (share_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        'id':         share_id,
        'filename':   row['filename'],
        'created_at': row['created_at'],
        'data':       json.loads(row['analysis_json']),
    }
