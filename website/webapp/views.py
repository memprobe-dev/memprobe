"""Django views for the memprobe web UI."""

from __future__ import annotations

import json
import secrets
import tempfile
import threading
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest
from django.middleware.csrf import get_token as csrf_get_token
from django.shortcuts import redirect, render
from django.template.loader import get_template
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from memprobe.parsers import map_gcc, map_iar, detect_iar
from memprobe.parsers import elf as elf_parser
from memprobe.diff import diff as compute_diff
from memprobe.models import MemoryMap, Section, Symbol, SectionType, MemoryRegion
from memprobe.report import _human_bytes, _SECTION_COLORS, _build_treemap_data
from memprobe.bloat import analyze as bloat_analyze
from memprobe.insights import compute_insights
from memprobe.demangle import demangle, is_mangled
from memprobe.libraries import detect_libraries
from memprobe import history as hist
from memprobe import __version__

hist.init_db()

_SHARE_ID_BYTES = 5   # 10 hex chars
_SUPPORTED = {'.map', '.elf', '.axf'}

# ── Rate limiting ─────────────────────────────────────────────────────────────
# Sliding-window rate limiter keyed by user ID (authenticated) or IP (guest).
# Stored in-process; resets on server restart. Fine for single-process Gunicorn.

_rate_lock = threading.Lock()
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _rate_limit(max_calls: int, window_seconds: int):
    """Decorator: allow max_calls per window_seconds per user/IP. Returns 429 if exceeded."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            key = str(request.user.pk) if request.user.is_authenticated else (
                request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                or request.META.get('REMOTE_ADDR', 'unknown')
            )
            now = time.monotonic()
            with _rate_lock:
                calls = _rate_buckets[key]
                # Evict timestamps outside the window
                _rate_buckets[key] = [t for t in calls if now - t < window_seconds]
                if len(_rate_buckets[key]) >= max_calls:
                    return JsonResponse(
                        {'error': 'Too many requests. Please wait and try again.'},
                        status=429,
                    )
                _rate_buckets[key].append(now)
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# Static file cache-buster: max mtime across all JS/CSS under static/.
# Recomputed on every HTML response (cheap: ~20 stat calls) so CSS/JS edits
# invalidate cached assets immediately without needing a server restart.
_STATIC_DIR = Path(__file__).resolve().parent.parent / 'static'


def _compute_asset_version() -> str:
    try:
        mtimes = [
            p.stat().st_mtime
            for p in _STATIC_DIR.rglob('*')
            if p.is_file() and p.suffix in {'.js', '.css'}
        ]
        return str(int(max(mtimes))) if mtimes else __version__
    except Exception:
        return __version__


_ASSET_VERSION = _compute_asset_version()


def _asset_version() -> str:
    # In DEBUG, recompute every request so JS/CSS changes are picked up without a restart.
    if settings.DEBUG:
        return _compute_asset_version()
    return _ASSET_VERSION


def _json_safe_for_html(data) -> str:
    """Serialize *data* to JSON safe for direct embedding inside a <script> tag.

    json.dumps() never escapes the characters ``<``, ``>`` and ``&``, which
    means a symbol name like ``</script><script>evil()`` would break out of the
    enclosing ``<script>`` block and execute arbitrary JS.  We replace the
    three dangerous ASCII characters with their Unicode escape equivalents;
    JSON parsers treat them identically, but HTML parsers never see the raw
    angle-bracket sequence.
    """
    return (
        json.dumps(data)
        .replace('<',  '\\u003c')
        .replace('>',  '\\u003e')
        .replace('&',  '\\u0026')
    )

# ── Auth decorators ────────────────────────────────────────────────────────────

def api_login_required(view_func):
    """Return 401 JSON (not a redirect) for unauthenticated API requests."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper


def web_login_required(view_func):
    """Redirect unauthenticated users to /login, preserving the next URL."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            from urllib.parse import urlencode
            next_url = request.get_full_path()
            return redirect(f'/login?next={next_url}')
        return view_func(request, *args, **kwargs)
    return wrapper


def _uid(request) -> str:
    """Return the authenticated user's ID as a string. Always call after auth check."""
    return str(request.user.pk)


# ── Helpers ────────────────────────────────────────────────────────────────────

MAX_UPLOAD_BYTES  = 30 * 1024 * 1024   # 30 MB
MAX_PROJECTS      = 2
MAX_BUILDS        = 10


def _is_pro(user) -> bool:
    """Return True if the user has a Pro subscription. Stub: always False until billing is wired up."""
    return False


def _load_upload(django_file):
    """Parse a Django InMemoryUploadedFile into a MemoryMap."""
    if django_file.size > MAX_UPLOAD_BYTES:
        raise ValueError(f"File too large ({django_file.size // (1024*1024)} MB). Maximum is 30 MB.")

    filename = django_file.name or 'firmware'
    suffix = Path(filename).suffix.lower()
    if suffix not in _SUPPORTED:
        raise ValueError(f"Unsupported file type '{suffix}'. Supported: {', '.join(_SUPPORTED)}")

    content = django_file.read()

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        if suffix == '.map':
            if detect_iar(content):
                return map_iar.parse(tmp_path)
            return map_gcc.parse(tmp_path)
        else:
            return elf_parser.parse(tmp_path)
    except Exception as e:
        raise ValueError(f"Failed to parse {filename}: {e}") from e
    finally:
        tmp_path.unlink(missing_ok=True)


def _mmap_to_json(mmap, warnings) -> dict:
    sec_type_map = {sec.name: sec.section_type.value for sec in mmap.sections}

    sections = [
        {
            'name': sec.name,
            'size': sec.size,
            'type': sec.section_type.value,
            'color': _SECTION_COLORS.get(sec.section_type, '#505060'),
            'address': sec.address,
            'vma': sec.vma,
            'lma': sec.lma,
        }
        for sec in sorted(mmap.sections, key=lambda s: s.size, reverse=True)
        if sec.size > 0
    ]

    symbols = [
        {
            'name': s.name,
            'demangled': demangle(s.name) if is_mangled(s.name) else s.name,
            'size': s.size,
            'section': s.section,
            'type': sec_type_map.get(s.section, 'other'),
            'object_file': s.object_file,
            'library': s.library or '',
            'source_location': s.source_location or '',
        }
        for s in sorted(mmap.all_symbols, key=lambda x: x.size, reverse=True)
    ]

    regions = []
    for r in mmap.regions:
        if r.length > 0:
            regions.append({
                'name': r.name,
                'used': r.used,
                'length': r.length,
                'pct': round(r.used / r.length * 100, 1),
                'used_human': _human_bytes(r.used),
                'length_human': _human_bytes(r.length),
            })

    warn_list = [
        {
            'level': w.level,
            'message': w.message,
            'how_to_fix': w.how_to_fix,
            'symbol': w.symbol,
            'size': w.size,
        }
        for w in warnings
    ]

    return {
        'filename': Path(mmap.source_file).name,
        'total_flash': mmap.total_flash,
        'total_ram': mmap.total_ram,
        'total_flash_human': _human_bytes(mmap.total_flash),
        'total_ram_human': _human_bytes(mmap.total_ram),
        'section_count': len(mmap.sections),
        'symbol_count': len(mmap.all_symbols),
        'sections': sections,
        'symbols': symbols,
        'regions': regions,
        'warnings': warn_list,
        'treemap': _build_treemap_data(mmap),
        'binary_info': mmap.binary_info or {},
        'insights': compute_insights(mmap),
        'libraries': [
            {
                'name': lib.name,
                'category': lib.category,
                'flash_bytes': lib.flash_bytes,
                'flash_human': _human_bytes(lib.flash_bytes),
                'symbol_count': lib.symbol_count,
                'url': lib.url,
            }
            for lib in detect_libraries(mmap)
        ],
    }


def _mmap_from_history(build_id: int, user_id: str) -> MemoryMap:
    """Reconstruct a MemoryMap from a stored history build owned by user_id."""
    rec = hist.get_build(build_id, user_id=user_id)
    if rec is None:
        raise ValueError(f'Build {build_id} not found')
    analysis = rec.get('analysis')
    if not analysis:
        raise ValueError(f'Build {build_id} has no stored analysis data')

    syms_by_section = defaultdict(list)
    for s in analysis.get('symbols', []):
        syms_by_section[s['section']].append(Symbol(
            name=s['name'], size=s['size'], address=0,
            section=s['section'], object_file=s.get('object_file', ''),
            library=s.get('library') or None,
            source_location=s.get('source_location') or None,
        ))

    sections = [
        Section(
            name=sd['name'], size=sd['size'], address=0,
            section_type=SectionType(sd['type']),
            symbols=syms_by_section.get(sd['name'], []),
        )
        for sd in analysis.get('sections', [])
    ]

    regions = [
        MemoryRegion(name=r['name'], origin=0, length=r['length'], used=r['used'])
        for r in analysis.get('regions', [])
    ]

    return MemoryMap(
        source_file=rec['source_file'],
        toolchain=rec.get('toolchain', 'unknown'),
        target=None,
        sections=sections,
        regions=regions,
    )



# ── Public web views ───────────────────────────────────────────────────────────

def landing(request):
    if request.user.is_authenticated:
        user = request.user
        display_name = user.get_full_name() or user.username or user.email or 'there'
        first_name = display_name.split()[0] if display_name else 'there'
        is_authenticated = True
    else:
        first_name = ''
        is_authenticated = False
    resp = render(request, 'landing.html', {
        'version': __version__,
        'asset_version': _asset_version(),
        'is_authenticated': is_authenticated,
        'first_name': first_name,
    })
    resp['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp['Pragma'] = 'no-cache'
    resp['Expires'] = '0'
    return resp


def privacy(request):
    return render(request, 'privacy.html')


def terms(request):
    return render(request, 'terms.html')


def docs(request):
    return render(request, 'docs.html')


def pricing(request):
    return render(request, 'pricing.html', {
        'is_authenticated': request.user.is_authenticated,
    })


def login_view(request):
    """Render the login page. If already logged in, redirect to /app."""
    if request.user.is_authenticated:
        next_url = request.GET.get('next', '/app')
        # Validate next is a safe relative URL
        if not next_url.startswith('/') or next_url.startswith('//'):
            next_url = '/app'
        return redirect(next_url)
    next_url = request.GET.get('next', '/app')
    if not next_url.startswith('/') or next_url.startswith('//'):
        next_url = '/app'
    return render(request, 'login.html', {
        'version': __version__,
        'asset_version': _asset_version(),
        'next_url': next_url,
        'csrf_token': csrf_get_token(request),  # needed for the OAuth POST forms
    })


def logout_view(request):
    """POST-only logout. GET requests just redirect to home."""
    if request.method == 'POST':
        auth_logout(request)
    return redirect('/')


# ── Account deletion ──────────────────────────────────────────────────────────
# Two-step flow:
#   GET  /account/delete  → confirmation page listing what will be removed
#   POST /account/delete  → actually delete everything, log out, redirect home
#
# What gets deleted (every byte of user data we hold):
#
#   memprobe (pg)      DELETE FROM builds  WHERE user_id = ?
#                      DELETE FROM shares  WHERE user_id = ?
#
#   Django (pg)        DELETE FROM auth_user                              (cascades to)
#                       └─ auth_user_groups
#                       └─ auth_user_user_permissions
#                       └─ account_emailaddress        (cascades to account_emailconfirmation)
#                       └─ socialaccount_socialaccount (cascades to socialaccount_socialtoken)
#                      DELETE FROM django_session WHERE _auth_user_id matches
#                       - sessions are NOT FK'd to User, so we walk them manually
#                         to log the user out everywhere (all devices)
#
# Re-runnable: every step is idempotent. If a partial failure happens
# (e.g. memprobe.db locked), the worst case is some orphaned rows that match
# no live user - they won't leak data and can be re-cleaned by re-running.


def _revoke_oauth_grant(social_account) -> bool:
    """Best-effort: revoke the user's OAuth grant at the provider.

    After this call, the provider will require the user to re-authorize
    (re-consent) the next time they click "Continue with Google/GitHub":
    avoiding the confusing "auto sign-in after deletion" experience.

    Returns True if the revocation appears to have succeeded. Failures are
    LOGGED but NOT raised: deletion proceeds regardless, since cleaning up
    our own records is more important than the remote revocation succeeding.

    We use the standard library's urllib so we don't pull in `requests`
    just for one HTTP call. Both endpoints accept a brief request.
    """
    import os
    import ssl
    import logging
    import urllib.request
    import urllib.parse
    import urllib.error
    from base64 import b64encode
    from allauth.socialaccount.models import SocialToken

    log = logging.getLogger(__name__)
    provider = social_account.provider

    # macOS Python.org builds don't trust the system keychain; use certifi
    # for a portable, up-to-date CA bundle that works the same in dev and prod.
    try:
        import certifi
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ssl_ctx = ssl.create_default_context()

    token = SocialToken.objects.filter(account=social_account).first()
    if not token or not token.token:
        # No token stored: happens when account predates SOCIALACCOUNT_STORE_TOKENS=True,
        # or token was already cleared. We can't revoke without it.
        log.warning(
            "Cannot revoke %s grant for user %s: no stored OAuth token. "
            "User should manually revoke at the provider.",
            provider, social_account.user_id,
        )
        return False

    try:
        if provider == 'google':
            # Google: POST https://oauth2.googleapis.com/revoke?token=ACCESS_TOKEN
            # https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke
            url = 'https://oauth2.googleapis.com/revoke'
            data = urllib.parse.urlencode({'token': token.token}).encode()
            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            req.add_header('User-Agent', 'memprobe-app')
            urllib.request.urlopen(req, timeout=5, context=ssl_ctx).read()
            log.info("Revoked Google OAuth grant for user %s", social_account.user_id)
            return True

        if provider == 'github':
            # GitHub: DELETE /applications/{client_id}/grant: revokes the
            # entire authorization grant (not just the token).
            # https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-authorization
            #
            # GitHub REQUIRES a User-Agent header on every request, and uses
            # HTTP Basic auth with the OAuth app's client_id:client_secret.
            client_id = os.environ.get('GITHUB_CLIENT_ID', '')
            client_secret = os.environ.get('GITHUB_CLIENT_SECRET', '')
            if not client_id or not client_secret:
                log.error("GITHUB_CLIENT_ID/SECRET missing: cannot revoke grant")
                return False
            url = f'https://api.github.com/applications/{client_id}/grant'
            body = json.dumps({'access_token': token.token}).encode()
            req = urllib.request.Request(url, data=body, method='DELETE')
            req.add_header('Accept', 'application/vnd.github+json')
            req.add_header('X-GitHub-Api-Version', '2022-11-28')
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'memprobe-app')
            credentials = b64encode(f'{client_id}:{client_secret}'.encode()).decode()
            req.add_header('Authorization', f'Basic {credentials}')
            urllib.request.urlopen(req, timeout=5, context=ssl_ctx).read()
            log.info("Revoked GitHub OAuth grant for user %s", social_account.user_id)
            return True

    except urllib.error.HTTPError as e:
        # 404 from GitHub = grant already revoked (user revoked manually,
        # or token already invalidated). Treat as success.
        if provider == 'github' and e.code == 404:
            log.info("GitHub grant for user %s was already revoked", social_account.user_id)
            return True
        # Log the actual response body so we can see WHY it failed.
        try:
            err_body = e.read().decode(errors='replace')[:500]
        except Exception:
            err_body = '<unreadable>'
        log.error(
            "Failed to revoke %s grant (HTTP %s): %s",
            provider, e.code, err_body,
        )
        return False
    except Exception as e:
        log.error("Failed to revoke %s grant: %s", provider, e)
        return False

    return False


def _kill_all_sessions_for(user_id: str) -> int:
    """Delete every active session that authenticates as this user_id.

    Django sessions store the authenticated user PK in encrypted blob data;
    they're not foreign-keyed, so we iterate. Linear in active-session count.
    Acceptable for our scale (sessions auto-expire too).
    """
    from django.contrib.sessions.models import Session
    from django.utils import timezone

    killed = 0
    qs = Session.objects.filter(expire_date__gte=timezone.now())
    for session in qs.iterator():
        try:
            data = session.get_decoded()
        except Exception:
            # Tampered or unreadable session - skip it (it can't auth anyway)
            continue
        if str(data.get('_auth_user_id', '')) == str(user_id):
            session.delete()
            killed += 1
    return killed


@web_login_required
@require_http_methods(['GET', 'POST'])
def delete_account(request):
    if request.method == 'GET':
        return render(request, 'delete_account.html', {
            'user': request.user,
            'csrf_token': csrf_get_token(request),
        })

    # POST: actually delete. Require explicit confirmation to avoid accidents.
    expected = f"delete {request.user.email}"
    if request.POST.get('confirm', '').strip() != expected:
        return render(request, 'delete_account.html', {
            'user': request.user,
            'csrf_token': csrf_get_token(request),
            'error': 'Confirmation phrase did not match. Please try again.',
        })

    user = request.user
    user_id = _uid(request)

    # 1. Revoke the OAuth grant at each provider FIRST, while we still have
    # the SocialAccount + SocialToken in the DB. Without this, a returning
    # user sees no re-consent prompt because Google/GitHub remembers the
    # authorization. Best-effort: any failure is logged, deletion proceeds.
    from allauth.socialaccount.models import SocialAccount
    for sa in SocialAccount.objects.filter(user=user):
        _revoke_oauth_grant(sa)

    # 2. Purge memprobe data (no FK to Django models)
    try:
        hist.delete_all_for_user(user_id)
    except Exception:
        # Best-effort. Re-running deletion is idempotent so a partial state
        # can be recovered. We continue so the Django side still gets cleaned.
        pass

    # 3. Kill ALL active sessions for this user (logs them out on every device).
    # Must happen BEFORE deleting the User row, since the current session
    # itself counts. Doing it after auth_logout() would still leave any
    # other-device sessions orphaned with a dangling user_id.
    _kill_all_sessions_for(user_id)

    # 4. Log out the current request (clears the response cookie)
    auth_logout(request)

    # 5. Delete the Django user. FK cascades remove:
    #      - SocialAccount + SocialToken
    #      - EmailAddress + EmailConfirmation
    #      - group/permission memberships
    user.delete()

    return redirect('/?deleted=1')


# ── App view (guests allowed, authenticated users get full access) ─────────────

def index(request):
    if request.user.is_authenticated:
        user = request.user
        display_name = user.get_full_name() or user.username or user.email or 'there'
        first_name = display_name.split()[0] if display_name else 'there'
        is_authenticated = True
    else:
        first_name = ''
        is_authenticated = False
    resp = render(request, 'ui.html', {
        'version': __version__,
        'asset_version': _asset_version(),
        'first_name': first_name,
        'is_authenticated': is_authenticated,
        'is_pro': _is_pro(request.user) if request.user.is_authenticated else False,
        'max_builds': MAX_BUILDS,
        'max_projects': MAX_PROJECTS,
        'csrf_token': csrf_get_token(request),
    })
    resp['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp['Pragma'] = 'no-cache'
    resp['Expires'] = '0'
    return resp


# ── Protected API views ────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST'])
@_rate_limit(max_calls=20, window_seconds=60)
def api_analyze(request):
    # Guests are allowed exactly one analysis per session
    if not request.user.is_authenticated:
        if request.session.get('guest_analyzed'):
            return JsonResponse(
                {'error': 'Sign in to analyze more files and save your history.'},
                status=403,
            )
        request.session['guest_analyzed'] = True

    if 'file' not in request.FILES:
        return HttpResponseBadRequest(
            json.dumps({'error': 'No file uploaded'}),
            content_type='application/json',
        )
    try:
        mmap = _load_upload(request.FILES['file'])
    except ValueError as e:
        return HttpResponseBadRequest(
            json.dumps({'error': str(e)}),
            content_type='application/json',
        )

    mmap.source_file = request.FILES['file'].name or mmap.source_file
    try:
        warnings = bloat_analyze(mmap)
        result = _mmap_to_json(mmap, warnings)
    except Exception as e:
        import traceback, logging
        logging.getLogger(__name__).error('Analysis failed: %s', traceback.format_exc())
        return JsonResponse({'error': f'Analysis failed: {e}'}, status=500)

    # Only save to history for authenticated users
    if request.user.is_authenticated:
        project = request.POST.get('project', '').strip() or None
        result['project'] = project
        uid = _uid(request)

        # Enforce project cap
        if project:
            existing_projects = hist.list_projects(user_id=uid)
            if project not in existing_projects and len(existing_projects) >= MAX_PROJECTS:
                return JsonResponse(
                    {'error': f'Free accounts are limited to {MAX_PROJECTS} projects. Delete one to continue.'},
                    status=403,
                )

        # Enforce total build history cap (10 across all projects)
        all_builds = hist.list_builds(user_id=uid)
        if len(all_builds) >= MAX_BUILDS:
            return JsonResponse(
                {'error': f'You have reached the {MAX_BUILDS}-build limit. Delete a build from your history to continue.'},
                status=403,
            )

        try:
            build_id = hist.save(mmap, user_id=uid, analysis_json=result, project=project)
            result['build_id'] = build_id
        except Exception:
            pass

    return JsonResponse(result)


def _resolve_side(request, side: str) -> MemoryMap:
    """Load one side of a diff from either an uploaded file or a history build ID."""
    id_key   = f'{side}_id'
    file_key = f'{side}_file'

    if id_key in request.POST:
        build_id = int(request.POST[id_key])
        return _mmap_from_history(build_id, user_id=_uid(request))

    if file_key in request.FILES:
        mmap = _load_upload(request.FILES[file_key])
        mmap.source_file = request.FILES[file_key].name or mmap.source_file
        return mmap

    raise ValueError(
        f"Provide either '{id_key}' (history build ID) or '{file_key}' (file upload) for the {side} build."
    )


@csrf_exempt
@require_http_methods(['POST'])
@api_login_required
def api_diff(request):
    try:
        old_mmap = _resolve_side(request, 'old')
        new_mmap = _resolve_side(request, 'new')
    except ValueError as e:
        return HttpResponseBadRequest(
            json.dumps({'error': str(e)}),
            content_type='application/json',
        )

    # Refuse mixed-type comparisons (.elf vs .map etc).
    def _canon(p: str) -> str:
        s = Path(p or '').suffix.lower()
        return '.elf' if s == '.axf' else s
    old_t = _canon(old_mmap.source_file)
    new_t = _canon(new_mmap.source_file)
    if old_t and new_t and old_t != new_t:
        return HttpResponseBadRequest(
            json.dumps({'error':
                'Both builds must be the same file type. '
                f'Got {Path(old_mmap.source_file).suffix.lower() or "?"} vs '
                f'{Path(new_mmap.source_file).suffix.lower() or "?"}. '
                'ELF (.elf/.axf) and linker map (.map) files cannot be compared.'
            }),
            content_type='application/json',
        )

    build_diff = compute_diff(old_mmap, new_mmap)

    sym_sec: dict[str, str] = {}
    for sec in old_mmap.sections:
        for sym in sec.symbols:
            sym_sec[sym.name] = sec.name
    for sec in new_mmap.sections:
        for sym in sec.symbols:
            sym_sec[sym.name] = sec.name

    return JsonResponse({
        'old_filename': Path(old_mmap.source_file).name,
        'new_filename': Path(new_mmap.source_file).name,
        'flash_delta': build_diff.flash_delta,
        'ram_delta': build_diff.ram_delta,
        'flash_delta_human': _human_bytes(abs(build_diff.flash_delta)),
        'ram_delta_human': _human_bytes(abs(build_diff.ram_delta)),
        'old_flash_human': _human_bytes(old_mmap.total_flash),
        'new_flash_human': _human_bytes(new_mmap.total_flash),
        'old_ram_human': _human_bytes(old_mmap.total_ram),
        'new_ram_human': _human_bytes(new_mmap.total_ram),
        'diffs': [
            {
                'name': d.name,
                'object_file': d.object_file,
                'old_size': d.old_size,
                'new_size': d.new_size,
                'delta': d.delta,
                'kind': 'added' if d.old_size == 0 else 'removed' if d.new_size == 0 else 'changed',
                'section': sym_sec.get(d.name, ''),
            }
            for d in build_diff.symbol_diffs
        ],
    })


@csrf_exempt
@api_login_required
def api_history(request):
    if request.method == 'GET':
        builds = hist.list_builds(user_id=_uid(request))
        return JsonResponse(
            [{**b, 'basename': Path(b['source_file']).name} for b in builds],
            safe=False,
        )
    if request.method == 'DELETE':
        hist.clear(user_id=_uid(request))
        return JsonResponse({'ok': True})
    return HttpResponse(status=405)


@api_login_required
def api_history_trend(request):
    project = request.GET.get('project', '').strip()
    source  = request.GET.get('source',  '').strip()
    rows = hist.get_trend(
        user_id=_uid(request),
        project=project or None,
        source_file=source or None,
    )
    return JsonResponse(rows, safe=False)


@api_login_required
def api_projects(request):
    return JsonResponse(hist.list_projects(user_id=_uid(request)), safe=False)


@api_login_required
def api_project_summaries(request):
    return JsonResponse(hist.list_project_summaries(user_id=_uid(request)), safe=False)


@api_login_required
def api_projects_full(request):
    """Rich per-project view: stats + saved settings (budgets, description)."""
    return JsonResponse(hist.list_projects_full(user_id=_uid(request)), safe=False)


def _project_name_from_path(name: str) -> str:
    """Decode and validate a project name from the URL."""
    from urllib.parse import unquote
    decoded = unquote(name or '').strip()
    if not decoded or len(decoded) > 200:
        raise ValueError('Invalid project name.')
    return decoded


@csrf_exempt
@require_http_methods(['GET', 'POST', 'PATCH', 'DELETE'])
@api_login_required
def api_project_detail(request, project_name: str):
    """Project settings: read, create, update, or delete the project entirely."""
    try:
        name = _project_name_from_path(project_name)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    uid = _uid(request)

    if request.method == 'GET':
        settings = hist.get_project_settings(user_id=uid, project=name) or {}
        return JsonResponse({'project': name, **settings})

    if request.method == 'DELETE':
        result = hist.delete_project(user_id=uid, project=name)
        return JsonResponse({'ok': True, **result})

    # POST: create a new empty project (enforces project cap)
    if request.method == 'POST':
        existing = hist.list_projects(user_id=uid)
        if name not in existing and len(existing) >= MAX_PROJECTS:
            return JsonResponse(
                {'error': f'Free accounts are limited to {MAX_PROJECTS} projects. Delete one to continue.'},
                status=403,
            )
        saved = hist.save_project_settings(user_id=uid, project=name)
        return JsonResponse({'project': name, **saved})

    # PATCH: update settings
    try:
        body = json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    def _opt_int(key):
        if key not in body or body[key] in (None, ''):
            return None
        try:
            v = int(body[key])
            if v < 0:
                raise ValueError
            return v
        except (TypeError, ValueError):
            return False  # sentinel for invalid

    flash = _opt_int('flash_budget_bytes')
    ram   = _opt_int('ram_budget_bytes')
    if flash is False or ram is False:
        return JsonResponse({'error': 'Budgets must be non-negative integers (bytes).'}, status=400)

    description = body.get('description')
    if description is not None:
        description = str(description).strip()[:1000] or None

    saved = hist.save_project_settings(
        user_id=uid, project=name,
        flash_budget_bytes=flash,
        ram_budget_bytes=ram,
        description=description,
    )
    return JsonResponse({'project': name, **saved})


@csrf_exempt
@require_http_methods(['DELETE'])
@api_login_required
def api_history_delete(request, build_id: int):
    deleted = hist.delete_build(build_id, user_id=_uid(request))
    if not deleted:
        return JsonResponse({'error': 'Build not found'}, status=404)
    return JsonResponse({'ok': True})


@api_login_required
def api_history_build(request, build_id: int):
    build = hist.get_build(build_id, user_id=_uid(request))
    if build is None:
        return JsonResponse({'error': 'Build not found'}, status=404)
    if not build.get('analysis'):
        return JsonResponse({'error': 'No analysis data stored for this build'}, status=404)
    return JsonResponse(build['analysis'])


@csrf_exempt
@require_http_methods(['POST'])
@api_login_required
def api_compare(request):
    mmaps = []
    i = 0
    while True:
        file_key = f'file_{i}'
        id_key   = f'id_{i}'
        if file_key in request.FILES:
            try:
                mmap = _load_upload(request.FILES[file_key])
                mmap.source_file = request.FILES[file_key].name or mmap.source_file
            except ValueError as e:
                return HttpResponseBadRequest(
                    json.dumps({'error': str(e)}),
                    content_type='application/json',
                )
            mmaps.append(mmap)
        elif id_key in request.POST:
            try:
                mmap = _mmap_from_history(int(request.POST[id_key]), user_id=_uid(request))
            except ValueError as e:
                return HttpResponseBadRequest(
                    json.dumps({'error': str(e)}),
                    content_type='application/json',
                )
            mmaps.append(mmap)
        else:
            break
        i += 1

    if len(mmaps) < 2:
        return HttpResponseBadRequest(
            json.dumps({'error': 'Provide at least two targets (file_0/id_0, file_1/id_1, ...)'}),
            content_type='application/json',
        )

    # Enforce: all targets must share the same file type. Comparing a .elf
    # against a .map (or .axf vs .map) is meaningless because the data shapes
    # don't line up the same way (symbol coverage, address vs offset, etc).
    suffixes = {Path(m.source_file).suffix.lower() for m in mmaps if m.source_file}
    # Treat .elf and .axf as the same family (both ELF-format).
    norm = {'.axf': '.elf'}
    canonical = {norm.get(s, s) for s in suffixes}
    if len(canonical) > 1:
        return HttpResponseBadRequest(
            json.dumps({'error':
                'All compared builds must be the same file type. '
                f'Got mixed types: {", ".join(sorted(suffixes))}. '
                'ELF (.elf/.axf) and linker map (.map) files cannot be compared against each other.'
            }),
            content_type='application/json',
        )

    all_sections: dict[str, None] = {}
    for mmap in mmaps:
        for sec in mmap.sections:
            if sec.size > 0:
                all_sections[sec.name] = None

    targets = []
    for mmap in mmaps:
        sec_lookup = {s.name: s for s in mmap.sections}
        section_rows = []
        for sec_name in all_sections:
            sec = sec_lookup.get(sec_name)
            section_rows.append({
                'name':  sec_name,
                'size':  sec.size if sec else 0,
                'type':  sec.section_type.value if sec else 'other',
                'color': _SECTION_COLORS.get(sec.section_type, '#505060') if sec else '#505060',
            })

        top_syms = sorted(mmap.all_symbols, key=lambda s: s.size, reverse=True)[:20]

        targets.append({
            'name':              Path(mmap.source_file).name,
            'total_flash':       mmap.total_flash,
            'total_ram':         mmap.total_ram,
            'total_flash_human': _human_bytes(mmap.total_flash),
            'total_ram_human':   _human_bytes(mmap.total_ram),
            'sections':          section_rows,
            'top_symbols': [
                {
                    'name':        s.name,
                    'size':        s.size,
                    'section':     s.section,
                    'object_file': s.object_file,
                }
                for s in top_syms
            ],
            'regions': [
                {
                    'name':         r.name,
                    'used':         r.used,
                    'length':       r.length,
                    'pct':          round(r.used / r.length * 100, 1) if r.length else 0,
                    'used_human':   _human_bytes(r.used),
                    'length_human': _human_bytes(r.length),
                }
                for r in mmap.regions if r.length > 0
            ],
        })

    # Aggregate by (name, section) and sum sizes for duplicates so two parses
    # of identical files always produce identical totals per (name, section).
    # See memprobe.diff._aggregate for the rationale.
    all_sym_keys: dict[tuple[str, str], None] = {}
    sym_tables: list[dict[tuple[str, str], int]] = []
    for mmap in mmaps:
        tbl: dict[tuple[str, str], int] = {}
        for s in mmap.all_symbols:
            key = (s.name, s.section)
            tbl[key] = tbl.get(key, 0) + s.size
        sym_tables.append(tbl)
        for k in tbl:
            all_sym_keys[k] = None

    differing = []
    for key in all_sym_keys:
        sizes = [tbl.get(key, 0) for tbl in sym_tables]
        if len(set(sizes)) > 1:
            differing.append({'name': key[0], 'sizes': sizes})

    differing.sort(key=lambda x: max(x['sizes']) - min(x['sizes']), reverse=True)

    return JsonResponse({
        'targets':           targets,
        'all_sections':      list(all_sections.keys()),
        'differing_symbols': differing[:100],
    })


# ── Share ──────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(['POST'])
@api_login_required
@_rate_limit(max_calls=30, window_seconds=60)
def api_share(request):
    """Save an analysis result and return a short share ID."""
    try:
        body = json.loads(request.body)
        analysis = body.get('analysis')
        filename = body.get('filename', 'firmware')
        if not analysis:
            return HttpResponseBadRequest(
                json.dumps({'error': 'Missing analysis payload'}),
                content_type='application/json',
            )
        share_id = secrets.token_hex(_SHARE_ID_BYTES)
        # Record creator's user_id so the share is purged with their account.
        # The share link itself remains publicly readable until deletion.
        hist.save_share(share_id, filename, json.dumps(analysis), user_id=_uid(request))
        return JsonResponse({'id': share_id})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def share_view(request, share_id: str):
    """Render a read-only shared analysis page. Public - no login required."""
    record = hist.get_share(share_id)
    if not record:
        return HttpResponse(
            '<html><body>Share link not found or expired.</body></html>',
            status=404, content_type='text/html',
        )
    # Django's |json_script template filter handles HTML-safe JSON embedding
    # (escapes </script>, etc.), so we pass the dict directly.
    return render(request, 'share.html', {
        'version': __version__,
        'asset_version': _asset_version(),
        'share_id': share_id,
        'filename': record['filename'],
        'created_at': record['created_at'][:10],
        'analysis_data': record['data'],
    })
