"""Django views for the memprobe web UI."""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import tempfile
import threading
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path

logger = logging.getLogger(__name__)

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

# Modal remote parser — only active when USE_MODAL=true.
# Function handles are resolved lazily on first use per tier so a slow Modal
# API never stalls gunicorn worker startup.
_USE_MODAL = os.environ.get('USE_MODAL', '').lower() in ('1', 'true', 'yes')

# Retry order — if a tier times out (OOM) we step to the next one.
_MODAL_TIERS = ['xs', 'sm', 'md', 'lg']
_modal_fns: dict[str, object] = {}  # populated lazily on first use per tier


def _modal_fn(key: str):
    """Return (and cache) the Modal function handle for the given tier key."""
    if key not in _modal_fns:
        try:
            import modal as _modal
            _modal_fns[key] = _modal.Function.from_name(
                'memprobe-parser', f'parse_file_{key}'
            )
        except Exception as exc:
            logger.warning('Modal unavailable (%s): %s', key, exc)
            return None
    return _modal_fns[key]


def _pick_tier(file_size: int) -> str:
    """Pick the smallest Modal tier that fits the estimated RAM for file_size.

    Formula: ceil(file_size_mb * 9.4 * 1.3), mapped to tiers:
      xs=128 MB, sm=300 MB, md=512 MB, lg=1024 MB
    """
    import math
    est = max(128, math.ceil((file_size / (1024 * 1024)) * 9.4 * 1.3))
    if est <= 128:
        return 'xs'
    if est <= 512:
        return 'sm'
    if est <= 768:
        return 'md'
    return 'lg'
from .models import AnalysisJob
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
            if request.user.is_authenticated:
                key = str(request.user.pk)
            else:
                # Use the rightmost X-Forwarded-For entry, which is appended by
                # Render's edge proxy and cannot be spoofed by the client.
                # The leftmost entry is attacker-controlled and must never be trusted.
                fwd = request.META.get('HTTP_X_FORWARDED_FOR', '')
                key = fwd.split(',')[-1].strip() if fwd else request.META.get('REMOTE_ADDR', 'unknown')
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
    """Parse an uploaded file into a MemoryMap.

    With FILE_UPLOAD_MAX_MEMORY_SIZE=0 Django always gives us a
    TemporaryUploadedFile whose bytes are already on disk, so we can
    parse directly from that path without any extra copy. For the rare
    in-memory case (e.g. tests) we stream to a temp file instead of
    reading the entire content into RAM first.
    """
    if django_file.size > MAX_UPLOAD_BYTES:
        raise ValueError(f"File too large ({django_file.size // (1024*1024)} MB). Maximum is 30 MB.")

    filename = django_file.name or 'firmware'
    suffix = Path(filename).suffix.lower()
    if suffix not in _SUPPORTED:
        raise ValueError(f"Unsupported file type '{suffix}'. Supported: {', '.join(_SUPPORTED)}")

    # If Django already wrote the upload to disk, use that path directly.
    if hasattr(django_file, 'temporary_file_path'):
        tmp_path = Path(django_file.temporary_file_path())
        owned = False  # Django manages cleanup
    else:
        # In-memory fallback: stream to a temp file without reading all bytes at once.
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            django_file.seek(0)
            shutil.copyfileobj(django_file, tmp)
            tmp_path = Path(tmp.name)
        owned = True

    try:
        if suffix == '.map':
            # Read only a small header for IAR detection — avoids loading the whole file.
            with open(tmp_path, 'rb') as fh:
                header = fh.read(4096)
            if detect_iar(header):
                return map_iar.parse(tmp_path)
            return map_gcc.parse(tmp_path)
        else:
            return elf_parser.parse(tmp_path)
    except Exception as e:
        raise ValueError(f"Failed to parse {filename}: {e}") from e
    finally:
        if owned:
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


def _call_modal_fn(fn, compressed: bytes, filename: str, on_progress) -> dict | None:
    """Call a Modal function, handling both generator (new) and blocking (old) workers.

    Returns the raw result dict, or None if no result was produced.
    Raises ValueError for parse errors, lets other exceptions propagate.
    """
    # Try generator path first (new worker with progress reporting).
    # If remote_gen isn't supported or the worker isn't a generator, fall
    # back to the blocking remote() call automatically.
    result = None
    gen_worked = False

    try:
        for event in fn.remote_gen(compressed, filename):
            gen_worked = True
            stage = event.get('stage', '')
            if stage == 'error':
                logger.error('Modal parse error (gen): %s\n%s', event.get('error'), event.get('traceback', ''))
                raise ValueError('Could not parse file. Check that it is a valid ELF or linker map.')
            if on_progress and 'progress' in event:
                try:
                    on_progress(event['progress'], stage)
                except Exception:
                    pass
            if stage == 'done':
                result = event['result']
                break
            # Old non-generator worker returns a single plain dict — detect and handle it.
            if 'sections' in event and stage == '':
                result = event
                break
    except ValueError:
        raise
    except Exception as exc:
        if gen_worked:
            # Generator started but blew up mid-stream — real error.
            raise
        # remote_gen itself failed before yielding anything — worker is old, fall back.
        logger.warning('remote_gen failed for %s, falling back to remote(): %s', filename, exc)
        raw = fn.remote(compressed, filename)
        if raw and 'error' in raw:
            logger.error('Modal parse error (remote): %s\n%s', raw['error'], raw.get('traceback', ''))
            raise ValueError('Could not parse file. Check that it is a valid ELF or linker map.')
        result = raw

    return result


def _analyze_via_modal(
    file_bytes: bytes,
    filename: str,
    file_size: int,
    on_progress=None,
) -> MemoryMap:
    """Call Modal to parse the file, retrying with larger tiers on OOM/timeout.

    on_progress(fraction, stage) is called for each progress event from the
    Modal generator. fraction is 0.0-1.0.

    Raises ValueError on parse errors or if all tiers are exhausted.
    """
    try:
        from modal.exception import FunctionTimeoutError
    except ImportError:
        FunctionTimeoutError = Exception  # fallback if Modal API changes

    import time as _time
    import zlib as _zlib

    compressed = _zlib.compress(file_bytes, level=1)
    start_tier = _pick_tier(file_size)
    tiers_to_try = _MODAL_TIERS[_MODAL_TIERS.index(start_tier):]

    for tier in tiers_to_try:
        fn = _modal_fn(tier)
        if fn is None:
            raise ValueError('Modal is not available. Try again later.')

        logger.info(
            'Modal parse: %s, tier=%s, file_size=%d bytes (compressed: %d bytes, %.1fx)',
            filename, tier, file_size, len(compressed), file_size / max(len(compressed), 1),
        )
        t_call = _time.monotonic()
        result = None
        try:
            result = _call_modal_fn(fn, compressed, filename, on_progress)
        except FunctionTimeoutError:
            logger.warning('Modal OOM/timeout: %s tier=%s — retrying', filename, tier)
            continue
        except ValueError:
            raise
        except Exception as exc:
            logger.error('Modal call failed: %s tier=%s — %s: %s', filename, tier, type(exc).__name__, exc, exc_info=True)
            raise ValueError('Analysis failed. Please try again later.') from exc

        if result is None:
            raise ValueError('Could not parse file. Check that it is a valid ELF or linker map.')

        round_trip_s = round(_time.monotonic() - t_call, 2)
        peak_mb = result.get('peak_ram_mb')
        timings = result.get('timings', {})
        logger.info(
            'Modal parse complete: %s tier=%s peak_ram=%.1f MB allocated=%s MB '
            'round_trip=%.1fs (transfer=%.1fs parse=%.1fs serialize=%.1fs)',
            filename, tier, peak_mb or 0,
            {'xs': 128, 'sm': 512, 'md': 768, 'lg': 1024}[tier],
            round_trip_s,
            round_trip_s - timings.get('total_s', 0),
            timings.get('parse_s', 0),
            timings.get('serialize_s', 0),
        )

        return _mmap_from_modal(result, filename)

    raise ValueError('File requires more memory than available. Try a smaller or stripped binary.')


def _mmap_from_modal(data: dict, filename: str) -> MemoryMap:
    """Reconstruct a MemoryMap from the dict returned by the Modal worker."""
    sections = []
    for sd in data.get('sections', []):
        symbols = [
            Symbol(
                name=s['name'],
                size=s['size'],
                address=s.get('address', 0),
                section=s['section'],
                object_file=s.get('object_file', ''),
                library=s.get('library') or None,
                source_location=s.get('source_location') or None,
            )
            for s in sd.get('symbols', [])
        ]
        sections.append(Section(
            name=sd['name'],
            size=sd['size'],
            address=sd.get('address', 0),
            section_type=SectionType(sd['type']),
            symbols=symbols,
            vma=sd.get('vma', 0),
            lma=sd.get('lma', 0),
        ))

    regions = [
        MemoryRegion(
            name=r['name'],
            origin=r.get('origin', 0),
            length=r['length'],
            used=r.get('used', 0),
        )
        for r in data.get('regions', [])
    ]

    return MemoryMap(
        source_file=data.get('source_file', filename),
        toolchain=data.get('toolchain', 'unknown'),
        target=data.get('target'),
        sections=sections,
        regions=regions,
        binary_info=data.get('binary_info') or None,
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


def sitemap(request):
    pages = [
        ('https://memprobe.dev/', '1.0', 'weekly'),
        ('https://memprobe.dev/docs', '0.9', 'monthly'),
        ('https://memprobe.dev/pricing', '0.7', 'monthly'),
        ('https://memprobe.dev/privacy', '0.3', 'yearly'),
        ('https://memprobe.dev/terms', '0.3', 'yearly'),
    ]
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for loc, priority, freq in pages:
        lines.append(
            f'  <url><loc>{loc}</loc>'
            f'<changefreq>{freq}</changefreq>'
            f'<priority>{priority}</priority></url>'
        )
    lines.append('</urlset>')
    return HttpResponse('\n'.join(lines), content_type='application/xml')


def robots(request):
    content = (
        'User-agent: *\n'
        'Allow: /\n'
        'Disallow: /api/\n'
        'Disallow: /app\n'
        'Disallow: /account/\n'
        '\n'
        'Sitemap: https://memprobe.dev/sitemap.xml\n'
    )
    return HttpResponse(content, content_type='text/plain')


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


@require_http_methods(['POST'])
def logout_view(request):
    """POST-only logout. Enforces method so GET /logout cannot silently leave a session active."""
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
    # Use email if available, otherwise fall back to username.
    account_label = request.user.email or request.user.username or ''
    expected = f"delete {account_label}"
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


# ── Background analysis job helpers ───────────────────────────────────────────

def _run_analysis_job(job_id: str, file_bytes: bytes, filename: str,
                      file_size: int, user_id: str | None, project: str | None,
                      is_guest: bool, session_key: str | None) -> None:
    """Run the full analysis in a background thread and update AnalysisJob."""
    import django.db
    django.db.close_old_connections()

    try:
        job = AnalysisJob.objects.get(job_id=job_id)
        job.status = AnalysisJob.STATUS_RUNNING
        job.save(update_fields=['status', 'updated_at'])

        if _USE_MODAL:
            def _on_progress(frac: float, stage: str):
                try:
                    AnalysisJob.objects.filter(job_id=job_id).update(progress=round(frac, 3))
                except Exception:
                    pass  # progress updates are best-effort

            mmap = _analyze_via_modal(file_bytes, filename, file_size, on_progress=_on_progress)
        else:
            import io
            from django.core.files.uploadedfile import InMemoryUploadedFile
            fake_file = InMemoryUploadedFile(
                io.BytesIO(file_bytes), 'file', filename,
                'application/octet-stream', len(file_bytes), None,
            )
            mmap = _load_upload(fake_file)

        mmap.source_file = filename
        warnings = bloat_analyze(mmap)
        result = _mmap_to_json(mmap, warnings)

        if user_id:
            project_val = project
            result['project'] = project_val

            existing_projects = hist.list_projects(user_id=user_id)
            if project_val and project_val not in existing_projects and len(existing_projects) >= MAX_PROJECTS:
                job.status = AnalysisJob.STATUS_FAILED
                job.error_message = f'Free accounts are limited to {MAX_PROJECTS} projects. Delete one to continue.'
                job.save(update_fields=['status', 'error_message', 'updated_at'])
                return

            all_builds = hist.list_builds(user_id=user_id)
            if len(all_builds) >= MAX_BUILDS:
                job.status = AnalysisJob.STATUS_FAILED
                job.error_message = f'You have reached the {MAX_BUILDS}-build limit. Delete a build from your history to continue.'
                job.save(update_fields=['status', 'error_message', 'updated_at'])
                return

            try:
                build_id = hist.save(mmap, user_id=user_id, analysis_json=result, project=project_val)
                result['build_id'] = build_id
            except Exception as exc:
                logger.error('Failed to save build for user %s: %s', user_id, exc)

        job.result_json = json.dumps(result)
        job.status = AnalysisJob.STATUS_DONE
        job.save(update_fields=['status', 'result_json', 'updated_at'])

    except Exception as exc:
        logger.error('Background analysis job %s failed: %s', job_id, exc, exc_info=True)
        try:
            job = AnalysisJob.objects.get(job_id=job_id)
            job.status = AnalysisJob.STATUS_FAILED
            job.error_message = str(exc)[:512]
            job.save(update_fields=['status', 'error_message', 'updated_at'])
        except Exception:
            pass
    finally:
        django.db.close_old_connections()


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
    uploaded_file = request.FILES['file']
    filename = uploaded_file.name or 'firmware'
    uploaded_file.seek(0)
    file_bytes = uploaded_file.read()
    file_size = len(file_bytes)

    # Check limits before starting background job so we can reject synchronously.
    if request.user.is_authenticated:
        uid = _uid(request)
        project = request.POST.get('project', '').strip() or None

        if project:
            existing_projects = hist.list_projects(user_id=uid)
            if project not in existing_projects and len(existing_projects) >= MAX_PROJECTS:
                return JsonResponse(
                    {'error': f'Free accounts are limited to {MAX_PROJECTS} projects. Delete one to continue.'},
                    status=403,
                )

        all_builds = hist.list_builds(user_id=uid)
        if len(all_builds) >= MAX_BUILDS:
            return JsonResponse(
                {'error': f'You have reached the {MAX_BUILDS}-build limit. Delete a build from your history to continue.'},
                status=403,
            )
    else:
        uid = None
        project = None

    job_id = secrets.token_hex(16)
    AnalysisJob.objects.create(
        job_id=job_id,
        status=AnalysisJob.STATUS_PENDING,
        user_id=uid,
        filename=filename,
    )

    t = threading.Thread(
        target=_run_analysis_job,
        args=(job_id, file_bytes, filename, file_size, uid, project,
              not request.user.is_authenticated, request.session.session_key),
        daemon=True,
    )
    t.start()

    return JsonResponse({'job_id': job_id, 'filename': filename})


@csrf_exempt
@require_http_methods(['GET'])
def api_job_status(request, job_id: str):
    """Poll the status of a background analysis job."""
    try:
        job = AnalysisJob.objects.get(job_id=job_id)
    except AnalysisJob.DoesNotExist:
        return JsonResponse({'error': 'Job not found.'}, status=404)

    if job.status == AnalysisJob.STATUS_DONE:
        result = json.loads(job.result_json)
        # Clean up after delivering the result once.
        job.delete()
        return JsonResponse({'status': 'done', 'result': result})

    if job.status == AnalysisJob.STATUS_FAILED:
        error = job.error_message or 'Analysis failed. Please try again.'
        job.delete()
        return JsonResponse({'status': 'failed', 'error': error})

    return JsonResponse({'status': job.status, 'progress': round(job.progress, 3)})


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


@require_http_methods(['GET'])
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


@require_http_methods(['GET'])
@api_login_required
def api_projects(request):
    return JsonResponse(hist.list_projects(user_id=_uid(request)), safe=False)


@require_http_methods(['GET'])
@api_login_required
def api_project_summaries(request):
    return JsonResponse(hist.list_project_summaries(user_id=_uid(request)), safe=False)


@require_http_methods(['GET'])
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


@csrf_exempt
@require_http_methods(['PATCH'])
@api_login_required
def api_history_patch(request, build_id: int):
    """Update mutable build metadata: active, timestamp, sort_order."""
    try:
        body = json.loads(request.body)
    except (ValueError, TypeError):
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    active     = body.get('active')
    timestamp  = body.get('timestamp')
    sort_order = body.get('sort_order')
    if active is not None and not isinstance(active, bool):
        return JsonResponse({'error': 'active must be boolean'}, status=400)
    if sort_order is not None:
        try:
            sort_order = int(sort_order)
        except (TypeError, ValueError):
            return JsonResponse({'error': 'sort_order must be an integer'}, status=400)
    if timestamp is not None:
        try:
            from datetime import datetime
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except (TypeError, ValueError):
            return JsonResponse({'error': 'timestamp must be a valid ISO 8601 string'}, status=400)
    updated = hist.update_build_meta(
        build_id, user_id=_uid(request),
        active=active, timestamp=timestamp, sort_order=sort_order,
    )
    if not updated:
        return JsonResponse({'error': 'Build not found'}, status=404)
    return JsonResponse({'ok': True})


@require_http_methods(['GET'])
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
