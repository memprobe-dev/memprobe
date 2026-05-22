"""
Django settings for the memprobe website.

Security notes:
- DJANGO_SECRET_KEY is required in production (hard error if missing)
- DEBUG must never be True in production
- OAuth credentials come from environment variables only - never hardcoded
- Sessions are HttpOnly + Secure (in production) + SameSite=Lax
- HSTS and SSL redirect are enforced in production
- Every user-data DB query is scoped to the authenticated user's ID
"""

import os
import sys
from pathlib import Path

import dj_database_url

from dotenv import load_dotenv

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env if present (development convenience; in production use real env vars)
load_dotenv(BASE_DIR / '.env')

# Add the sibling memprobe library to the path
MEMPROBE_LIB = BASE_DIR.parent / 'memprobe'
if str(MEMPROBE_LIB) not in sys.path:
    sys.path.insert(0, str(MEMPROBE_LIB))


# ── Security fundamentals ─────────────────────────────────────────────────────

DEBUG = os.environ.get('DJANGO_DEBUG', 'false').lower() == 'true'

_secret_key = os.environ.get('DJANGO_SECRET_KEY', '')
if not _secret_key:
    if DEBUG:
        # Insecure fallback is only acceptable during local development
        _secret_key = 'django-insecure-dev-only-do-not-use-in-production'
    else:
        raise RuntimeError(
            'DJANGO_SECRET_KEY environment variable is not set. '
            'Generate one with: python3 -c "import secrets; print(secrets.token_urlsafe(64))"'
        )
SECRET_KEY = _secret_key

_allowed = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1')
ALLOWED_HOSTS = [h.strip() for h in _allowed.split(',') if h.strip()]

# ── Installed apps ────────────────────────────────────────────────────────────

INSTALLED_APPS = [
    # Django core (required by auth, sessions, allauth)
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.sites',
    'django.contrib.staticfiles',
    # Third-party
    'corsheaders',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.github',
    # Our app
    'webapp',
]

SITE_ID = 1

# ── Middleware ────────────────────────────────────────────────────────────────
# Order matters: SecurityMiddleware first, sessions before auth, auth before messages.

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

# ── Database ──────────────────────────────────────────────────────────────────
# Requires DATABASE_URL=postgres://user:pass@host:5432/dbname

_db_url = os.environ.get('DATABASE_URL', '')
if not _db_url:
    raise RuntimeError(
        'DATABASE_URL environment variable is not set. '
        'Set it to a PostgreSQL connection string (see .env).'
    )
DATABASES = {
    'default': dj_database_url.parse(_db_url, conn_max_age=600, conn_health_checks=True)
}

# ── Authentication ────────────────────────────────────────────────────────────

# Only allauth's backend - no Django ModelBackend means no password logins at all
AUTHENTICATION_BACKENDS = [
    'allauth.account.auth_backends.AuthenticationBackend',
]

AUTH_PASSWORD_VALIDATORS = []  # OAuth-only: no passwords to validate

LOGIN_URL = '/login'
LOGIN_REDIRECT_URL = '/app'
LOGOUT_REDIRECT_URL = '/'

# ── allauth: OAuth-only, no email/password signup ────────────────────────────

# Disable all email/password account flows (allauth 65.x syntax)
ACCOUNT_SIGNUP_FIELDS = []         # No fields required - OAuth only
ACCOUNT_EMAIL_VERIFICATION = 'none'
SOCIALACCOUNT_ONLY = True          # Blocks email/password signup entirely
SOCIALACCOUNT_AUTO_SIGNUP = True   # Create account automatically on first OAuth login
# Store OAuth tokens so we can call the provider's revocation endpoint
# when a user deletes their account. The token is otherwise never used
# (we don't make API calls on behalf of the user) and is deleted with the
# account. See views.py:_revoke_oauth_grant for the revocation logic.
SOCIALACCOUNT_STORE_TOKENS = True
SOCIALACCOUNT_LOGIN_ON_GET = False  # Require POST for OAuth initiation (CSRF protection)

# Custom adapter strips profile photos and other PII before persisting.
# See webapp/adapters.py for the scrub list.
SOCIALACCOUNT_ADAPTER = 'webapp.adapters.MemprobeSocialAccountAdapter'

# Minimum-data scopes: just enough to identify the user (email + name).
# Google's `profile` scope returns a picture URL too, but our adapter
# strips that before it's stored. GitHub needs `read:user` to expose name.
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
            'secret':    os.environ.get('GOOGLE_CLIENT_SECRET', ''),
            'key':       '',
        },
        'SCOPE': ['profile', 'email'],  # picture URL discarded by adapter
        'AUTH_PARAMS': {'access_type': 'online'},
        'OAUTH_PKCE_ENABLED': True,
    },
    'github': {
        'APP': {
            'client_id': os.environ.get('GITHUB_CLIENT_ID', ''),
            'secret':    os.environ.get('GITHUB_CLIENT_SECRET', ''),
            'key':       '',
        },
        'SCOPE': ['user:email', 'read:user'],  # read:user for display name
    },
}

# ── Templates ─────────────────────────────────────────────────────────────────
# Single Django Templates backend covers everything: our app views,
# allauth overrides, and any app-shipped templates discovered via APP_DIRS.

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'templates',              # global overrides (allauth, etc.)
            BASE_DIR / 'webapp' / 'templates',   # our app's page templates
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# ── Session security ──────────────────────────────────────────────────────────

SESSION_COOKIE_HTTPONLY = True          # JS cannot read the session cookie
SESSION_COOKIE_SAMESITE = 'Lax'        # Blocks cross-site request inclusion
SESSION_COOKIE_SECURE = not DEBUG       # HTTPS-only in production
SESSION_COOKIE_AGE = 60 * 60 * 24 * 30  # 30 days

# ── CSRF ──────────────────────────────────────────────────────────────────────
# All POST API endpoints are @csrf_exempt + require login via session.
# CSRF is enforced on allauth's own forms (login initiation, logout).

CSRF_COOKIE_HTTPONLY = True   # JS never needs to read CSRF token (API is exempt)
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = not DEBUG

# ── Security headers ──────────────────────────────────────────────────────────

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000          # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ── CORS ──────────────────────────────────────────────────────────────────────

if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True
else:
    _cors = os.environ.get('CORS_ALLOWED_ORIGINS', '').strip()
    CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors.split(',') if o.strip()]

# ── Logging ───────────────────────────────────────────────────────────────────
# Stream our app's INFO/WARN/ERROR messages to the console so we can see things
# like OAuth-revocation failures during runserver. Production should pipe to
# a real log aggregator.

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {'format': '[{levelname}] {name}: {message}', 'style': '{'},
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'webapp': {  # our app's loggers
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# ── URLs & WSGI ───────────────────────────────────────────────────────────────

ROOT_URLCONF = 'config.urls'
WSGI_APPLICATION = 'config.wsgi.application'

# ── Static files ──────────────────────────────────────────────────────────────

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# ── File uploads ──────────────────────────────────────────────────────────────

FILE_UPLOAD_MAX_MEMORY_SIZE = 256 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = 256 * 1024 * 1024

# ── Misc ──────────────────────────────────────────────────────────────────────

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = False
USE_TZ = True
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
