"""Signal handlers for memprobe.

Two responsibilities:

1. PII scrubbing (pre_save on SocialAccount)
   Strips disallowed OAuth fields before they ever touch the DB.
   This is a defense-in-depth backstop; the primary scrub happens in
   adapters.py during the allauth flow.

2. User profile creation (post_save on User)
   Creates a user_profiles row the moment a new account is created so
   every user always has a plan and beta-status record. The is_beta_user
   flag is set permanently at signup time based on BETA_END_DATE in
   settings.py — it marks eligibility, not the current plan.
"""

from __future__ import annotations

import logging
from datetime import date, timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from allauth.socialaccount.models import SocialAccount

from .adapters import _scrub

log = logging.getLogger(__name__)
User = get_user_model()


# ── 1. PII scrubbing ──────────────────────────────────────────────────────────

@receiver(pre_save, sender=SocialAccount)
def _scrub_extra_data_on_save(sender, instance: SocialAccount, **kwargs):
    """Strip any disallowed keys out of extra_data before it's written."""
    instance.extra_data = _scrub(instance.extra_data)


# ── 2. User profile creation ──────────────────────────────────────────────────

@receiver(post_save, sender=User)
def _create_user_profile(sender, instance: User, created: bool, **kwargs):
    """Create a user_profiles row for every new account.

    Only fires on INSERT (created=True) so updates to an existing user
    (e.g. last_login timestamp) don't trigger this.

    is_beta_user is True if the signup date is on or before BETA_END_DATE.
    Once set it is never changed, so beta users keep their status even
    after the beta period ends.
    """
    if not created:
        return

    beta_end: date = getattr(settings, 'BETA_END_DATE', None)
    today = date.today()
    is_beta = (beta_end is None) or (today <= beta_end)

    user_id = str(instance.pk)
    try:
        from memprobe import history as hist
        hist.create_profile(user_id=user_id, is_beta_user=is_beta)
        log.info(
            'Created user_profile for user %s (beta=%s)',
            user_id, is_beta,
        )
    except Exception as exc:
        # Non-fatal: the app functions without a profile row, but log loudly
        # so the failure is visible in the server logs.
        log.error(
            'Failed to create user_profile for user %s: %s',
            user_id, exc,
        )
