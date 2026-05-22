"""Database-level safety net.

These signal handlers fire on EVERY write to the affected tables, no matter
who triggered the save (allauth flow, Django admin, management commands,
direct ORM calls). Treat them as a last line of defense - the adapter in
``adapters.py`` is the primary path; this just guarantees we never persist
PII outside the allow-list, even if the adapter is bypassed.
"""

from __future__ import annotations

from django.db.models.signals import pre_save
from django.dispatch import receiver

from allauth.socialaccount.models import SocialAccount

from .adapters import _scrub


@receiver(pre_save, sender=SocialAccount)
def _scrub_extra_data_on_save(sender, instance: SocialAccount, **kwargs):
    """Strip any disallowed keys out of ``extra_data`` before it's written."""
    instance.extra_data = _scrub(instance.extra_data)
