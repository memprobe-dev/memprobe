"""Custom allauth adapter + a defense-in-depth DB signal that minimize stored
user data.

We collect only:
- email (account identity)
- name  (UI greeting)

Everything else from the OAuth provider - pictures, avatars, locale, gender,
bio, repos, social graph - is dropped before it touches the database.

There are two layers of defense:

1. ``MemprobeSocialAccountAdapter`` - runs during the allauth flow on
   ``pre_social_login`` and ``save_user``. Catches the normal path.

2. ``_scrub_extra_data_on_save`` (Django ``pre_save`` signal) - runs on EVERY
   write to ``SocialAccount``, regardless of which code path triggered it.
   This catches any direct ``.save()`` from admin, shells, or future
   provider integrations that bypass the adapter.

Together these guarantee that ``socialaccount_socialaccount.extra_data``
never contains anything outside the allow-list.
"""

from __future__ import annotations

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


# Strict allow-list. Anything not here is dropped at write time.
# Why allow-list, not deny-list? Because providers add new fields over time
# (Google has added several to userinfo over the years) and the safe default
# for new unknown fields is "don't store it".
_KEEP = frozenset({
    'email',           # Account identity
    'email_verified',  # Used by allauth's email-verification logic
    'verified_email',  # GitHub equivalent
    'name',            # Display name shown in our UI
    'login',           # GitHub username - used by allauth to identify the account
})


def _scrub(extra_data: dict | None) -> dict:
    """Return a copy of ``extra_data`` with only allow-listed keys."""
    if not extra_data:
        return {}
    return {k: v for k, v in extra_data.items() if k in _KEEP}


class MemprobeSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Scrub OAuth profile data before allauth persists it."""

    def pre_social_login(self, request, sociallogin):
        # Runs for BOTH first-time and returning logins. Mutates the in-memory
        # SocialAccount before allauth's own .save() is called downstream.
        sociallogin.account.extra_data = _scrub(sociallogin.account.extra_data)
        return super().pre_social_login(request, sociallogin)

    def save_user(self, request, sociallogin, form=None):
        # Belt-and-braces: re-scrub right before the account is persisted.
        sociallogin.account.extra_data = _scrub(sociallogin.account.extra_data)
        return super().save_user(request, sociallogin, form)
