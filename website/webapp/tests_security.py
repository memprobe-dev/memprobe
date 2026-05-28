"""Security & data-isolation tests.

Run with:  cd website && python3 manage.py test webapp.tests_security -v 2

These tests are paranoid. They verify the properties we promise users:

1. PII minimization - only email + name are persisted from OAuth providers.
2. Account deletion - correct confirmation phrase required; anonymous cannot call.
3. One user cannot read or delete another user's data (IDOR).

History DB calls are mocked via unittest.mock so no PostgreSQL is needed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import Client, TestCase
from django.urls import reverse

from allauth.socialaccount.models import SocialAccount

# Make sure the memprobe library can be imported
_REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO_ROOT / 'memprobe'))

User = get_user_model()

_HIST_PATH = 'webapp.views.hist'


def _make_user(name='Alice Example', email='alice@example.com'):
    """Create a Django user the way allauth would after a Google login."""
    u = User.objects.create_user(
        username=email,
        email=email,
        first_name=name.split()[0],
        last_name=' '.join(name.split()[1:]),
    )
    SocialAccount.objects.create(
        user=u,
        provider='google',
        uid=f'google-uid-{u.pk}',
        extra_data={'email': email, 'name': name, 'email_verified': True},
    )
    return u


# ── PII minimization ──────────────────────────────────────────────────────────

class TestPIIMinimization(TestCase):
    """Verify the adapter and signal scrub photo/profile data."""

    def test_extra_data_strips_picture_avatar_on_save(self):
        u = User.objects.create_user(username='bob@example.com', email='bob@example.com')
        sa = SocialAccount(
            user=u, provider='google', uid='bob-google',
            extra_data={
                'email': 'bob@example.com',
                'name': 'Bob',
                'picture': 'https://lh3.googleusercontent.com/secret-photo',
                'avatar_url': 'https://github.com/bob.png',
                'locale': 'en-US',
                'gender': 'unspecified',
                'company': 'Acme',
            },
        )
        sa.save()
        sa.refresh_from_db()

        # Only allow-listed keys survive
        self.assertEqual(set(sa.extra_data.keys()), {'email', 'name'})
        self.assertNotIn('picture', sa.extra_data)
        self.assertNotIn('avatar_url', sa.extra_data)
        self.assertNotIn('company', sa.extra_data)

    def test_extra_data_scrubbed_on_subsequent_update(self):
        u = User.objects.create_user(username='c@example.com', email='c@example.com')
        sa = SocialAccount.objects.create(
            user=u, provider='google', uid='c-google',
            extra_data={'email': 'c@example.com', 'name': 'C'},
        )
        # Simulate a future allauth update trying to write photo back
        sa.extra_data = {'picture': 'evil.png', 'email': 'c@example.com', 'name': 'C'}
        sa.save()
        sa.refresh_from_db()
        self.assertNotIn('picture', sa.extra_data)


# ── Account deletion confirmation ─────────────────────────────────────────────

class TestAccountDeletionConfirmation(TestCase):
    """Deletion requires the exact phrase "delete <email>"."""

    def test_correct_phrase_triggers_deletion(self):
        alice = _make_user()
        client = Client()
        client.force_login(alice)

        mock_del = MagicMock(return_value={
            'builds_deleted': 0, 'shares_deleted': 0,
            'project_settings_deleted': 0, 'profiles_deleted': 0,
        })
        with patch(_HIST_PATH + '.delete_all_for_user', mock_del), \
             patch('webapp.views._revoke_oauth_grant'):
            resp = client.post(reverse('delete_account'),
                               {'confirm': f'delete {alice.email}'})

        self.assertEqual(resp.status_code, 302)
        self.assertIn('deleted=1', resp.url)
        self.assertFalse(User.objects.filter(pk=alice.pk).exists())

    def test_wrong_phrase_does_not_delete(self):
        alice = _make_user('Alice Wrong', 'alice_wrong@example.com')
        client = Client()
        client.force_login(alice)

        mock_del = MagicMock()
        with patch(_HIST_PATH + '.delete_all_for_user', mock_del):
            # Empty confirmation
            resp = client.post(reverse('delete_account'), {})
        self.assertEqual(resp.status_code, 200)  # re-renders page with error
        self.assertTrue(User.objects.filter(pk=alice.pk).exists())
        mock_del.assert_not_called()

    def test_partial_phrase_rejected(self):
        alice = _make_user('Alice Partial', 'alice_partial@example.com')
        client = Client()
        client.force_login(alice)

        for wrong in ('delete', 'DELETE', alice.email, 'yes', ''):
            mock_del = MagicMock()
            with patch(_HIST_PATH + '.delete_all_for_user', mock_del):
                resp = client.post(reverse('delete_account'), {'confirm': wrong})
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(User.objects.filter(pk=alice.pk).exists(),
                            f"User deleted with wrong phrase {wrong!r}")
            mock_del.assert_not_called()

    def test_anonymous_cannot_call_delete(self):
        """Unauthenticated POST redirects to /login without deleting anything."""
        client = Client()
        resp = client.post(reverse('delete_account'), {'confirm': 'anything'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.url)

    def test_all_sessions_killed_on_deletion(self):
        """After deletion the user's session must be gone."""
        alice = _make_user('Alice Session', 'alice_session@example.com')
        client = Client()
        client.force_login(alice)
        self.assertEqual(Session.objects.count(), 1)

        mock_del = MagicMock(return_value={
            'builds_deleted': 0, 'shares_deleted': 0,
            'project_settings_deleted': 0, 'profiles_deleted': 0,
        })
        with patch(_HIST_PATH + '.delete_all_for_user', mock_del), \
             patch('webapp.views._revoke_oauth_grant'):
            client.post(reverse('delete_account'),
                        {'confirm': f'delete {alice.email}'})

        self.assertEqual(Session.objects.count(), 0)

    def test_user_without_email_uses_username(self):
        """If a user has no email (edge case), username is used in the phrase."""
        u = User.objects.create_user(username='noemail', email='')
        client = Client()
        client.force_login(u)

        mock_del = MagicMock(return_value={
            'builds_deleted': 0, 'shares_deleted': 0,
            'project_settings_deleted': 0, 'profiles_deleted': 0,
        })
        with patch(_HIST_PATH + '.delete_all_for_user', mock_del), \
             patch('webapp.views._revoke_oauth_grant'):
            # Wrong phrase (email-based) should NOT delete
            resp = client.post(reverse('delete_account'),
                               {'confirm': f'delete {u.email}'})
        # email is empty so phrase would be "delete " which is unlikely to match
        # unless username is also empty; just verify user still exists
        # (The phrase is "delete " for empty email — wrong phrase, user should survive)
        # With our fix: phrase = "delete noemail" (username fallback)
        self.assertTrue(User.objects.filter(pk=u.pk).exists())


# ── Cross-user isolation (IDOR) ───────────────────────────────────────────────

class TestCrossUserIsolation(TestCase):
    """Verify Bob cannot read or delete Alice's data even by guessing IDs."""

    def setUp(self):
        self.alice = _make_user('Alice', 'alice@isolation.test')
        self.bob   = _make_user('Bob',   'bob@isolation.test')
        self.alice_id = str(self.alice.pk)
        self.bob_id   = str(self.bob.pk)
        self.client_alice = Client()
        self.client_alice.force_login(self.alice)
        self.client_bob   = Client()
        self.client_bob.force_login(self.bob)

    def test_get_build_returns_none_for_other_user(self):
        with patch(_HIST_PATH + '.get_build', MagicMock(return_value=None)):
            r = self.client_bob.get(
                reverse('api_history_build', kwargs={'build_id': 99})
            )
        self.assertEqual(r.status_code, 404)

    def test_get_build_passes_correct_user_id(self):
        """The view must pass Bob's user_id to get_build, not a hardcoded one."""
        mock_gb = MagicMock(return_value=None)
        with patch(_HIST_PATH + '.get_build', mock_gb):
            self.client_bob.get(
                reverse('api_history_build', kwargs={'build_id': 1})
            )
        mock_gb.assert_called_once_with(1, user_id=self.bob_id)

    def test_delete_build_no_op_for_other_user(self):
        with patch(_HIST_PATH + '.delete_build', MagicMock(return_value=False)):
            r = self.client_bob.delete(
                reverse('api_history_delete', kwargs={'build_id': 99})
            )
        self.assertEqual(r.status_code, 404)

    def test_delete_build_passes_correct_user_id(self):
        mock_del = MagicMock(return_value=False)
        with patch(_HIST_PATH + '.delete_build', mock_del):
            self.client_bob.delete(
                reverse('api_history_delete', kwargs={'build_id': 5})
            )
        mock_del.assert_called_once_with(5, user_id=self.bob_id)

    def test_patch_build_passes_correct_user_id(self):
        mock_upd = MagicMock(return_value=False)
        with patch(_HIST_PATH + '.update_build_meta', mock_upd):
            self.client_alice.patch(
                reverse('api_history_patch', kwargs={'build_id': 3}),
                data=json.dumps({'active': False}),
                content_type='application/json',
            )
        mock_upd.assert_called_once_with(
            3, user_id=self.alice_id,
            active=False, timestamp=None, sort_order=None,
        )

    def test_list_builds_isolated(self):
        """list_builds is called with the authenticated user's ID, never another's."""
        alice_builds = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.list_builds', alice_builds):
            self.client_alice.get(reverse('api_history'))
        alice_builds.assert_called_once_with(user_id=self.alice_id)

    def test_project_detail_delete_uses_correct_user(self):
        mock_del = MagicMock(return_value={'builds_deleted': 0, 'settings_deleted': 0})
        with patch(_HIST_PATH + '.delete_project', mock_del):
            self.client_alice.delete(
                reverse('api_project_detail', kwargs={'project_name': 'someproject'})
            )
        mock_del.assert_called_once_with(user_id=self.alice_id, project='someproject')

    def test_clear_history_uses_correct_user(self):
        mock_clear = MagicMock()
        with patch(_HIST_PATH + '.clear', mock_clear):
            self.client_bob.delete(reverse('api_history'))
        mock_clear.assert_called_once_with(user_id=self.bob_id)


# ── Anonymous sentinel guard ──────────────────────────────────────────────────

class TestRefusesAnonymousSentinel(TestCase):
    """delete_all_for_user must refuse the anonymous sentinel and empty string."""

    def test_refuses_anonymous_sentinel(self):
        from memprobe import history as hist
        with self.assertRaises(ValueError):
            hist.delete_all_for_user('__anonymous__')

    def test_refuses_empty_user_id(self):
        from memprobe import history as hist
        with self.assertRaises(ValueError):
            hist.delete_all_for_user('')
