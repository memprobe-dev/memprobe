"""Security & data-isolation tests.

Run with:  cd website && python3 manage.py test webapp.tests_security -v 2

These tests are paranoid. They verify the properties we promise users:

1. PII minimization - only email + name are persisted from OAuth providers.
2. Account deletion is total - no row anywhere references the deleted user.
3. One user cannot read or delete another user's data.
"""

from __future__ import annotations

import json
import os
import sys
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from allauth.socialaccount.models import SocialAccount

# Make sure the memprobe library can be imported
_REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO_ROOT / 'memprobe'))
from memprobe import history as hist  # noqa: E402

User = get_user_model()


def _make_user(name='Alice Example', email='alice@example.com'):
    """Create a Django user the way allauth would after a Google login."""
    u = User.objects.create_user(
        username=email,  # allauth uses email as username for OAuth-only setups
        email=email,
        first_name=name.split()[0],
        last_name=' '.join(name.split()[1:]),
    )
    # Mimic an OAuth identity record - extra_data already scrubbed
    SocialAccount.objects.create(
        user=u,
        provider='google',
        uid=f'google-uid-{u.pk}',
        extra_data={'email': email, 'name': name, 'email_verified': True},
    )
    return u


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
        # Attacker / future allauth update tries to write photo back
        sa.extra_data = {'picture': 'evil.png', 'email': 'c@example.com', 'name': 'C'}
        sa.save()
        sa.refresh_from_db()
        self.assertNotIn('picture', sa.extra_data)


class TestAccountDeletionIsTotal(TestCase):
    """Every byte of user data must disappear on deletion."""

    def setUp(self):
        # Use a fresh temp DB per test. We patch BOTH the module-level
        # _DB_PATH (for the production view code path) AND pass db_path
        # explicitly to our test setup calls below - defaults are captured
        # at function-definition time and won't see a patched _DB_PATH.
        self._tmpdir = tempfile.mkdtemp()
        self._hist_db = Path(self._tmpdir) / 'history.db'
        self._patcher = patch.object(hist, '_DB_PATH', self._hist_db)
        self._patcher.start()
        # Also patch each function's default by overriding via __defaults__
        for fn_name in ('save', 'get_build', 'list_builds', 'delete_build',
                         'clear', 'list_projects', 'list_project_summaries',
                         'get_trend', 'save_share', 'get_share',
                         'save_project_settings', 'get_project_settings',
                         'delete_project', 'list_projects_full',
                         'delete_all_for_user', '_connect'):
            fn = getattr(hist, fn_name)
            if fn.__defaults__:
                fn.__defaults__ = tuple(
                    self._hist_db if isinstance(d, Path) else d
                    for d in fn.__defaults__
                )

    def tearDown(self):
        self._patcher.stop()

    def test_user_delete_purges_all_tables(self):
        alice = _make_user('Alice A', 'alice@a.test')
        bob   = _make_user('Bob B',   'bob@b.test')

        # Give each user some memprobe history
        from memprobe.models import MemoryMap, MemoryRegion
        for u in (alice, bob):
            mmap = MemoryMap(
                source_file=f'/tmp/{u.username}.elf',
                toolchain='gcc', target=None,
                sections=[], regions=[MemoryRegion(name='FLASH', origin=0, length=1024, used=512)],
            )
            hist.save(mmap, user_id=str(u.pk), analysis_json={'foo': 'bar'}, project=u.username)
            hist.save_share(
                share_id=f'share-{u.pk}',
                filename='fw.elf',
                analysis_json=json.dumps({'x': 1}),
                user_id=str(u.pk),
            )

        # Confirm both users have data
        self.assertEqual(len(hist.list_builds(user_id=str(alice.pk))), 1)
        self.assertEqual(len(hist.list_builds(user_id=str(bob.pk))),   1)

        # Build a session for Alice (mimic /login)
        client = Client()
        client.force_login(alice)
        self.assertEqual(Session.objects.count(), 1)

        # Delete Alice's account
        resp = client.post(reverse('delete_account'), {'confirm': 'DELETE'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('deleted=1', resp.url)

        alice_id = str(alice.pk)

        # ── Django side ────────────────────────────────────────────────
        self.assertFalse(User.objects.filter(pk=alice.pk).exists())
        self.assertFalse(SocialAccount.objects.filter(user_id=alice.pk).exists())
        self.assertEqual(Session.objects.count(), 0)

        # ── memprobe side ──────────────────────────────────────────────
        with sqlite3.connect(str(self._hist_db)) as c:
            builds = c.execute(
                'SELECT COUNT(*) FROM builds WHERE user_id = ?', (alice_id,)
            ).fetchone()[0]
            shares = c.execute(
                'SELECT COUNT(*) FROM shares WHERE user_id = ?', (alice_id,)
            ).fetchone()[0]
            settings = c.execute(
                'SELECT COUNT(*) FROM project_settings WHERE user_id = ?',
                (alice_id,),
            ).fetchone()[0]
        self.assertEqual(builds, 0, 'Alice still has build rows after deletion')
        self.assertEqual(shares, 0, 'Alice still has share rows after deletion')
        self.assertEqual(settings, 0, 'Alice still has project_settings after deletion')

        # ── Bob is untouched ───────────────────────────────────────────
        self.assertTrue(User.objects.filter(pk=bob.pk).exists())
        self.assertEqual(len(hist.list_builds(user_id=str(bob.pk))), 1)
        self.assertEqual(
            SocialAccount.objects.filter(user_id=bob.pk).count(), 1
        )

    def test_delete_requires_exact_confirmation_phrase(self):
        alice = _make_user()
        client = Client()
        client.force_login(alice)

        # Empty / wrong text → refused
        resp = client.post(reverse('delete_account'), {})
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(User.objects.filter(pk=alice.pk).exists())

        resp = client.post(reverse('delete_account'), {'confirm': 'delete'})  # lowercase
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(User.objects.filter(pk=alice.pk).exists())

        resp = client.post(reverse('delete_account'), {'confirm': 'YES'})
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(User.objects.filter(pk=alice.pk).exists())

    def test_anonymous_cannot_call_delete(self):
        # No login → 302 to /login, no deletion happens
        client = Client()
        resp = client.post(reverse('delete_account'), {'confirm': 'DELETE'})
        # web_login_required redirects, doesn't 401
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.url)


class TestCrossUserIsolation(TestCase):
    """Verify Bob cannot read or delete Alice's data even by guessing IDs."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._hist_db = Path(self._tmpdir) / 'history.db'
        self._patcher = patch.object(hist, '_DB_PATH', self._hist_db)
        self._patcher.start()
        for fn_name in ('save', 'get_build', 'list_builds', 'delete_build',
                         'clear', 'list_projects', 'list_project_summaries',
                         'get_trend', 'save_share', 'get_share',
                         'save_project_settings', 'get_project_settings',
                         'delete_project', 'list_projects_full',
                         'delete_all_for_user', '_connect'):
            fn = getattr(hist, fn_name)
            if fn.__defaults__:
                fn.__defaults__ = tuple(
                    self._hist_db if isinstance(d, Path) else d
                    for d in fn.__defaults__
                )

    def tearDown(self):
        self._patcher.stop()

    def test_get_build_returns_none_for_other_users_id(self):
        alice = _make_user('Alice', 'alice@x.test')
        bob   = _make_user('Bob',   'bob@x.test')

        from memprobe.models import MemoryMap
        mmap = MemoryMap(source_file='/tmp/a.elf', toolchain='gcc', target=None)
        alice_build = hist.save(mmap, user_id=str(alice.pk), analysis_json={'a': 1})

        # Bob tries to fetch Alice's build by ID
        result = hist.get_build(alice_build, user_id=str(bob.pk))
        self.assertIsNone(result)

        # Alice can fetch her own
        result = hist.get_build(alice_build, user_id=str(alice.pk))
        self.assertIsNotNone(result)

    def test_delete_build_no_op_for_other_user(self):
        alice = _make_user('Alice', 'alice2@x.test')
        bob   = _make_user('Bob',   'bob2@x.test')

        from memprobe.models import MemoryMap
        mmap = MemoryMap(source_file='/tmp/a.elf', toolchain='gcc', target=None)
        alice_build = hist.save(mmap, user_id=str(alice.pk))

        # Bob tries to delete Alice's build
        deleted = hist.delete_build(alice_build, user_id=str(bob.pk))
        self.assertFalse(deleted)

        # Build is still there for Alice
        self.assertIsNotNone(hist.get_build(alice_build, user_id=str(alice.pk)))

    def test_list_builds_isolated_per_user(self):
        alice = _make_user('Alice', 'alice3@x.test')
        bob   = _make_user('Bob',   'bob3@x.test')

        from memprobe.models import MemoryMap
        for i in range(3):
            hist.save(MemoryMap(source_file=f'/tmp/a{i}.elf', toolchain='gcc', target=None),
                      user_id=str(alice.pk))
        for i in range(2):
            hist.save(MemoryMap(source_file=f'/tmp/b{i}.elf', toolchain='gcc', target=None),
                      user_id=str(bob.pk))

        self.assertEqual(len(hist.list_builds(user_id=str(alice.pk))), 3)
        self.assertEqual(len(hist.list_builds(user_id=str(bob.pk))),   2)

    def test_clear_only_affects_calling_user(self):
        alice = _make_user('Alice', 'alice4@x.test')
        bob   = _make_user('Bob',   'bob4@x.test')

        from memprobe.models import MemoryMap
        hist.save(MemoryMap(source_file='/tmp/a.elf', toolchain='gcc', target=None), user_id=str(alice.pk))
        hist.save(MemoryMap(source_file='/tmp/b.elf', toolchain='gcc', target=None), user_id=str(bob.pk))

        hist.clear(user_id=str(alice.pk))

        self.assertEqual(len(hist.list_builds(user_id=str(alice.pk))), 0)
        self.assertEqual(len(hist.list_builds(user_id=str(bob.pk))),   1)


class TestRefusesAnonymousDeletion(TestCase):
    """delete_all_for_user must refuse the anonymous sentinel."""

    def test_refuses_anonymous_sentinel(self):
        with self.assertRaises(ValueError):
            hist.delete_all_for_user('__anonymous__')

    def test_refuses_empty_user_id(self):
        with self.assertRaises(ValueError):
            hist.delete_all_for_user('')
