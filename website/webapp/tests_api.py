"""API endpoint and security tests for the memprobe Django webapp.

Run with:  cd website && python3 manage.py test webapp.tests_api -v 2

All history DB calls are mocked so these tests do not require a live
PostgreSQL database.
"""

from __future__ import annotations

import io
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

# Make sure the memprobe library is importable
_REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO_ROOT / 'memprobe'))

# ---------------------------------------------------------------------------
# Minimal fixtures: ELF files from memprobe/tests/fixtures/
# ---------------------------------------------------------------------------

_FIXTURES = _REPO_ROOT / 'memprobe' / 'tests' / 'fixtures'
_STM32_ELF = _FIXTURES / 'stm32f407_motor_ctrl.elf'
_IAR_MAP    = _FIXTURES / 'sample_iar.map'

User = get_user_model()


def _make_user(email='alice@test.com', name='Alice'):
    return User.objects.create_user(
        username=email, email=email,
        first_name=name.split()[0], last_name=' '.join(name.split()[1:]),
    )


def _build_stub(build_id=1, user_id='1', project='myproj'):
    """Minimal build dict that mirrors what hist.get_build returns."""
    return {
        'id': build_id,
        'user_id': user_id,
        'source_file': '/tmp/fw.elf',
        'timestamp': datetime(2025, 1, 1, tzinfo=timezone.utc),
        'git_hash': None, 'git_branch': None,
        'total_flash': 50000, 'total_ram': 20000,
        'toolchain': 'gcc', 'project': project,
        'metadata': {},
        'has_analysis': True,
        'analysis': {
            'sections': [{'name': '.text', 'size': 50000, 'type': 'text'}],
            'symbols': [],
            'regions': [],
        },
    }


# ---------------------------------------------------------------------------
# Helper mixin that patches all hist.* calls
# ---------------------------------------------------------------------------

_HIST_PATH = 'webapp.views.hist'


class HistMock:
    """Context manager + attribute bag that stubs out hist.*."""

    def __init__(self, **kwargs):
        self._overrides = kwargs
        self._patcher = patch(_HIST_PATH)

    def __enter__(self):
        self.mock = self._patcher.start()
        # sensible defaults
        self.mock.list_projects.return_value = []
        self.mock.list_builds.return_value = []
        self.mock.list_projects_full.return_value = []
        self.mock.list_project_summaries.return_value = []
        self.mock.get_trend.return_value = []
        self.mock.save.return_value = 1
        self.mock.get_build.return_value = None
        self.mock.delete_build.return_value = False
        self.mock.update_build_meta.return_value = False
        self.mock.get_project_settings.return_value = None
        self.mock.save_project_settings.return_value = {}
        self.mock.delete_project.return_value = {'builds_deleted': 0, 'settings_deleted': 0}
        self.mock.clear.return_value = None
        self.mock.save_share.return_value = None
        self.mock.get_share.return_value = None
        self.mock.init_db.return_value = None
        for k, v in self._overrides.items():
            setattr(self.mock, k, v)
        return self.mock

    def __exit__(self, *args):
        self._patcher.stop()


# ---------------------------------------------------------------------------
# Authentication guard tests
# ---------------------------------------------------------------------------

class TestAuthGuards(TestCase):
    """Unauthenticated requests to protected endpoints must return 401."""

    def setUp(self):
        self.client = Client()

    def _assert_401(self, url_name, **kwargs):
        with HistMock():
            r = self.client.get(reverse(url_name, **kwargs))
        self.assertEqual(r.status_code, 401, f"{url_name} should return 401 for guests")

    def test_api_history_get_requires_auth(self):
        self._assert_401('api_history')

    def test_api_history_trend_requires_auth(self):
        self._assert_401('api_history_trend')

    def test_api_projects_requires_auth(self):
        self._assert_401('api_projects')

    def test_api_project_summaries_requires_auth(self):
        self._assert_401('api_project_summaries')

    def test_api_projects_full_requires_auth(self):
        self._assert_401('api_projects_full')

    def test_api_history_build_requires_auth(self):
        self._assert_401('api_history_build', kwargs={'build_id': 1})

    def test_api_history_patch_requires_auth(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data=json.dumps({'active': True}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 401)

    def test_api_history_delete_requires_auth(self):
        with HistMock():
            r = self.client.delete(reverse('api_history_delete', kwargs={'build_id': 1}))
        self.assertEqual(r.status_code, 401)

    def test_api_project_detail_requires_auth(self):
        with HistMock():
            r = self.client.get(reverse('api_project_detail', kwargs={'project_name': 'p'}))
        self.assertEqual(r.status_code, 401)

    def test_api_compare_requires_auth(self):
        with HistMock():
            r = self.client.post(reverse('api_compare'))
        self.assertEqual(r.status_code, 401)

    def test_api_share_requires_auth(self):
        with HistMock():
            r = self.client.post(reverse('api_share'))
        self.assertEqual(r.status_code, 401)

    def test_api_diff_requires_auth(self):
        with HistMock():
            r = self.client.post(reverse('api_diff'))
        self.assertEqual(r.status_code, 401)


# ---------------------------------------------------------------------------
# IDOR / cross-user isolation tests
# ---------------------------------------------------------------------------

class TestIDOR(TestCase):
    """User B cannot read, patch, or delete User A's builds."""

    def setUp(self):
        self.alice = _make_user('alice@idor.test', 'Alice')
        self.bob   = _make_user('bob@idor.test',   'Bob')
        self.alice_id = str(self.alice.pk)
        self.bob_id   = str(self.bob.pk)
        self.client_alice = Client()
        self.client_alice.force_login(self.alice)
        self.client_bob   = Client()
        self.client_bob.force_login(self.bob)

    def test_bob_gets_404_for_alice_build(self):
        # hist.get_build returns None when user_id doesn't match
        with HistMock(get_build=MagicMock(return_value=None)):
            r = self.client_bob.get(reverse('api_history_build', kwargs={'build_id': 99}))
        self.assertEqual(r.status_code, 404)

    def test_bob_cannot_delete_alice_build(self):
        # delete_build returns False when user_id doesn't match
        with HistMock(delete_build=MagicMock(return_value=False)):
            r = self.client_bob.delete(
                reverse('api_history_delete', kwargs={'build_id': 99})
            )
        self.assertEqual(r.status_code, 404)

    def test_bob_cannot_patch_alice_build(self):
        with HistMock(update_build_meta=MagicMock(return_value=False)):
            r = self.client_bob.patch(
                reverse('api_history_patch', kwargs={'build_id': 99}),
                data=json.dumps({'active': False}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 404)

    def test_history_calls_include_user_id(self):
        """list_builds must be called with the authenticated user's ID."""
        mock = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.list_builds', mock):
            self.client_alice.get(reverse('api_history'))
        mock.assert_called_once_with(user_id=self.alice_id)

    def test_delete_build_called_with_correct_user_id(self):
        mock_del = MagicMock(return_value=True)
        with patch(_HIST_PATH + '.delete_build', mock_del):
            self.client_alice.delete(
                reverse('api_history_delete', kwargs={'build_id': 5})
            )
        mock_del.assert_called_once_with(5, user_id=self.alice_id)

    def test_patch_build_called_with_correct_user_id(self):
        mock_patch = MagicMock(return_value=True)
        with patch(_HIST_PATH + '.update_build_meta', mock_patch):
            self.client_alice.patch(
                reverse('api_history_patch', kwargs={'build_id': 7}),
                data=json.dumps({'active': True}),
                content_type='application/json',
            )
        mock_patch.assert_called_once_with(7, user_id=self.alice_id, active=True,
                                           timestamp=None, sort_order=None)

    def test_get_trend_called_with_correct_user_id(self):
        mock_trend = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.get_trend', mock_trend):
            self.client_alice.get(reverse('api_history_trend'))
        mock_trend.assert_called_once_with(
            user_id=self.alice_id, project=None, source_file=None,
        )


# ---------------------------------------------------------------------------
# api_analyze tests
# ---------------------------------------------------------------------------

class TestApiAnalyze(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@analyze.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def _upload(self, path, project=None):
        data = {'file': open(path, 'rb')}
        if project:
            data['project'] = project
        with HistMock():
            return self.client.post(reverse('api_analyze'), data=data)

    def test_upload_stm32_elf_returns_200(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        r = self._upload(_STM32_ELF)
        self.assertEqual(r.status_code, 200)

    def test_upload_elf_returns_sections(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        r = self._upload(_STM32_ELF)
        data = r.json()
        self.assertIn('sections', data)
        self.assertGreater(len(data['sections']), 0)

    def test_upload_elf_returns_total_flash(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        r = self._upload(_STM32_ELF)
        data = r.json()
        self.assertIn('total_flash', data)
        self.assertGreater(data['total_flash'], 0)

    def test_no_file_returns_400(self):
        with HistMock():
            r = self.client.post(reverse('api_analyze'))
        self.assertEqual(r.status_code, 400)

    def test_unsupported_type_returns_400(self):
        f = io.BytesIO(b"hello world")
        f.name = 'firmware.exe'
        with HistMock():
            r = self.client.post(reverse('api_analyze'), data={'file': f})
        self.assertEqual(r.status_code, 400)
        self.assertIn('error', r.json())

    def test_oversized_file_returns_400(self):
        # Patch MAX_UPLOAD_BYTES to a tiny value
        with patch('webapp.views.MAX_UPLOAD_BYTES', 10), HistMock():
            f = io.BytesIO(b"x" * 100)
            f.name = 'fw.elf'
            # Manually set size attribute (Django InMemoryUploadedFile behavior)
            from django.core.files.uploadedfile import InMemoryUploadedFile
            uf = InMemoryUploadedFile(
                file=f, field_name='file', name='fw.elf',
                content_type='application/octet-stream', size=100, charset=None,
            )
            r = self.client.post(reverse('api_analyze'), data={'file': uf})
        self.assertEqual(r.status_code, 400)

    def test_guest_allowed_first_analyze(self):
        """Guests get exactly one analysis without logging in."""
        anon = Client()
        with HistMock():
            f = io.BytesIO(b"\x7fELF" + b"\x00" * 60)
            f.name = 'fw.elf'
            # This will fail to parse (garbage ELF) but should fail with 400 not 403
            r = anon.post(reverse('api_analyze'), data={'file': f})
        # Either 400 (parse error) or 200 - not 403 on first attempt
        self.assertNotEqual(r.status_code, 403)

    def test_guest_blocked_on_second_analyze(self):
        anon = Client()
        session = anon.session
        session['guest_analyzed'] = True
        session.save()
        with HistMock():
            f = io.BytesIO(b"\x7fELF" + b"\x00" * 60)
            f.name = 'fw.elf'
            r = anon.post(reverse('api_analyze'), data={'file': f})
        self.assertEqual(r.status_code, 403)

    def test_build_cap_enforced(self):
        """After MAX_BUILDS, further uploads should return 403."""
        builds = [{'id': i, 'source_file': f'/tmp/{i}.elf'} for i in range(10)]
        with HistMock(list_builds=MagicMock(return_value=builds),
                      list_projects=MagicMock(return_value=[])):
            if _STM32_ELF.exists():
                r = self._upload(_STM32_ELF)
                self.assertEqual(r.status_code, 403)

    def test_project_cap_enforced(self):
        """Uploading to a new project when already at cap returns 403."""
        existing = ['proj1', 'proj2']
        with HistMock(list_projects=MagicMock(return_value=existing),
                      list_builds=MagicMock(return_value=[])):
            if _STM32_ELF.exists():
                data = {
                    'file': open(_STM32_ELF, 'rb'),
                    'project': 'proj3_new',
                }
                r = self.client.post(reverse('api_analyze'), data=data)
                self.assertEqual(r.status_code, 403)


# ---------------------------------------------------------------------------
# api_history tests
# ---------------------------------------------------------------------------

class TestApiHistory(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@history.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_get_history_returns_list(self):
        builds = [{'id': 1, 'source_file': '/tmp/fw.elf', 'total_flash': 1000,
                   'total_ram': 500, 'toolchain': 'gcc', 'project': None,
                   'timestamp': datetime.now(timezone.utc), 'git_hash': None,
                   'git_branch': None, 'metadata': {}, 'has_analysis': False}]
        with HistMock(list_builds=MagicMock(return_value=builds)):
            r = self.client.get(reverse('api_history'))
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)

    def test_delete_history_clears_all(self):
        mock_clear = MagicMock()
        with patch(_HIST_PATH + '.clear', mock_clear):
            r = self.client.delete(reverse('api_history'))
        self.assertEqual(r.status_code, 200)
        mock_clear.assert_called_once_with(user_id=str(self.alice.pk))

    def test_unsupported_method_returns_405(self):
        with HistMock():
            r = self.client.put(reverse('api_history'), data='{}',
                                content_type='application/json')
        self.assertEqual(r.status_code, 405)


# ---------------------------------------------------------------------------
# api_history_patch tests
# ---------------------------------------------------------------------------

class TestApiHistoryPatch(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@patch.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_patch_active_true(self):
        with HistMock(update_build_meta=MagicMock(return_value=True)):
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data=json.dumps({'active': True}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 200)

    def test_patch_active_non_bool_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data=json.dumps({'active': 'yes'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)

    def test_patch_sort_order_string_coerced(self):
        mock_upd = MagicMock(return_value=True)
        with patch(_HIST_PATH + '.update_build_meta', mock_upd):
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 2}),
                data=json.dumps({'sort_order': '5'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 200)
        mock_upd.assert_called_once_with(2, user_id=str(self.alice.pk),
                                         active=None, timestamp=None, sort_order=5)

    def test_patch_invalid_sort_order_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data=json.dumps({'sort_order': 'not-an-int'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)

    def test_patch_invalid_timestamp_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data=json.dumps({'timestamp': 'not-a-date'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)

    def test_patch_valid_timestamp_accepted(self):
        with HistMock(update_build_meta=MagicMock(return_value=True)):
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data=json.dumps({'timestamp': '2025-06-01T12:00:00Z'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 200)

    def test_patch_missing_build_returns_404(self):
        with HistMock(update_build_meta=MagicMock(return_value=False)):
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 999}),
                data=json.dumps({'active': True}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 404)

    def test_patch_invalid_json_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data='not json',
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# api_project_detail tests
# ---------------------------------------------------------------------------

class TestApiProjectDetail(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@proj.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_get_existing_project(self):
        settings_data = {'project': 'myproj', 'flash_budget_bytes': None,
                         'ram_budget_bytes': None, 'description': None,
                         'created_at': None, 'updated_at': None}
        with HistMock(get_project_settings=MagicMock(return_value=settings_data)):
            r = self.client.get(
                reverse('api_project_detail', kwargs={'project_name': 'myproj'})
            )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['project'], 'myproj')

    def test_delete_project(self):
        mock_del = MagicMock(return_value={'builds_deleted': 3, 'settings_deleted': 1})
        with patch(_HIST_PATH + '.delete_project', mock_del):
            r = self.client.delete(
                reverse('api_project_detail', kwargs={'project_name': 'myproj'})
            )
        self.assertEqual(r.status_code, 200)
        mock_del.assert_called_once_with(user_id=str(self.alice.pk), project='myproj')

    def test_patch_project_settings(self):
        saved = {'project': 'myproj', 'flash_budget_bytes': 524288,
                 'ram_budget_bytes': None, 'description': 'A project',
                 'created_at': None, 'updated_at': None}
        mock_save = MagicMock(return_value=saved)
        with patch(_HIST_PATH + '.save_project_settings', mock_save):
            r = self.client.patch(
                reverse('api_project_detail', kwargs={'project_name': 'myproj'}),
                data=json.dumps({'flash_budget_bytes': 524288, 'description': 'A project'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 200)

    def test_patch_negative_budget_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_project_detail', kwargs={'project_name': 'p'}),
                data=json.dumps({'flash_budget_bytes': -1}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)

    def test_patch_invalid_budget_type_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_project_detail', kwargs={'project_name': 'p'}),
                data=json.dumps({'flash_budget_bytes': 'big'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)

    def test_create_new_project(self):
        mock_save = MagicMock(return_value={'project': 'newp', 'flash_budget_bytes': None,
                                            'ram_budget_bytes': None, 'description': None,
                                            'created_at': None, 'updated_at': None})
        with HistMock(list_projects=MagicMock(return_value=[]),
                      save_project_settings=mock_save):
            r = self.client.post(
                reverse('api_project_detail', kwargs={'project_name': 'newp'})
            )
        self.assertEqual(r.status_code, 200)

    def test_create_project_at_cap_returns_403(self):
        existing = ['proj1', 'proj2']
        with HistMock(list_projects=MagicMock(return_value=existing)):
            r = self.client.post(
                reverse('api_project_detail', kwargs={'project_name': 'proj3'})
            )
        self.assertEqual(r.status_code, 403)

    def test_project_name_too_long_returns_400(self):
        long_name = 'x' * 201
        with HistMock():
            r = self.client.get(
                reverse('api_project_detail', kwargs={'project_name': long_name})
            )
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# api_projects_full tests
# ---------------------------------------------------------------------------

class TestApiProjectsFull(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@full.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_returns_list(self):
        projects = [
            {'project': 'p1', 'build_count': 3, 'first_build': None,
             'last_build': None, 'latest_flash': 50000, 'latest_ram': 20000,
             'flash_delta': None, 'ram_delta': None,
             'flash_budget_bytes': None, 'ram_budget_bytes': None,
             'description': None, 'settings_created_at': None,
             'settings_updated_at': None},
        ]
        with HistMock(list_projects_full=MagicMock(return_value=projects)):
            r = self.client.get(reverse('api_projects_full'))
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)
        self.assertEqual(r.json()[0]['project'], 'p1')

    def test_called_with_user_id(self):
        mock_fn = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.list_projects_full', mock_fn):
            self.client.get(reverse('api_projects_full'))
        mock_fn.assert_called_once_with(user_id=str(self.alice.pk))


# ---------------------------------------------------------------------------
# api_compare tests
# ---------------------------------------------------------------------------

class TestApiCompare(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@compare.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_fewer_than_two_targets_returns_400(self):
        with HistMock():
            r = self.client.post(reverse('api_compare'))
        self.assertEqual(r.status_code, 400)

    def test_two_elf_files_returns_200(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        nrf = _FIXTURES / 'nrf52840_ble_peripheral.elf'
        if not nrf.exists():
            self.skipTest("nRF fixture not present")
        with HistMock():
            r = self.client.post(reverse('api_compare'), data={
                'file_0': open(_STM32_ELF, 'rb'),
                'file_1': open(nrf, 'rb'),
            })
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn('targets', data)
        self.assertEqual(len(data['targets']), 2)

    def test_mixed_types_returns_400(self):
        if not _STM32_ELF.exists() or not _IAR_MAP.exists():
            self.skipTest("Fixtures not present")
        with HistMock():
            r = self.client.post(reverse('api_compare'), data={
                'file_0': open(_STM32_ELF, 'rb'),
                'file_1': open(_IAR_MAP, 'rb'),
            })
        self.assertEqual(r.status_code, 400)
        self.assertIn('error', r.json())


# ---------------------------------------------------------------------------
# Input validation tests
# ---------------------------------------------------------------------------

class TestInputValidation(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@valid.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_analyze_with_empty_filename(self):
        f = io.BytesIO(b"garbage")
        f.name = ''
        with HistMock():
            r = self.client.post(reverse('api_analyze'), data={'file': f})
        # Garbage data should fail parse; 400 expected
        self.assertEqual(r.status_code, 400)

    def test_history_patch_empty_body_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_history_patch', kwargs={'build_id': 1}),
                data='',
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)

    def test_project_detail_patch_invalid_json_returns_400(self):
        with HistMock():
            r = self.client.patch(
                reverse('api_project_detail', kwargs={'project_name': 'p'}),
                data='{invalid',
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# api_share tests
# ---------------------------------------------------------------------------

class TestApiShare(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@share.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_share_missing_analysis_returns_400(self):
        with HistMock():
            r = self.client.post(
                reverse('api_share'),
                data=json.dumps({'filename': 'fw.elf'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)
        self.assertIn('error', r.json())

    def test_share_with_analysis_returns_id(self):
        mock_save = MagicMock()
        with patch(_HIST_PATH + '.save_share', mock_save):
            r = self.client.post(
                reverse('api_share'),
                data=json.dumps({'analysis': {'sections': []}, 'filename': 'fw.elf'}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn('id', body)
        self.assertIsInstance(body['id'], str)
        self.assertGreater(len(body['id']), 0)

    def test_share_id_is_hex_string(self):
        with HistMock(save_share=MagicMock()):
            r = self.client.post(
                reverse('api_share'),
                data=json.dumps({'analysis': {'sections': []}}),
                content_type='application/json',
            )
        share_id = r.json()['id']
        # Must be a valid hex string
        int(share_id, 16)  # raises ValueError if not hex

    def test_share_passes_user_id_to_save_share(self):
        mock_save = MagicMock()
        with patch(_HIST_PATH + '.save_share', mock_save):
            self.client.post(
                reverse('api_share'),
                data=json.dumps({'analysis': {'x': 1}}),
                content_type='application/json',
            )
        call_kwargs = mock_save.call_args
        self.assertIn(str(self.alice.pk), str(call_kwargs))

    def test_guest_cannot_share(self):
        anon = Client()
        with HistMock():
            r = anon.post(
                reverse('api_share'),
                data=json.dumps({'analysis': {'sections': []}}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 401)

    def test_share_empty_body_returns_400(self):
        with HistMock():
            r = self.client.post(
                reverse('api_share'),
                data=json.dumps({}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# api_diff tests
# ---------------------------------------------------------------------------

class TestApiDiff(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@diff.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_no_inputs_returns_400(self):
        with HistMock():
            r = self.client.post(reverse('api_diff'))
        self.assertEqual(r.status_code, 400)

    def test_only_old_provided_returns_400(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock():
            r = self.client.post(reverse('api_diff'), data={
                'old_file': open(_STM32_ELF, 'rb'),
            })
        self.assertEqual(r.status_code, 400)

    def test_two_matching_elf_files_returns_200(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock():
            r = self.client.post(reverse('api_diff'), data={
                'old_file': open(_STM32_ELF, 'rb'),
                'new_file': open(_STM32_ELF, 'rb'),
            })
        self.assertEqual(r.status_code, 200)

    def test_diff_response_has_expected_keys(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock():
            r = self.client.post(reverse('api_diff'), data={
                'old_file': open(_STM32_ELF, 'rb'),
                'new_file': open(_STM32_ELF, 'rb'),
            })
        data = r.json()
        for key in ('flash_delta', 'ram_delta', 'diffs', 'old_filename', 'new_filename'):
            self.assertIn(key, data)

    def test_identical_files_flash_delta_zero(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock():
            r = self.client.post(reverse('api_diff'), data={
                'old_file': open(_STM32_ELF, 'rb'),
                'new_file': open(_STM32_ELF, 'rb'),
            })
        self.assertEqual(r.json()['flash_delta'], 0)

    def test_diff_requires_auth(self):
        anon = Client()
        with HistMock():
            r = anon.post(reverse('api_diff'))
        self.assertEqual(r.status_code, 401)

    def test_diff_entry_kind_field(self):
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock():
            r = self.client.post(reverse('api_diff'), data={
                'old_file': open(_STM32_ELF, 'rb'),
                'new_file': open(_STM32_ELF, 'rb'),
            })
        for entry in r.json()['diffs']:
            self.assertIn(entry['kind'], ('added', 'removed', 'changed'))


# ---------------------------------------------------------------------------
# api_history_trend tests
# ---------------------------------------------------------------------------

class TestApiHistoryTrend(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@trend.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_returns_list(self):
        with HistMock(get_trend=MagicMock(return_value=[])):
            r = self.client.get(reverse('api_history_trend'))
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_project_param_passed_to_get_trend(self):
        mock_trend = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.get_trend', mock_trend):
            self.client.get(reverse('api_history_trend') + '?project=myproj')
        mock_trend.assert_called_once_with(
            user_id=str(self.alice.pk),
            project='myproj',
            source_file=None,
        )

    def test_source_param_passed_to_get_trend(self):
        mock_trend = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.get_trend', mock_trend):
            self.client.get(reverse('api_history_trend') + '?source=fw.elf')
        mock_trend.assert_called_once_with(
            user_id=str(self.alice.pk),
            project=None,
            source_file='fw.elf',
        )

    def test_empty_project_param_treated_as_none(self):
        mock_trend = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.get_trend', mock_trend):
            self.client.get(reverse('api_history_trend') + '?project=')
        mock_trend.assert_called_once_with(
            user_id=str(self.alice.pk),
            project=None,
            source_file=None,
        )

    def test_post_not_allowed(self):
        with HistMock():
            r = self.client.post(reverse('api_history_trend'))
        self.assertEqual(r.status_code, 405)


# ---------------------------------------------------------------------------
# api_projects and api_project_summaries tests
# ---------------------------------------------------------------------------

class TestApiProjects(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@projects.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_projects_returns_list(self):
        with HistMock(list_projects=MagicMock(return_value=['proj1', 'proj2'])):
            r = self.client.get(reverse('api_projects'))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), ['proj1', 'proj2'])

    def test_projects_empty_for_new_user(self):
        with HistMock(list_projects=MagicMock(return_value=[])):
            r = self.client.get(reverse('api_projects'))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

    def test_projects_called_with_user_id(self):
        mock_fn = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.list_projects', mock_fn):
            self.client.get(reverse('api_projects'))
        mock_fn.assert_called_once_with(user_id=str(self.alice.pk))

    def test_project_summaries_returns_list(self):
        summaries = [{'project': 'p1', 'build_count': 2, 'latest_flash': 50000}]
        with HistMock(list_project_summaries=MagicMock(return_value=summaries)):
            r = self.client.get(reverse('api_project_summaries'))
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_project_summaries_called_with_user_id(self):
        mock_fn = MagicMock(return_value=[])
        with patch(_HIST_PATH + '.list_project_summaries', mock_fn):
            self.client.get(reverse('api_project_summaries'))
        mock_fn.assert_called_once_with(user_id=str(self.alice.pk))


# ---------------------------------------------------------------------------
# _quota_error helper unit tests (via API endpoints)
# ---------------------------------------------------------------------------

class TestQuotaError(TestCase):
    """Verify _quota_error is called correctly and returns the right response codes."""

    def setUp(self):
        self.alice = _make_user('alice@quota.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_at_build_cap_analyze_returns_403(self):
        builds = [{'id': i, 'source_file': f'/tmp/{i}.elf'} for i in range(10)]
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock(
            list_builds=MagicMock(return_value=builds),
            list_projects=MagicMock(return_value=[]),
        ):
            r = self.client.post(reverse('api_analyze'), data={
                'file': open(_STM32_ELF, 'rb'),
            })
        self.assertEqual(r.status_code, 403)
        self.assertIn('error', r.json())

    def test_at_build_cap_error_message_contains_limit(self):
        builds = [{'id': i, 'source_file': f'/tmp/{i}.elf'} for i in range(10)]
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock(
            list_builds=MagicMock(return_value=builds),
            list_projects=MagicMock(return_value=[]),
        ):
            r = self.client.post(reverse('api_analyze'), data={
                'file': open(_STM32_ELF, 'rb'),
            })
        self.assertIn('10', r.json()['error'])

    def test_at_project_cap_new_project_returns_403(self):
        existing = ['proj1', 'proj2']
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock(
            list_projects=MagicMock(return_value=existing),
            list_builds=MagicMock(return_value=[]),
        ):
            r = self.client.post(reverse('api_analyze'), data={
                'file': open(_STM32_ELF, 'rb'),
                'project': 'new_proj',
            })
        self.assertEqual(r.status_code, 403)

    def test_existing_project_allowed_despite_cap(self):
        """Uploading to an already-existing project does not count as a new project."""
        existing = ['proj1', 'proj2']
        if not _STM32_ELF.exists():
            self.skipTest("STM32 fixture not present")
        with HistMock(
            list_projects=MagicMock(return_value=existing),
            list_builds=MagicMock(return_value=[]),
        ):
            r = self.client.post(reverse('api_analyze'), data={
                'file': open(_STM32_ELF, 'rb'),
                'project': 'proj1',  # already exists
            })
        # Should not hit the project cap — may succeed (200) or fail for other reasons
        self.assertNotEqual(r.status_code, 403)


# ---------------------------------------------------------------------------
# api_history_build tests
# ---------------------------------------------------------------------------

class TestApiHistoryBuild(TestCase):
    def setUp(self):
        self.alice = _make_user('alice@build.test')
        self.client = Client()
        self.client.force_login(self.alice)

    def test_get_existing_build_returns_200(self):
        build = _build_stub(build_id=42, user_id=str(self.alice.pk))
        with HistMock(get_build=MagicMock(return_value=build)):
            r = self.client.get(reverse('api_history_build', kwargs={'build_id': 42}))
        self.assertEqual(r.status_code, 200)

    def test_get_missing_build_returns_404(self):
        with HistMock(get_build=MagicMock(return_value=None)):
            r = self.client.get(reverse('api_history_build', kwargs={'build_id': 999}))
        self.assertEqual(r.status_code, 404)

    def test_get_build_called_with_user_id(self):
        mock_gb = MagicMock(return_value=None)
        with patch(_HIST_PATH + '.get_build', mock_gb):
            self.client.get(reverse('api_history_build', kwargs={'build_id': 7}))
        mock_gb.assert_called_once_with(7, user_id=str(self.alice.pk))

    def test_build_response_has_id_field(self):
        build = _build_stub(build_id=42, user_id=str(self.alice.pk))
        with HistMock(get_build=MagicMock(return_value=build)):
            r = self.client.get(reverse('api_history_build', kwargs={'build_id': 42}))
        self.assertIn('id', r.json())

    def test_delete_existing_build_returns_200(self):
        with HistMock(delete_build=MagicMock(return_value=True)):
            r = self.client.delete(
                reverse('api_history_delete', kwargs={'build_id': 42})
            )
        self.assertEqual(r.status_code, 200)

    def test_delete_missing_build_returns_404(self):
        with HistMock(delete_build=MagicMock(return_value=False)):
            r = self.client.delete(
                reverse('api_history_delete', kwargs={'build_id': 999})
            )
        self.assertEqual(r.status_code, 404)
