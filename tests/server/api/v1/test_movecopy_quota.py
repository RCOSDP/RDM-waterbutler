# tests/server/api/v1/test_movecopy_quota.py
import copy
import pytest
from unittest import mock

import waterbutler.server.api.v1.provider.movecopy
import waterbutler.server.auth

from waterbutler.core import exceptions
from tests.utils import MockCoroutine, MockFileMetadata, MockFolderMetadata, MockProvider
from tests.server.api.v1.utils import mock_handler
from tests.server.api.v1.fixtures import (
    http_request, handler_auth, mock_inter, mock_intra, mock_file_metadata, patch_auth_handler, patch_make_provider_move_copy
)
from waterbutler.core.path import WaterButlerPath
from waterbutler.constants import DEFAULT_CONFLICT

# ---------------------------------------------------------------------------
# Helper provider with NAME = 'osfstorage'
# ---------------------------------------------------------------------------

class MockOsfStorageProvider(MockProvider):
    NAME = 'osfstorage'


class MockFileMetadataWithSize(MockFileMetadata):
    def __init__(self, size, name='Foo.name'):
        super().__init__()
        self._size = size
        self._name = name

    @property
    def size(self):
        return self._size

    @property
    def name(self):
        return self._name


class MockFolderMetadataWithName(MockFolderMetadata):
    def __init__(self, name='Bar', path='/Bar/'):
        super().__init__()
        self._name = name
        self._path = path

    @property
    def name(self):
        return self._name

    @property
    def path(self):
        return self._path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_with_max_file_size(handler_auth):
    """Deep-copy of handler_auth that has max_file_size = 1 MB in settings."""
    auth = copy.deepcopy(handler_auth)
    auth['settings']['max_file_size'] = 1   # 1 MB
    return auth

@pytest.fixture
def patch_auth_handler_max_file_size(monkeypatch, handler_auth, auth_with_max_file_size):
    """Patch auth_handler.get: 1st call (source) → normal auth; 2nd call (dest) → auth with max_file_size=1."""
    mock_auth = MockCoroutine(side_effect=[handler_auth, auth_with_max_file_size])
    monkeypatch.setattr(waterbutler.server.auth.AuthHandler, 'get', mock_auth)
    return mock_auth

@pytest.fixture
def patch_auth_handler_no_max_file_size(monkeypatch, handler_auth):
    """Patch auth_handler.get: both calls return auth without max_file_size."""
    mock_auth = MockCoroutine(side_effect=[handler_auth, copy.deepcopy(handler_auth)])
    monkeypatch.setattr(waterbutler.server.auth.AuthHandler, 'get', mock_auth)
    return mock_auth

@pytest.fixture
def mock_inter_osfstorage_quota_ok(monkeypatch):
    """Inter-provider fixture where dest is osfstorage with sufficient quota (used=0, max=100000)."""
    src_provider = MockProvider()
    dest_provider = MockOsfStorageProvider()
    dest_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000})

    mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
    monkeypatch.setattr(
        waterbutler.server.api.v1.provider.movecopy, 'make_provider', mock_make_provider
    )

    mock_adelay = MockCoroutine(return_value='task-uuid-ok')
    mock_wait = MockCoroutine(return_value=(MockFileMetadata(), False))
    monkeypatch.setattr(waterbutler.server.api.v1.provider.movecopy.tasks.copy, 'adelay', mock_adelay)
    monkeypatch.setattr(waterbutler.server.api.v1.provider.movecopy.tasks.move, 'adelay', mock_adelay)
    monkeypatch.setattr(waterbutler.server.api.v1.provider.movecopy.tasks, 'wait_on_celery', mock_wait)

    return mock_make_provider, dest_provider

@pytest.fixture
def mock_inter_osfstorage_quota_exceeded(monkeypatch):
    """Inter-provider fixture where dest is osfstorage with insufficient quota (used=90000, max=100000)."""
    src_provider = MockProvider()
    dest_provider = MockOsfStorageProvider()
    dest_provider.get_quota = MockCoroutine(return_value={'used': 90_000, 'max': 100_000})

    mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
    monkeypatch.setattr(
        waterbutler.server.api.v1.provider.movecopy, 'make_provider', mock_make_provider
    )
    return mock_make_provider, dest_provider

@pytest.fixture
def mock_inter_folder(monkeypatch):
    src_provider = MockProvider()
    dest_provider = MockProvider()
    src_provider.metadata = MockCoroutine(
        return_value=[MockFolderMetadata(), MockFileMetadata()]
    )
    mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
    monkeypatch.setattr(waterbutler.server.api.v1.provider.movecopy, 'make_provider', mock_make_provider)

    mock_adelay = MockCoroutine(return_value='task-uuid-folder')
    mock_wait = MockCoroutine(return_value=(MockFileMetadata(), False))
    monkeypatch.setattr(waterbutler.server.api.v1.provider.movecopy.tasks.copy, 'adelay', mock_adelay)
    monkeypatch.setattr(waterbutler.server.api.v1.provider.movecopy.tasks.move, 'adelay', mock_adelay)
    monkeypatch.setattr(waterbutler.server.api.v1.provider.movecopy.tasks, 'wait_on_celery', mock_wait)

    return mock_make_provider, src_provider

# ---------------------------------------------------------------------------
# Tests: max_file_size checks
# ---------------------------------------------------------------------------

class TestMaxFileSizeCheck:

    @pytest.mark.asyncio
    async def test_copy_file_not_oversized(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Copy of a file succeeds when the file size is within limits."""
        mock_make_provider, _ = mock_inter
        src_provider = MockProvider()
        dest_provider = MockProvider()
        src_provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'copy', 'path': '/dest_path/'}

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_copy_file_oversized(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Copy of a file raises InvalidParameters (413) when the file size exceeds limit."""
        mock_make_provider, _ = mock_inter
        src_provider = MockProvider()
        dest_provider = MockProvider()
        oversized_meta = MockFileMetadataWithSize(2 * 1024 * 1024, name='bigfile.dat')
        src_provider.metadata = MockCoroutine(return_value=oversized_meta)
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'copy', 'path': '/dest_path/'}

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        assert exc.value.data['message'] == 'Move/Copy Failed due to oversized files.'
        assert exc.value.data['oversized_files'] == [{'name': 'bigfile.dat', 'size': 2 * 1024 * 1024}]

    @pytest.mark.asyncio
    async def test_copy_folder_has_oversized_file(
            self, http_request, mock_inter_folder, patch_auth_handler_max_file_size, monkeypatch):
        """Copy of a folder raises InvalidParameters (413) when background task fails due to oversized files."""
        oversized = [{'name': 'huge.bin', 'size': 3 * 1024 * 1024}]
        handler = mock_handler(http_request)
        handler.path = '/test_folder/'
        handler._json = {'action': 'copy', 'path': '/dest_folder/'}

        mock_wait = MockCoroutine(side_effect=exceptions.InvalidParameters({
            'message': 'Move/Copy Failed due to oversized files.',
            'oversized_files': oversized,
            'max_size': 1 * 1024 * 1024,
        }, code=413))
        monkeypatch.setattr(
            waterbutler.server.api.v1.provider.movecopy.tasks, 'wait_on_celery', mock_wait
        )

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        assert exc.value.data['oversized_files'] == oversized

    @pytest.mark.asyncio
    async def test_copy_folder_no_oversized_files(
            self, http_request, mock_inter_folder, patch_auth_handler_max_file_size):
        """Copy of a folder succeeds when no oversized files exist."""
        handler = mock_handler(http_request)
        handler.path = '/test_folder/'
        handler._json = {'action': 'copy', 'path': '/dest_folder/'}

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_move_file_oversized(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Move raises InvalidParameters (413) when file metadata shows an oversized file."""
        mock_make_provider, _ = mock_inter
        # Different destination resource (node): same-storage-same-project moves skip this
        # check (see test_move_file_same_project_non_osfstorage_skips_max_file_size), so the
        # request must target a different resource here to exercise the general
        # oversized-file rejection.
        src_provider = MockProvider()
        dest_provider = MockProvider()
        oversized_meta = MockFileMetadataWithSize(2 * 1024 * 1024, name='bigfile.dat')
        src_provider.metadata = MockCoroutine(return_value=oversized_meta)
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'move', 'path': '/dest_path/', 'resource': 'other_resource'}

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        assert exc.value.data['message'] == 'Move/Copy Failed due to oversized files.'

    @pytest.mark.asyncio
    async def test_move_file_same_project_non_osfstorage_skips_max_file_size(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """A single-file move on a non-osfstorage provider that stays within the same
        resource (project) must skip max_file_size -- node-match still applies here,
        driven by the request's own resource id, never by provider.nid (see
        should_skip_size_check())."""
        mock_make_provider, _ = mock_inter
        src_provider = MockProvider()
        dest_provider = MockProvider()
        oversized_meta = MockFileMetadataWithSize(2 * 1024 * 1024, name='bigfile.dat')
        src_provider.metadata = MockCoroutine(return_value=oversized_meta)
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        # No 'resource' override -> dest_resource falls back to the same resource as source.
        handler._json = {'action': 'move', 'path': '/dest_path/'}

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_rename_skips_max_file_size_check(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Rename action skips max_file_size check even when a large size is provided."""
        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {
            'action': 'rename',
            'rename': 'new_name.dat',
            'path': '/test_path/',
        }

        await handler.move_or_copy()

        handler.write.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: quota checks
# ---------------------------------------------------------------------------

class TestQuotaCheck:

    @pytest.mark.asyncio
    async def test_copy_osfstorage_quota_ok_size_from_metadata(
            self, http_request, mock_inter_osfstorage_quota_ok, patch_auth_handler_no_max_file_size):
        """Copy to osfstorage succeeds when file size fits within quota."""
        mock_make_provider, dest_provider = mock_inter_osfstorage_quota_ok
        src_provider = MockProvider()
        file_meta = MockFileMetadataWithSize(1_000)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'copy', 'path': '/dest_path/'}

        await handler.move_or_copy()

        dest_provider.get_quota.assert_called_once_with()
        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_copy_osfstorage_quota_exceeded_size_from_metadata(
            self, http_request, mock_inter_osfstorage_quota_exceeded,
            patch_auth_handler_no_max_file_size):
        """Copy to osfstorage raises NotEnoughQuotaError when file size exceeds quota."""
        mock_make_provider, dest_provider = mock_inter_osfstorage_quota_exceeded
        src_provider = MockProvider()
        file_meta = MockFileMetadataWithSize(90_001)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'copy', 'path': '/dest_path/'}

        with pytest.raises(exceptions.NotEnoughQuotaError) as exc:
            await handler.move_or_copy()

        assert exc.value.data == {'message_key': 'quota_exceeded', 'message': 'You do not have enough available quota.'}
        dest_provider.get_quota.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_copy_non_osfstorage_skips_quota_check(
            self, http_request, mock_inter, patch_auth_handler_no_max_file_size):
        """Copy to a non-osfstorage provider does not perform any quota check."""
        mock_make_provider, _ = mock_inter
        src_provider = MockProvider()
        dest_provider = MockProvider()
        file_meta = MockFileMetadataWithSize(90_001)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'copy', 'path': '/dest_path/'}

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_rename_skips_quota_check(
            self, http_request, mock_inter, patch_auth_handler_no_max_file_size):
        """Rename action does not trigger quota check."""
        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {
            'action': 'rename',
            'rename': 'new_name.dat',
            'path': '/test_path/',
        }

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_oversized_check_fails_before_quota_limit_is_applied(
            self, http_request, mock_inter_osfstorage_quota_ok, patch_auth_handler_max_file_size):
        """An oversized copy is rejected with 413 before any quota check runs -- quota is
        fetched only after the max_file_size check passes."""
        mock_make_provider, dest_provider = mock_inter_osfstorage_quota_ok
        src_provider = MockProvider()
        file_meta = MockFileMetadataWithSize(2 * 1024 * 1024, name='bigfile.dat')
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        mock_make_provider.side_effect = [src_provider, dest_provider]

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'copy', 'path': '/dest_path/'}

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        dest_provider.get_quota.assert_not_called()

    @pytest.mark.asyncio
    async def test_copy_folder_passes_check_kwargs_to_task(
            self, http_request, mock_inter_folder, patch_auth_handler_max_file_size, monkeypatch):
        """When copying a folder, move_or_copy passes max_size_bytes and check_quota to the background task."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        handler = mock_handler(http_request)
        handler.path = '/test_folder/'
        handler._json = {'action': 'copy', 'path': '/dest_folder/'}

        mock_make_provider, _ = mock_inter_folder
        src_provider = MockProvider()
        dest_provider = MockOsfStorageProvider()  # NAME = 'osfstorage'
        mock_make_provider.side_effect = [src_provider, dest_provider]

        mock_adelay = MockCoroutine(return_value='celery-task-id')
        monkeypatch.setattr(movecopy_module.tasks.copy, 'adelay', mock_adelay)

        await handler.move_or_copy()

        mock_adelay.assert_called_once()
        kwargs = mock_adelay.call_args[1]
        assert kwargs['max_size_bytes'] == 1 * 1024 * 1024
        assert kwargs['check_quota'] is True

    @pytest.mark.asyncio
    async def test_intra_folder_runs_pre_checks(
            self, http_request, mock_intra, patch_auth_handler_max_file_size, monkeypatch):
        """Intra-provider move/copy of a folder calls run_pre_checks."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        mock_run_pre_checks = MockCoroutine()
        monkeypatch.setattr(movecopy_module, 'run_pre_checks', mock_run_pre_checks)

        handler = mock_handler(http_request)
        handler.path = '/test_folder/'
        handler._json = {'action': 'copy', 'path': '/dest_folder/'}

        async def mock_backgrounded(coro):
            res = await coro()
            return res, True
        monkeypatch.setattr(movecopy_module.tasks, 'backgrounded', mock_backgrounded)

        mock_make_provider, _ = mock_intra
        src_provider = MockProvider()
        src_provider.can_intra_copy = mock.Mock(return_value=True)
        dest_provider = MockOsfStorageProvider()  # NAME = 'osfstorage'
        mock_make_provider.side_effect = [src_provider, dest_provider]

        await handler.move_or_copy()

        mock_run_pre_checks.assert_called_once_with(
            src_provider, WaterButlerPath('/test_folder/'), dest_provider,
            dest_path=WaterButlerPath('/dest_folder/'),
            operation='copy',
            conflict=DEFAULT_CONFLICT,
            rename=None,
            src_nid=handler.resource, dest_nid=handler.dest_resource,
            max_size_bytes=1 * 1024 * 1024,
            check_quota=True
        )

    @pytest.mark.asyncio
    async def test_intra_folder_pre_checks_receives_operation(
            self, http_request, mock_intra, patch_auth_handler_max_file_size, monkeypatch):
        """Intra-provider move/copy of a folder forwards dest_path/conflict/rename to
        run_pre_checks, not just operation=, so it can compute replaced_size correctly."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        mock_run_pre_checks = MockCoroutine()
        monkeypatch.setattr(movecopy_module, 'run_pre_checks', mock_run_pre_checks)

        handler = mock_handler(http_request)
        handler.path = '/test_folder/'
        handler._json = {'action': 'move', 'path': '/dest_folder/'}

        async def mock_backgrounded(coro):
            res = await coro()
            return res, True
        monkeypatch.setattr(movecopy_module.tasks, 'backgrounded', mock_backgrounded)

        mock_make_provider, _ = mock_intra
        src_provider = MockProvider()
        src_provider.can_intra_move = mock.Mock(return_value=True)
        dest_provider = MockOsfStorageProvider()
        mock_make_provider.side_effect = [src_provider, dest_provider]

        await handler.move_or_copy()

        mock_run_pre_checks.assert_called_once_with(
            src_provider, WaterButlerPath('/test_folder/'), dest_provider,
            dest_path=WaterButlerPath('/dest_folder/'),
            operation='move',
            conflict=DEFAULT_CONFLICT,
            rename=None,
            src_nid=handler.resource, dest_nid=handler.dest_resource,
            max_size_bytes=1 * 1024 * 1024,
            check_quota=True
        )

    @pytest.mark.asyncio
    async def test_intra_folder_replace_forwards_conflict_and_rename(
            self, http_request, mock_intra, patch_auth_handler_max_file_size, monkeypatch):
        """A folder move/copy with conflict='replace' (+ optional rename) must forward those
        exact values, not the defaults — this is what lets run_pre_checks find and size the
        existing destination folder being overwritten."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        mock_run_pre_checks = MockCoroutine()
        monkeypatch.setattr(movecopy_module, 'run_pre_checks', mock_run_pre_checks)

        handler = mock_handler(http_request)
        handler.path = '/test_folder/'
        handler._json = {
            'action': 'copy', 'path': '/dest_folder/',
            'conflict': 'replace', 'rename': 'renamed_folder',
        }

        async def mock_backgrounded(coro):
            res = await coro()
            return res, True
        monkeypatch.setattr(movecopy_module.tasks, 'backgrounded', mock_backgrounded)

        mock_make_provider, _ = mock_intra
        src_provider = MockProvider()
        src_provider.can_intra_copy = mock.Mock(return_value=True)
        dest_provider = MockOsfStorageProvider()
        mock_make_provider.side_effect = [src_provider, dest_provider]

        await handler.move_or_copy()

        mock_run_pre_checks.assert_called_once_with(
            src_provider, WaterButlerPath('/test_folder/'), dest_provider,
            dest_path=WaterButlerPath('/dest_folder/'),
            operation='copy',
            conflict='replace',
            rename='renamed_folder',
            src_nid=handler.resource, dest_nid=handler.dest_resource,
            max_size_bytes=1 * 1024 * 1024,
            check_quota=True
        )

    @pytest.mark.asyncio
    async def test_move_file_same_user_quota_skips_quota_check(
            self, http_request, patch_auth_handler_no_max_file_size, monkeypatch):
        """Single-file move within the same UserQuota record must not raise NotEnoughQuotaError
        even when used + file_size would exceed max."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        src_provider = MockOsfStorageProvider()
        dest_provider = MockOsfStorageProvider()
        file_meta = MockFileMetadataWithSize(600)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
        monkeypatch.setattr(movecopy_module, 'make_provider', mock_make_provider)

        mock_adelay = MockCoroutine(return_value='task-uuid-move-same-user-quota')
        mock_wait = MockCoroutine(return_value=(MockFileMetadata(), False))
        monkeypatch.setattr(movecopy_module.tasks.move, 'adelay', mock_adelay)
        monkeypatch.setattr(movecopy_module.tasks, 'wait_on_celery', mock_wait)

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'move', 'path': '/dest_path/'}

        await handler.move_or_copy()

        handler.write.assert_called_once()
        src_provider.get_quota.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_move_file_replace_subtracts_replaced_size(
            self, http_request, patch_auth_handler_no_max_file_size, monkeypatch):
        """Replacing an existing file at the destination subtracts its size from the quota
        formula."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        src_provider = MockProvider()
        dest_provider = MockOsfStorageProvider()
        file_meta = MockFileMetadataWithSize(600, name='test_file')
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 900, 'max': 1000, 'user_guid': 'user-b', 'storage_type': 1})
        dest_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(500, name='test_file')]
        )

        mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
        monkeypatch.setattr(movecopy_module, 'make_provider', mock_make_provider)

        mock_adelay = MockCoroutine(return_value='task-uuid-replace')
        mock_wait = MockCoroutine(return_value=(MockFileMetadata(), False))
        monkeypatch.setattr(movecopy_module.tasks.move, 'adelay', mock_adelay)
        monkeypatch.setattr(movecopy_module.tasks, 'wait_on_celery', mock_wait)

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        # 900 (used) + 600 (file_size) - 500 (replaced_size) = 1000, not > 1000(max) -> must pass
        handler._json = {'action': 'move', 'path': '/dest_path/', 'conflict': 'replace'}

        await handler.move_or_copy()

        handler.write.assert_called_once()
        dest_provider.metadata.assert_called_once()

    @pytest.mark.asyncio
    async def test_move_file_replace_ignores_same_named_folder(
            self, http_request, patch_auth_handler_no_max_file_size, monkeypatch):
        """Moving a file onto a same-named folder overwrites nothing, so that folder's size
        must not be credited back."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        src_provider = MockProvider()
        dest_provider = MockOsfStorageProvider()
        file_meta = MockFileMetadataWithSize(600, name='test_file')
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        dest_provider.get_quota = MockCoroutine(return_value={'used': 900, 'max': 1000, 'user_guid': 'user-b', 'storage_type': 1})
        # Only a *folder* named 'test_file' exists at the destination.
        dest_provider.metadata = MockCoroutine(
            return_value=[MockFolderMetadataWithName(name='test_file', path='/dest_path/test_file/')]
        )

        mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
        monkeypatch.setattr(movecopy_module, 'make_provider', mock_make_provider)

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        # 900 (used) + 600 (file_size) - 0 (nothing replaced) = 1500 > 1000 -> must be refused.
        handler._json = {'action': 'move', 'path': '/dest_path/', 'conflict': 'replace'}

        with pytest.raises(exceptions.NotEnoughQuotaError):
            await handler.move_or_copy()

        # validate_path must only be called once, to resolve self.dest_path -- never again
        # to walk the kind-mismatched folder's contents for its size.
        assert dest_provider.validate_path.call_count == 1

    @pytest.mark.asyncio
    async def test_move_file_same_region_skips_max_file_size(
            self, http_request, patch_auth_handler_max_file_size, monkeypatch):
        """A single-file osfstorage move that stays within the same region re-uploads
        nothing, so max_file_size must not reject it -- regardless of node (customer
        review 4: the differentiator for osfstorage is region, not node/project)."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        src_provider = MockOsfStorageProvider()
        dest_provider = MockOsfStorageProvider()
        src_provider.is_same_region = mock.Mock(return_value=True)
        # 2 MB against the fixture's 1 MB limit.
        file_meta = MockFileMetadataWithSize(2 * 1024 * 1024, name='bigfile.dat')
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})

        mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
        monkeypatch.setattr(movecopy_module, 'make_provider', mock_make_provider)

        mock_adelay = MockCoroutine(return_value='task-uuid-intra-move-oversized')
        mock_wait = MockCoroutine(return_value=(MockFileMetadata(), False))
        monkeypatch.setattr(movecopy_module.tasks.move, 'adelay', mock_adelay)
        monkeypatch.setattr(movecopy_module.tasks, 'wait_on_celery', mock_wait)

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'move', 'path': '/dest_path/'}

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_move_file_same_quota_record_different_region_still_enforces_max_file_size(
            self, http_request, patch_auth_handler_max_file_size, monkeypatch):
        """A move between a project and its own component shares a UserQuota record, but a
        genuine cross-region move (e.g. the creator's default_region changed between the
        two nodes' creation) must still reject an oversized file, even though the quota
        check itself would skip."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        src_provider = MockOsfStorageProvider()
        dest_provider = MockOsfStorageProvider()
        src_provider.is_same_region = mock.Mock(return_value=False)
        file_meta = MockFileMetadataWithSize(2 * 1024 * 1024, name='bigfile.dat')
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})

        mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
        monkeypatch.setattr(movecopy_module, 'make_provider', mock_make_provider)

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'move', 'path': '/dest_path/'}

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413

    @pytest.mark.asyncio
    async def test_copy_file_across_user_quota_still_enforces_max_file_size(
            self, http_request, patch_auth_handler_max_file_size, monkeypatch):
        """A copy into another UserQuota record is still rejected with 413; the relaxation
        only applies to intra-record moves."""
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        src_provider = MockOsfStorageProvider()
        dest_provider = MockOsfStorageProvider()
        file_meta = MockFileMetadataWithSize(2 * 1024 * 1024, name='bigfile.dat')
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-b', 'storage_type': 1})

        mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
        monkeypatch.setattr(movecopy_module, 'make_provider', mock_make_provider)

        handler = mock_handler(http_request)
        handler.path = '/test_file'
        handler._json = {'action': 'copy', 'path': '/dest_path/'}

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
