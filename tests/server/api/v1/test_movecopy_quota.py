# tests/server/api/v1/test_quota_maxfilesize.py
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

# ---------------------------------------------------------------------------
# Helper provider with NAME = 'osfstorage'
# ---------------------------------------------------------------------------

class MockOsfStorageProvider(MockProvider):
    NAME = 'osfstorage'


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
    async def test_copy_no_size_file_metadata_not_oversized(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Copy succeeds when get_folder_info reports no oversized files."""
        handler = mock_handler(http_request)
        handler._json = {'action': 'copy', 'path': '/test_path/'}
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        handler.get_folder_info = MockCoroutine(return_value=[])

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_copy_no_size_file_metadata_oversized(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Copy raises InvalidParameters (413) when get_folder_info finds an oversized file."""
        oversized = [{'name': 'bigfile.dat', 'size': 2 * 1024 * 1024}]
        handler = mock_handler(http_request)
        handler._json = {'action': 'copy', 'path': '/test_path/'}
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        handler.get_folder_info = MockCoroutine(return_value=oversized)

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        assert exc.value.data['message'] == 'Move/Copy Failed due to oversized files.'
        assert exc.value.data['oversized_files'] == oversized

    @pytest.mark.asyncio
    async def test_copy_no_size_folder_has_oversized_file(
            self, http_request, mock_inter_folder, patch_auth_handler_max_file_size):
        """Copy of a folder raises InvalidParameters (413) when folder contains an oversized file."""
        oversized = [{'name': 'huge.bin', 'size': 3 * 1024 * 1024}]
        handler = mock_handler(http_request)
        # Use a trailing slash so the path is treated as a directory.
        handler.path = '/test_folder/'
        handler._json = {'action': 'copy', 'path': '/dest_folder/'}
        handler.provider.metadata = MockCoroutine(
            return_value=[MockFolderMetadata(), MockFileMetadata()]
        )
        handler.get_folder_info = MockCoroutine(return_value=oversized)

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        assert exc.value.data['oversized_files'] == oversized

    @pytest.mark.asyncio
    async def test_copy_no_size_folder_no_oversized_files(
            self, http_request, mock_inter_folder, patch_auth_handler_max_file_size):
        """Copy of a folder succeeds when get_folder_info returns no oversized files."""
        handler = mock_handler(http_request)
        handler.path = '/test_folder/'
        handler._json = {'action': 'copy', 'path': '/dest_folder/'}
        handler.provider.metadata = MockCoroutine(return_value=[MockFileMetadata()])
        handler.get_folder_info = MockCoroutine(return_value=[])

        await handler.move_or_copy()

        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_move_no_size_file_metadata_oversized(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Move raises InvalidParameters (413) when metadata shows an oversized file."""
        oversized = [{'name': 'bigfile.dat', 'size': 2 * 1024 * 1024}]
        handler = mock_handler(http_request)
        handler._json = {'action': 'move', 'path': '/test_path/'}
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        handler.get_folder_info = MockCoroutine(return_value=oversized)

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        assert exc.value.data['message'] == 'Move/Copy Failed due to oversized files.'

    # -- rename skips the check entirely ------------------------------------

    @pytest.mark.asyncio
    async def test_rename_skips_max_file_size_check(
            self, http_request, mock_inter, patch_auth_handler_max_file_size):
        """Rename action skips max_file_size check even when a large size is provided."""
        handler = mock_handler(http_request)
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
        """Copy to osfstorage succeeds when calculated file size fits within quota."""
        handler = mock_handler(http_request)
        handler._json = {'action': 'copy', 'path': '/test_path/'}
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        handler.get_folder_info = MockCoroutine(return_value=[])   # no oversized
        handler.get_file_size = MockCoroutine(return_value=1_000)  # 1000 bytes

        await handler.move_or_copy()

        _, dest_provider = mock_inter_osfstorage_quota_ok
        dest_provider.get_quota.assert_called_once_with()
        handler.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_copy_osfstorage_quota_exceeded_size_from_metadata(
            self, http_request, mock_inter_osfstorage_quota_exceeded,
            patch_auth_handler_no_max_file_size):
        """Copy to osfstorage raises NotEnoughQuotaError when calculated size exceeds quota."""
        handler = mock_handler(http_request)
        handler._json = {'action': 'copy', 'path': '/test_path/'}
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        handler.get_folder_info = MockCoroutine(return_value=[])
        handler.get_file_size = MockCoroutine(return_value=90_001)  # exceeds remaining quota

        with pytest.raises(exceptions.NotEnoughQuotaError) as exc:
            await handler.move_or_copy()

        assert exc.value.message == 'You do not have enough available quota.'
        _, dest_provider = mock_inter_osfstorage_quota_exceeded
        dest_provider.get_quota.assert_called_once_with()

    # -- non-osfstorage destination skips quota check -----------------------

    @pytest.mark.asyncio
    async def test_copy_non_osfstorage_skips_quota_check(
            self, http_request, mock_inter, patch_auth_handler_no_max_file_size):
        """Copy to a non-osfstorage provider does not perform any quota check."""
        handler = mock_handler(http_request)
        handler._json = {'action': 'copy', 'path': '/test_path/'}
        handler.get_folder_info = MockCoroutine(return_value=[])
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        handler.get_file_size = MockCoroutine(return_value=90_001)  # exceeds remaining quota

        # dest_provider.NAME = 'MockProvider' (not osfstorage) → quota check skipped

        await handler.move_or_copy()

        handler.write.assert_called_once()

    # -- rename skips quota check -------------------------------------------

    @pytest.mark.asyncio
    async def test_rename_skips_quota_check(
            self, http_request, mock_inter, patch_auth_handler_no_max_file_size):
        """Rename action does not trigger quota check."""
        handler = mock_handler(http_request)
        handler._json = {
            'action': 'rename',
            'rename': 'new_name.dat',
            'path': '/test_path/',
        }

        await handler.move_or_copy()

        handler.write.assert_called_once()

    # -- combined max_file_size + quota check --------------------------------

    @pytest.mark.asyncio
    async def test_oversized_check_runs_before_quota_check(
            self, http_request, mock_inter_osfstorage_quota_ok, patch_auth_handler_max_file_size):
        """Max file_size check is evaluated before quota check; oversized error is raised first."""
        oversized = [{'name': 'bigfile.dat', 'size': 2 * 1024 * 1024}]
        handler = mock_handler(http_request)
        # File is 2 MB → oversized (max=1 MB) AND quota is fine, but oversized raises first
        handler._json = {'action': 'copy', 'path': '/test_path/'}
        handler.get_folder_info = MockCoroutine(return_value=oversized)
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())
        handler.get_file_size = MockCoroutine(return_value=2 * 1024 * 1024)  # 2 MB

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await handler.move_or_copy()

        assert exc.value.code == 413
        # Quota was NOT checked because exception was raised during oversized check
        _, dest_provider = mock_inter_osfstorage_quota_ok
        dest_provider.get_quota.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_or_copy_dir_metadata_with_pagination_token(self, http_request, monkeypatch, handler_auth):
        """Covers: move_or_copy line 163-165.
        When path is a directory and provider.metadata returns data whose last element is
        a string pagination token, handle_data must be called to strip the token before
        passing the list to get_folder_info.
        """
        import waterbutler.server.api.v1.provider.movecopy as movecopy_module

        monkeypatch.setattr(
            waterbutler.server.auth.AuthHandler, 'get',
            MockCoroutine(return_value=handler_auth)
        )

        file_meta = MockFileMetadata()
        src_provider = MockProvider()
        dest_provider = MockProvider()
        mock_make_provider = mock.Mock(side_effect=[src_provider, dest_provider])
        monkeypatch.setattr(movecopy_module, 'make_provider', mock_make_provider)

        # metadata returns a list where the last element is a pagination token (string)
        paged_data = [file_meta, 'next_page_token']
        src_provider.metadata = MockCoroutine(return_value=paged_data)
        src_provider.handle_data = mock.Mock(return_value=([file_meta], 'next_page_token'))

        mock_adelay = MockCoroutine(return_value='celery-task-id')
        monkeypatch.setattr(movecopy_module.tasks.copy, 'adelay', mock_adelay)
        monkeypatch.setattr(movecopy_module.tasks, 'wait_on_celery',
                            MockCoroutine(return_value=(file_meta, True)))

        handler = mock_handler(http_request)
        # '/test_folder/' ends with '/' → WaterButlerPath.is_dir == True
        handler.path = '/test_folder/'
        handler._json = {'action': 'copy', 'path': '/dest_folder/'}

        await handler.move_or_copy()

        # handle_data must have been called to separate data from the token
        src_provider.handle_data.assert_called_once_with(paged_data)
        handler.write.assert_called_once()


@pytest.mark.usefixtures('patch_auth_handler', 'patch_make_provider_move_copy')
class TestGetFileSize:

    @pytest.mark.asyncio
    async def test_get_file_size_single_file(self, http_request):
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_file')

        result = await handler.get_file_size(MockFileMetadata())

        assert result == 1337

    @pytest.mark.asyncio
    async def test_get_file_size_multiple_files(self, http_request):
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_file')

        result = await handler.get_file_size([MockFileMetadata(), MockFileMetadata()])

        assert result == 1337 * 2

    @pytest.mark.asyncio
    async def test_get_file_size_folder_containing_file(self, http_request):
        """When self.path.is_dir is False the single metadata result is wrapped in a list."""
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_file')  # is_dir == False
        handler.provider.metadata = MockCoroutine(return_value=MockFileMetadata())

        result = await handler.get_file_size([MockFolderMetadata()])

        assert result == 1337

    @pytest.mark.asyncio
    async def test_get_file_size_folder_metadata_with_token(self, http_request):
        """When self.path.is_dir is True and metadata returns a list ending with a token,
        handle_data is called to strip the token before recursing."""
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_folder/')  # is_dir == True
        file_meta = MockFileMetadata()
        paged = [file_meta, 'next_token']
        handler.provider.metadata = MockCoroutine(return_value=paged)
        handler.provider.handle_data = mock.Mock(return_value=([file_meta], 'next_token'))

        result = await handler.get_file_size([MockFolderMetadata()])

        assert result == 1337
        handler.provider.handle_data.assert_called_once_with(paged)

@pytest.mark.usefixtures('patch_auth_handler', 'patch_make_provider_move_copy')
class TestGetFolderInfo:

    @pytest.mark.asyncio
    async def test_get_folder_info_no_oversized_files(self, http_request):
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_folder/')
        max_size_bytes = 2000  # 2000 > 1337 (MockFileMetadata.size)

        result = await handler.get_folder_info([MockFileMetadata()], max_size_bytes)

        assert result == []

    @pytest.mark.asyncio
    async def test_get_folder_info_with_oversized_file(self, http_request):
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_folder/')
        max_size_bytes = 1000  # 1000 < 1337 → file is oversized

        result = await handler.get_folder_info([MockFileMetadata()], max_size_bytes)

        assert len(result) == 1
        assert result[0]['name'] == 'Foo.name'
        assert result[0]['size'] == 1337

    @pytest.mark.asyncio
    async def test_get_folder_info_no_max_size(self, http_request):
        """When max_size_bytes is None no files are flagged as oversized."""
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_folder/')

        result = await handler.get_folder_info([MockFileMetadata()], max_size_bytes=None)

        assert result == []

    @pytest.mark.asyncio
    async def test_get_folder_info_subfolder_with_oversized_file(self, http_request):
        """Oversized files inside a subfolder are found through recursion."""
        handler = mock_handler(http_request)
        # is_dir == False → data_child is wrapped: data_child = [metadata_object]
        handler.path = WaterButlerPath('/test_file')
        file_meta = MockFileMetadata()
        handler.provider.metadata = MockCoroutine(return_value=file_meta)
        max_size_bytes = 1000  # 1000 < 1337

        # One folder (whose child is oversized) + one direct oversized file
        result = await handler.get_folder_info([MockFolderMetadata(), file_meta], max_size_bytes)

        assert len(result) == 2
        assert all(r['size'] == 1337 for r in result)

    @pytest.mark.asyncio
    async def test_get_folder_info_is_dir_with_token(self, http_request):
        handler = mock_handler(http_request)
        handler.path = WaterButlerPath('/test_folder/')  # is_dir == True

        # Mock folder metadata
        folder_meta = mock.Mock()
        folder_meta.kind = 'folder'
        folder_meta.name = 'folderA'
        folder_meta.path = '/test_folder/folderA/'

        file_meta = MockFileMetadata()
        paged = [file_meta, 'next_token']

        # Patch provider
        handler.provider.validate_v1_path = MockCoroutine(return_value='/test_folder/folderA/')
        handler.provider.metadata = MockCoroutine(return_value=paged)
        handler.provider.handle_data = mock.Mock(return_value=([file_meta], 'next_token'))

        result = await handler.get_folder_info([folder_meta], max_size_bytes=2000)

        handler.provider.handle_data.assert_called_once_with(paged)
        assert result == []
