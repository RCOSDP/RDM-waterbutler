# tests/tasks/test_pre_checks.py
import sys
import time
import pytest
from unittest import mock
import copy as cp

# Import tasks first to populate sys.modules
from waterbutler import tasks

# Resolve the actual modules to avoid package attribute shadowing issues
copy_module = sys.modules['waterbutler.tasks.copy']
move_module = sys.modules['waterbutler.tasks.move']

from waterbutler.core import exceptions
from waterbutler.core.path import WaterButlerPath
from waterbutler.constants import DEFAULT_CONFLICT
from waterbutler.tasks import pre_checks as pre_checks_module
from waterbutler.tasks.pre_checks import run_pre_checks, get_replaced_size, should_skip_size_check
from tests.utils import MockCoroutine, MockFileMetadata, MockFolderMetadata, MockProvider

# Retrieve the Celery tasks from the modules
copy_task = copy_module.copy
move_task = move_module.move

# ---------------------------------------------------------------------------
# Custom Mock Metadata classes to allow custom sizes and kinds
# ---------------------------------------------------------------------------

class MockFileMetadataWithSize(MockFileMetadata):
    def __init__(self, size, name='Foo.name', kind='file', path='/Foo.name'):
        super().__init__()
        self._size = size
        self._name = name
        self._kind = kind
        self._path = path

    @property
    def size(self):
        return self._size

    @property
    def name(self):
        return self._name

    @property
    def kind(self):
        return self._kind

    @property
    def path(self):
        return self._path


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

    @property
    def kind(self):
        return 'folder'


# ---------------------------------------------------------------------------
# Task Integration Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def src_provider():
    p = MockProvider()
    p.copy.return_value = (MockFileMetadata(), True)
    p.auth['callback_url'] = 'src_callback'
    return p


@pytest.fixture
def dest_provider():
    p = MockProvider()
    p.copy.return_value = (MockFileMetadata(), True)
    p.auth['callback_url'] = 'dest_callback'
    return p


@pytest.fixture
def providers(monkeypatch, src_provider, dest_provider):
    """Mock make_provider to return our mock source and destination providers."""
    def make_provider(name=None, **kwargs):
        if name == 'src':
            return src_provider
        if name == 'dest':
            return dest_provider
        raise ValueError('Unexpected provider: {}'.format(name))
    monkeypatch.setattr(copy_module.utils, 'make_provider', make_provider)
    monkeypatch.setattr(move_module.utils, 'make_provider', make_provider)
    return src_provider, dest_provider


# ---------------------------------------------------------------------------
# Pre-checks Unit Tests
# ---------------------------------------------------------------------------

class TestShouldSkipSizeCheck:
    """For non-osfstorage providers, the skip decision must come from the caller-supplied
    src_nid/dest_nid -- never from provider.nid, which is None for most extended-storage
    providers (see should_skip_size_check() docstring)."""

    def test_true_for_move_same_storage_same_project(self):
        src = MockProvider()
        dest = MockProvider()
        assert should_skip_size_check('move', src, dest, 'node-1', 'node-1') is True

    def test_false_for_copy_even_same_storage_same_project(self):
        src = MockProvider()
        dest = MockProvider()
        assert should_skip_size_check('copy', src, dest, 'node-1', 'node-1') is False

    def test_false_for_different_storage_same_project(self):
        src = MockProvider()
        dest = MockProvider()
        dest.NAME = 'someotherstorage'
        assert should_skip_size_check('move', src, dest, 'node-1', 'node-1') is False

    def test_false_for_same_storage_different_project(self):
        src = MockProvider()
        dest = MockProvider()
        assert should_skip_size_check('move', src, dest, 'node-1', 'node-2') is False

    def test_false_when_provider_nid_matches_but_caller_nid_differs(self):
        """Regression for the customer-review-4 trap: provider.nid is None on both sides
        for most extended storage, so a None == None comparison must never be the basis
        for the decision -- only the caller-supplied nid matters."""
        src = MockProvider(settings={'nid': None})
        dest = MockProvider(settings={'nid': None})
        assert should_skip_size_check('move', src, dest, 'node-1', 'node-2') is False

    def test_true_for_osfstorage_same_region_different_project(self):
        """osfstorage uses is_same_region(), not node-match -- a project and its
        same-region component must skip even though src_nid != dest_nid."""
        src = MockProvider(settings={'nid': 'node-1'})
        dest = MockProvider(settings={'nid': 'node-2'})
        src.NAME = dest.NAME = 'osfstorage'
        src.is_same_region = mock.Mock(return_value=True)
        assert should_skip_size_check('move', src, dest, 'node-1', 'node-2') is True

    def test_false_for_osfstorage_different_region(self):
        src = MockProvider(settings={'nid': 'node-1'})
        dest = MockProvider(settings={'nid': 'node-1'})
        src.NAME = dest.NAME = 'osfstorage'
        src.is_same_region = mock.Mock(return_value=False)
        assert should_skip_size_check('move', src, dest, 'node-1', 'node-1') is False


class TestPreChecks:

    @pytest.mark.asyncio
    async def test_file_pre_checks_no_checks(self, monkeypatch):
        """Pre-checks should return early when no checks (max size or quota) are enabled."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        await run_pre_checks(src_provider, src_path, dest_provider)
        src_provider.metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_file_pre_checks_max_size_ok(self, monkeypatch):
        """Pre-checks should succeed if the file size is within limits."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(100, name='file.txt')
        src_provider.metadata = MockCoroutine(return_value=file_meta)

        await run_pre_checks(src_provider, src_path, dest_provider, max_size_bytes=200)
        src_provider.metadata.assert_called_once_with(src_path, version=None, revision=None)

    @pytest.mark.asyncio
    async def test_file_pre_checks_max_size_oversized(self, monkeypatch):
        """Pre-checks should raise InvalidParameters (413) if the file exceeds max size."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(300, name='bigfile.txt')
        src_provider.metadata = MockCoroutine(return_value=file_meta)

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(src_provider, src_path, dest_provider, max_size_bytes=200)

        assert exc.value.code == 413
        assert exc.value.data['message'] == 'Move/Copy Failed due to oversized files.'
        assert exc.value.data['oversized_files'] == [{'name': 'bigfile.txt', 'size': 300}]

    @pytest.mark.asyncio
    async def test_file_pre_checks_quota_ok(self, monkeypatch):
        """Pre-checks should succeed if the file fits in the destination quota."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(100)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000})

        await run_pre_checks(src_provider, src_path, dest_provider, check_quota=True)
        dest_provider.get_quota.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_file_pre_checks_quota_exceeded(self, monkeypatch):
        """Pre-checks should raise NotEnoughQuotaError if the file exceeds quota."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(600)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000})

        with pytest.raises(exceptions.NotEnoughQuotaError) as exc:
            await run_pre_checks(src_provider, src_path, dest_provider, check_quota=True)

        assert exc.value.data['message_key'] == 'quota_exceeded'

    @pytest.mark.asyncio
    async def test_fetch_all_pages_pagination(self, monkeypatch):
        """Pre-checks should exhaust all pages when fetching paginated metadata."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        # Page 1 contains a file and a pagination token. Page 2 contains a file.
        page1 = [MockFileMetadataWithSize(100, name='file1.txt'), 'page2_token']
        page2 = [MockFileMetadataWithSize(200, name='file2.txt')]

        src_provider.metadata = MockCoroutine(side_effect=[page1, page2])
        src_provider.handle_data = mock.Mock(return_value=([page1[0]], 'page2_token'))

        await run_pre_checks(src_provider, src_path, dest_provider, max_size_bytes=500)

        assert src_provider.metadata.call_count == 2
        src_provider.metadata.assert_has_calls([
            mock.call(src_path, version=None, revision=None, next_token=None),
            mock.call(src_path, version=None, revision=None, next_token='page2_token')
        ])
        src_provider.handle_data.assert_called_once_with(page1)

    @pytest.mark.asyncio
    async def test_folder_pre_checks_max_size_ok(self, monkeypatch):
        """Pre-checks should succeed if all files in the folder are within size limits."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        file1 = MockFileMetadataWithSize(50, name='file1.txt')
        subfolder = MockFolderMetadataWithName(name='subfolder', path='/folder/subfolder/')
        file2 = MockFileMetadataWithSize(80, name='file2.txt')

        src_provider.metadata = MockCoroutine(side_effect=[[file1, subfolder], [file2]])
        src_provider.validate_path = MockCoroutine(return_value=WaterButlerPath('/folder/subfolder/', prepend=None))

        await run_pre_checks(src_provider, src_path, dest_provider, max_size_bytes=100)

        assert src_provider.metadata.call_count == 2
        src_provider.validate_path.assert_called_once_with('/folder/subfolder/')

    @pytest.mark.asyncio
    async def test_folder_pre_checks_max_size_oversized(self, monkeypatch):
        """Pre-checks should raise InvalidParameters listing all oversized files inside folder sorted properly."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        file_ok = MockFileMetadataWithSize(50, name='file_ok.txt')
        bigfile1 = MockFileMetadataWithSize(150, name='bigfile1.txt')
        subfolder = MockFolderMetadataWithName(name='subfolder', path='/folder/subfolder/')
        bigfile2 = MockFileMetadataWithSize(180, name='bigfile2.txt')

        src_provider.metadata = MockCoroutine(side_effect=[
            [file_ok, bigfile1, subfolder],
            [bigfile2]
        ])
        src_provider.validate_path = MockCoroutine(return_value=WaterButlerPath('/folder/subfolder/', prepend=None))

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(src_provider, src_path, dest_provider, max_size_bytes=100)

        assert exc.value.code == 413
        # subfolder is sorted first (kind=='folder'), then bigfile1.txt
        assert exc.value.data['oversized_files'] == [
            {'name': 'bigfile2.txt', 'size': 180},
            {'name': 'bigfile1.txt', 'size': 150}
        ]

    @pytest.mark.asyncio
    async def test_folder_pre_checks_quota_ok(self, monkeypatch):
        """Pre-checks should succeed if folder's recursive size fits within destination quota."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        file1 = MockFileMetadataWithSize(100)
        subfolder = MockFolderMetadataWithName(name='subfolder', path='/folder/subfolder/')
        file2 = MockFileMetadataWithSize(150)

        src_provider.metadata = MockCoroutine(side_effect=[[file1, subfolder], [file2]])
        src_provider.validate_path = MockCoroutine(return_value=WaterButlerPath('/folder/subfolder/', prepend=None))
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000})

        await run_pre_checks(src_provider, src_path, dest_provider, check_quota=True)

    @pytest.mark.asyncio
    async def test_folder_pre_checks_quota_exceeded(self, monkeypatch):
        """Pre-checks should raise NotEnoughQuotaError if folder's recursive size exceeds quota."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        file1 = MockFileMetadataWithSize(200)
        subfolder = MockFolderMetadataWithName(name='subfolder', path='/folder/subfolder/')
        file2 = MockFileMetadataWithSize(250)

        src_provider.metadata = MockCoroutine(side_effect=[[file1, subfolder], [file2]])
        src_provider.validate_path = MockCoroutine(return_value=WaterButlerPath('/folder/subfolder/', prepend=None))
        dest_provider.get_quota = MockCoroutine(return_value={'used': 600, 'max': 1000})

        with pytest.raises(exceptions.NotEnoughQuotaError) as exc:
            await run_pre_checks(src_provider, src_path, dest_provider, check_quota=True)

        assert exc.value.data['message_key'] == 'quota_exceeded'

    @pytest.mark.asyncio
    async def test_move_same_user_quota_skips_quota_check_entirely(self, monkeypatch):
        """Move sharing the same UserQuota record must skip the quota check, even if
        used + file_size would otherwise exceed max."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(600)
        src_provider.NAME = 'osfstorage'
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        await run_pre_checks(
            src_provider, src_path, dest_provider, check_quota=True, operation='move'
        )
        dest_provider.get_quota.assert_called_once_with()
        src_provider.get_quota.assert_called_once_with()

    @pytest.mark.asyncio
    async def test_move_from_non_osfstorage_src_skips_src_quota_fetch(self, monkeypatch):
        """Moving from a non-osfstorage provider (e.g. Dropbox) into osfstorage must never call
        src_provider.get_quota() — non-osfstorage providers have no `nid`, so that call would
        build a bad URL and blow up. Only the destination quota should be checked."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()  # NAME == 'MockProvider', not 'osfstorage'
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(100)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(
            side_effect=AssertionError('src_provider.get_quota() must not be called for non-osfstorage src')
        )
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000})

        await run_pre_checks(
            src_provider, src_path, dest_provider, check_quota=True, operation='move'
        )
        dest_provider.get_quota.assert_called_once_with()
        src_provider.get_quota.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_different_user_quota_still_checks_quota(self, monkeypatch):
        """Move across different UserQuota records must still apply used+size>max."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(600)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-b', 'storage_type': 1})

        with pytest.raises(exceptions.NotEnoughQuotaError):
            await run_pre_checks(
                src_provider, src_path, dest_provider, check_quota=True, operation='move'
            )

    @pytest.mark.asyncio
    async def test_copy_same_user_quota_still_checks_quota_and_does_not_fetch_src_quota(self, monkeypatch):
        """Copy always creates new data, so it must NOT skip even when sharing the same UserQuota record,
        and must not waste a call fetching the source's quota."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(600)
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        with pytest.raises(exceptions.NotEnoughQuotaError):
            await run_pre_checks(
                src_provider, src_path, dest_provider, check_quota=True, operation='copy'
            )
        src_provider.get_quota.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_replaced_size_zero_when_conflict_not_replace(self, monkeypatch):
        """conflict='keep' (or anything but 'replace') never subtracts anything, even if a
        same-named item exists at the destination — nothing is actually being overwritten."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        dest_provider.metadata = MockCoroutine(return_value=[MockFileMetadataWithSize(999, name='Foo.txt')])

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo.txt', 'keep',
                                       'file')

        assert size == 0
        dest_provider.metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_replaced_size_zero_when_no_matching_child(self, monkeypatch):
        """conflict='replace' but nothing at the destination shares the incoming name -> 0."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        dest_provider.metadata = MockCoroutine(return_value=[MockFileMetadataWithSize(999, name='Other.txt')])

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo.txt', 'replace',
                                       'file')

        assert size == 0

    @pytest.mark.asyncio
    async def test_get_replaced_size_matches_file_by_name(self, monkeypatch):
        """conflict='replace' with a matching file at the destination -> that file's size."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        dest_provider.metadata = MockCoroutine(return_value=[
            MockFileMetadataWithSize(999, name='Other.txt'),
            MockFileMetadataWithSize(500, name='Foo.txt'),
        ])

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo.txt', 'replace',
                                       'file')

        assert size == 500

    @pytest.mark.asyncio
    async def test_get_replaced_size_sums_matching_folder_recursively(self, monkeypatch):
        """conflict='replace' against a matching FOLDER sums its contents recursively."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        existing_folder = MockFolderMetadataWithName(name='Foo', path='/dest/Foo/')
        existing_folder_path = WaterButlerPath('/dest/Foo/', prepend=None)

        dest_provider.metadata = MockCoroutine(side_effect=[
            [MockFileMetadataWithSize(999, name='Other.txt'), existing_folder],   # listing dest_container_path
            [MockFileMetadataWithSize(300, name='a.txt'), MockFileMetadataWithSize(200, name='b.txt')],
        ])
        dest_provider.validate_path = MockCoroutine(return_value=existing_folder_path)

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo', 'replace',
                                       'folder')

        assert size == 500
        dest_provider.validate_path.assert_called_once_with('/dest/Foo/')

    @pytest.mark.asyncio
    async def test_get_replaced_size_zero_when_only_kind_differs_file_over_folder(self, monkeypatch):
        """A file replacing a same-named folder overwrites nothing, so the folder's size
        must not be subtracted."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        existing_folder = MockFolderMetadataWithName(name='data', path='/dest/data/')
        dest_provider.metadata = MockCoroutine(return_value=[existing_folder])
        dest_provider.validate_path = MockCoroutine(
            side_effect=AssertionError('a kind mismatch must not be sized at all')
        )

        size = await get_replaced_size(dest_provider, dest_container_path, 'data', 'replace',
                                       'file')

        assert size == 0

    @pytest.mark.asyncio
    async def test_get_replaced_size_zero_when_only_kind_differs_folder_over_file(self, monkeypatch):
        """A folder replacing a same-named file leaves the file in place, so nothing is freed."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        dest_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(999, name='data')]
        )

        size = await get_replaced_size(dest_provider, dest_container_path, 'data', 'replace',
                                       'folder')

        assert size == 0

    @pytest.mark.asyncio
    async def test_get_replaced_size_picks_matching_kind_among_duplicate_names(self, monkeypatch):
        """With both a file and a folder named 'data' at the destination, only the one
        matching the source's kind gets sized."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        existing_folder = MockFolderMetadataWithName(name='data', path='/dest/data/')
        dest_provider.metadata = MockCoroutine(side_effect=[
            [MockFileMetadataWithSize(10, name='data'), existing_folder],   # dest listing
            [MockFileMetadataWithSize(50, name='inside.txt')],              # folder's children
        ])
        dest_provider.validate_path = MockCoroutine(
            return_value=WaterButlerPath('/dest/data/', prepend=None)
        )

        assert await get_replaced_size(dest_provider, dest_container_path, 'data', 'replace',
                                       'file') == 10

        dest_provider.metadata = MockCoroutine(side_effect=[
            [MockFileMetadataWithSize(10, name='data'), existing_folder],
            [MockFileMetadataWithSize(50, name='inside.txt')],
        ])
        assert await get_replaced_size(dest_provider, dest_container_path, 'data', 'replace',
                                       'folder') == 50

    @pytest.mark.asyncio
    async def test_folder_pre_check_quota_subtracts_replaced_folder_size(self, monkeypatch):
        """A folder replace subtracts the existing destination folder's total size, not just
        used + new_size."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/src_folder/', prepend=None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        existing_folder = MockFolderMetadataWithName(name='src_folder', path='/dest/src_folder/')
        existing_folder_path = WaterButlerPath('/dest/src_folder/', prepend=None)

        src_provider.metadata = MockCoroutine(return_value=[MockFileMetadataWithSize(600, name='new.txt')])
        dest_provider.metadata = MockCoroutine(side_effect=[
            [existing_folder],                                     # listing dest_container_path
            [MockFileMetadataWithSize(500, name='old.txt')],        # listing existing_folder's children
        ])
        dest_provider.validate_path = MockCoroutine(return_value=existing_folder_path)
        dest_provider.get_quota = MockCoroutine(return_value={'used': 900, 'max': 1000, 'user_guid': 'user-b', 'storage_type': 1})
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        # 900 (used) + 600 (new folder) - 500 (existing folder being replaced) = 1000, not > 1000 -> must pass
        await run_pre_checks(
            src_provider, src_path, dest_provider, dest_path=dest_container_path,
            check_quota=True, operation='copy', conflict='replace'
        )

    @pytest.mark.asyncio
    async def test_folder_pre_check_quota_ignores_replace_when_no_dest_path(self, monkeypatch):
        """Callers that don't pass dest_path keep replaced_size at 0, with no extra
        metadata calls."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/src_folder/', prepend=None)
        dest_provider = MockProvider()

        src_provider.metadata = MockCoroutine(return_value=[MockFileMetadataWithSize(100, name='new.txt')])
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-b', 'storage_type': 1})
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        await run_pre_checks(
            src_provider, src_path, dest_provider, check_quota=True, operation='copy'
        )
        dest_provider.metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_same_user_quota_does_not_walk_source_tree(self, monkeypatch):
        """A move within one UserQuota record bails out of the quota check before recursing
        into the source folder tree."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        subfolder = MockFolderMetadataWithName(name='subfolder', path='/folder/subfolder/')
        src_provider.NAME = 'osfstorage'
        # Top-level listing (always fetched) contains a subfolder; validate_path/further
        # metadata calls are only reached by the recursive _get_total_size() walk.
        src_provider.metadata = MockCoroutine(return_value=[subfolder])
        src_provider.validate_path = MockCoroutine(
            side_effect=AssertionError('source tree must not be walked when quota check is skipped')
        )
        src_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        await run_pre_checks(
            src_provider, src_path, dest_provider, check_quota=True, operation='move'
        )
        src_provider.validate_path.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_same_user_quota_does_not_look_up_replaced_item(self, monkeypatch):
        """A same-UserQuota-record move also skips get_replaced_size(), since the quota
        check itself is skipped."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/file.txt', prepend=None)
        dest_provider = MockProvider()

        file_meta = MockFileMetadataWithSize(600)
        src_provider.NAME = 'osfstorage'
        src_provider.metadata = MockCoroutine(return_value=file_meta)
        src_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        mock_get_replaced_size = MockCoroutine()
        monkeypatch.setattr(pre_checks_module, 'get_replaced_size', mock_get_replaced_size)

        await run_pre_checks(
            src_provider, src_path, dest_provider, dest_path=WaterButlerPath('/dest/', prepend=None),
            check_quota=True, operation='move', conflict='replace'
        )
        mock_get_replaced_size.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_same_storage_same_region_skips_max_file_size_check(self, monkeypatch):
        """A move that stays on osfstorage AND the same region re-uploads nothing, so
        max_file_size must not apply -- regardless of node/project (customer review 4:
        the differentiator for osfstorage is region, not node)."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider(settings={'nid': 'node-1'})
        dest_provider = MockProvider(settings={'nid': 'node-1'})
        src_provider.NAME = 'osfstorage'
        dest_provider.NAME = 'osfstorage'
        src_provider.is_same_region = mock.Mock(return_value=True)
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        src_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        await run_pre_checks(
            src_provider, src_path=WaterButlerPath('/folder/', prepend=None), dest_provider=dest_provider,
            max_size_bytes=100, check_quota=True, operation='move'
        )
        src_provider.metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_same_region_different_project_also_skips_max_file_size(self, monkeypatch):
        """A move between a project and its same-region component must skip max_file_size
        too, even with a different node/creator -- region is the only differentiator for
        osfstorage (this is the exact case customer review 4 corrected: node-match used
        to wrongly enforce the limit here)."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider(settings={'nid': 'node-1'})
        dest_provider = MockProvider(settings={'nid': 'node-2'})
        src_provider.NAME = 'osfstorage'
        dest_provider.NAME = 'osfstorage'
        src_provider.is_same_region = mock.Mock(return_value=True)
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        src_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        await run_pre_checks(
            src_provider, src_path=WaterButlerPath('/folder/', prepend=None), dest_provider=dest_provider,
            max_size_bytes=100, check_quota=True, operation='move'
        )
        src_provider.metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_different_region_still_enforces_max_file_size(self, monkeypatch):
        """A genuine cross-region osfstorage move (e.g. the creator's default_region
        changed between the two nodes' creation) still enforces max_file_size, even
        though both sides are osfstorage."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider(settings={'nid': 'node-1'})
        dest_provider = MockProvider(settings={'nid': 'node-2'})
        src_provider.NAME = 'osfstorage'
        dest_provider.NAME = 'osfstorage'
        src_provider.is_same_region = mock.Mock(return_value=False)
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        src_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 500, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(
                src_provider, src_path=WaterButlerPath('/folder/', prepend=None), dest_provider=dest_provider,
                max_size_bytes=100, check_quota=True, operation='move'
            )
        assert exc.value.code == 413

    @pytest.mark.asyncio
    async def test_move_same_project_different_storage_still_enforces_max_file_size(self, monkeypatch):
        """Two different storage types on the very same project never share "the same
        storage", so max_file_size still applies regardless of the project match."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider(settings={'nid': 'node-1'})
        dest_provider = MockProvider(settings={'nid': 'node-1'})
        src_provider.NAME = 'osfstorage'
        dest_provider.NAME = 'someotherstorage'
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(
                src_provider, src_path=WaterButlerPath('/folder/', prepend=None), dest_provider=dest_provider,
                max_size_bytes=100, operation='move'
            )
        assert exc.value.code == 413

    @pytest.mark.asyncio
    async def test_copy_across_user_quota_still_enforces_max_file_size(self, monkeypatch):
        """A copy still enforces the size limit; the skip only applies to intra-record moves."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        src_provider.NAME = 'osfstorage'
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(
                src_provider, src_path, dest_provider, max_size_bytes=100,
                check_quota=True, operation='copy'
            )
        assert exc.value.code == 413

    @pytest.mark.asyncio
    async def test_move_to_other_storage_type_still_enforces_max_file_size(self, monkeypatch):
        """A move into a different UserQuota record (other storage_type) still re-uploads,
        so the size limit still applies."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/folder/', prepend=None)
        dest_provider = MockProvider()

        src_provider.NAME = 'osfstorage'
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 100_000, 'user_guid': 'user-a', 'storage_type': 2})

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(
                src_provider, src_path, dest_provider, max_size_bytes=100,
                check_quota=True, operation='move'
            )
        assert exc.value.code == 413

    @pytest.mark.asyncio
    async def test_move_non_osfstorage_different_project_still_enforces_max_file_size(self, monkeypatch):
        """Destinations that have no quota to check (non-osfstorage) still enforce the
        size limit when source and destination are different projects -- no quota lookup
        happens at all."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider(settings={'nid': 'node-1'})
        dest_provider = MockProvider(settings={'nid': 'node-2'})
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        dest_provider.get_quota = MockCoroutine(
            side_effect=AssertionError('no quota lookup when check_quota is False')
        )

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(
                src_provider, src_path=WaterButlerPath('/folder/', prepend=None), dest_provider=dest_provider,
                max_size_bytes=100, operation='move', src_nid='node-1', dest_nid='node-2'
            )
        assert exc.value.code == 413
        dest_provider.get_quota.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_non_osfstorage_different_project_enforces_even_when_provider_nid_matches(self, monkeypatch):
        """Regression for the customer-review-4 `provider.nid` trap: even if the provider
        objects themselves carry an equal (or equally None) `.nid`, the decision must use
        the caller-supplied src_nid/dest_nid -- so a genuine cross-project move is never
        wrongly exempted."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider(settings={'nid': None})
        dest_provider = MockProvider(settings={'nid': None})
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        dest_provider.get_quota = MockCoroutine(
            side_effect=AssertionError('no quota lookup when check_quota is False')
        )

        with pytest.raises(exceptions.InvalidParameters) as exc:
            await run_pre_checks(
                src_provider, src_path=WaterButlerPath('/folder/', prepend=None), dest_provider=dest_provider,
                max_size_bytes=100, operation='move', src_nid='node-1', dest_nid='node-2'
            )
        assert exc.value.code == 413

    @pytest.mark.asyncio
    async def test_move_non_osfstorage_same_project_skips_max_file_size(self, monkeypatch):
        """A move between two extended-storage locations that is BOTH the same storage
        type AND the same project must skip max_file_size too."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider(settings={'nid': 'node-1'})
        dest_provider = MockProvider(settings={'nid': 'node-1'})
        src_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(6000, name='huge.bin')]
        )
        dest_provider.get_quota = MockCoroutine(
            side_effect=AssertionError('no quota lookup when check_quota is False')
        )

        await run_pre_checks(
            src_provider, src_path=WaterButlerPath('/folder/', prepend=None), dest_provider=dest_provider,
            max_size_bytes=100, operation='move', src_nid='node-1', dest_nid='node-1'
        )
        src_provider.metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_folder_pre_check_matches_replaced_item_by_kind(self, monkeypatch):
        """A folder move onto a same-named file frees nothing, so the quota formula must
        not subtract that file's size."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        src_path = WaterButlerPath('/data/', prepend=None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)

        src_provider.metadata = MockCoroutine(return_value=[MockFileMetadataWithSize(600, name='new.txt')])
        # A *file* named 'data' at the destination: same name, different kind.
        dest_provider.metadata = MockCoroutine(
            return_value=[MockFileMetadataWithSize(500, name='data')]
        )
        dest_provider.get_quota = MockCoroutine(return_value={'used': 900, 'max': 1000, 'user_guid': 'user-b', 'storage_type': 1})
        src_provider.get_quota = MockCoroutine(return_value={'used': 0, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})

        # 900 + 600 - 0 (nothing replaced) = 1500 > 1000 -> must be refused.
        with pytest.raises(exceptions.NotEnoughQuotaError):
            await run_pre_checks(
                src_provider, src_path, dest_provider, dest_path=dest_container_path,
                check_quota=True, operation='copy', conflict='replace'
            )


# ---------------------------------------------------------------------------
# Celery Task Integration Tests
# ---------------------------------------------------------------------------

class TestPreChecksTaskIntegration:

    def test_copy_task_calls_pre_checks(self, monkeypatch, providers, bundles, callback):
        """Copy task should execute pre-checks before triggering copy."""
        src, dest = providers
        src_bundle, dest_bundle = bundles

        mock_run_pre_checks = MockCoroutine()
        monkeypatch.setattr(copy_module, 'run_pre_checks', mock_run_pre_checks)

        copy_task(
            cp.deepcopy(src_bundle),
            cp.deepcopy(dest_bundle),
            max_size_bytes=1000,
            check_quota=True
        )

        mock_run_pre_checks.assert_called_once_with(
            src, src_bundle['path'], dest,
            dest_path=dest_bundle['path'],
            max_size_bytes=1000,
            check_quota=True,
            operation='copy',
            conflict=DEFAULT_CONFLICT,
            rename=None,
            src_nid=src_bundle['nid'], dest_nid=dest_bundle['nid']
        )
        assert src.copy.called

    def test_move_task_calls_pre_checks(self, monkeypatch, providers, bundles, callback):
        """Move task should execute pre-checks before triggering move."""
        src, dest = providers
        src_bundle, dest_bundle = bundles

        mock_run_pre_checks = MockCoroutine()
        monkeypatch.setattr(move_module, 'run_pre_checks', mock_run_pre_checks)

        src.move.return_value = (MockFileMetadata(), True)

        move_task(
            cp.deepcopy(src_bundle),
            cp.deepcopy(dest_bundle),
            max_size_bytes=1000,
            check_quota=True
        )

        mock_run_pre_checks.assert_called_once_with(
            src, src_bundle['path'], dest,
            dest_path=dest_bundle['path'],
            max_size_bytes=1000,
            check_quota=True,
            operation='move',
            conflict=DEFAULT_CONFLICT,
            rename=None,
            src_nid=src_bundle['nid'], dest_nid=dest_bundle['nid']
        )
        assert src.move.called

    def test_copy_task_forwards_conflict_and_rename_to_pre_checks(self, monkeypatch, providers, bundles, callback):
        """conflict/rename passed to the celery task (e.g. from an explicit replace request)
        must reach run_pre_checks unchanged, not just the defaults."""
        src, dest = providers
        src_bundle, dest_bundle = bundles

        mock_run_pre_checks = MockCoroutine()
        monkeypatch.setattr(copy_module, 'run_pre_checks', mock_run_pre_checks)

        copy_task(
            cp.deepcopy(src_bundle),
            cp.deepcopy(dest_bundle),
            max_size_bytes=1000,
            check_quota=True,
            conflict='replace',
            rename='renamed.txt'
        )

        mock_run_pre_checks.assert_called_once_with(
            src, src_bundle['path'], dest,
            dest_path=dest_bundle['path'],
            max_size_bytes=1000,
            check_quota=True,
            operation='copy',
            conflict='replace',
            rename='renamed.txt',
            src_nid=src_bundle['nid'], dest_nid=dest_bundle['nid']
        )

    def test_copy_task_pre_checks_failure_aborts_copy(self, monkeypatch, providers, bundles, callback):
        """Copy task should abort and raise if pre-checks raise InvalidParameters."""
        src, dest = providers
        src_bundle, dest_bundle = bundles

        mock_run_pre_checks = MockCoroutine(side_effect=exceptions.InvalidParameters('Oversized files', code=413))
        monkeypatch.setattr(copy_module, 'run_pre_checks', mock_run_pre_checks)

        with pytest.raises(exceptions.InvalidParameters):
            copy_task(
                cp.deepcopy(src_bundle),
                cp.deepcopy(dest_bundle),
                max_size_bytes=1000,
                check_quota=True
            )

        assert not src.copy.called

    def test_move_task_pre_checks_failure_aborts_move(self, monkeypatch, providers, bundles, callback):
        """Move task should abort and raise if pre-checks raise NotEnoughQuotaError."""
        src, dest = providers
        src_bundle, dest_bundle = bundles

        mock_run_pre_checks = MockCoroutine(side_effect=exceptions.NotEnoughQuotaError('Quota exceeded'))
        monkeypatch.setattr(move_module, 'run_pre_checks', mock_run_pre_checks)

        with pytest.raises(exceptions.NotEnoughQuotaError):
            move_task(
                cp.deepcopy(src_bundle),
                cp.deepcopy(dest_bundle),
                max_size_bytes=1000,
                check_quota=True
            )

        assert not src.move.called
