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
from waterbutler.tasks.pre_checks import run_pre_checks, get_replaced_size, evaluate_quota
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

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo.txt', 'keep')

        assert size == 0
        dest_provider.metadata.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_replaced_size_zero_when_no_matching_child(self, monkeypatch):
        """conflict='replace' but nothing at the destination shares the incoming name -> 0."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        dest_provider = MockProvider()
        dest_container_path = WaterButlerPath('/dest/', prepend=None)
        dest_provider.metadata = MockCoroutine(return_value=[MockFileMetadataWithSize(999, name='Other.txt')])

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo.txt', 'replace')

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

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo.txt', 'replace')

        assert size == 500

    @pytest.mark.asyncio
    async def test_get_replaced_size_sums_matching_folder_recursively(self, monkeypatch):
        """conflict='replace' with a matching FOLDER at the destination -> sum of everything
        inside it, recursively — this is the folder-replace gap the customer flagged."""
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

        size = await get_replaced_size(dest_provider, dest_container_path, 'Foo', 'replace')

        assert size == 500
        dest_provider.validate_path.assert_called_once_with('/dest/Foo/')

    @pytest.mark.asyncio
    async def test_folder_pre_check_quota_subtracts_replaced_folder_size(self, monkeypatch):
        """run_pre_checks on a folder replace must subtract the existing destination folder's
        total size, not just check used + new_size blindly (the customer's 'yêu cầu bổ sung')."""
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
        """Callers that don't pass dest_path (none currently do, until Task 4/5) keep today's
        behavior exactly — replaced_size is 0, no extra metadata calls happen."""
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
        """D.7: when the move stays within one UserQuota record, run_pre_checks must bail
        out of the quota check BEFORE recursing into the source folder tree — the size
        would only be discarded by evaluate_quota()'s skip anyway."""
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
        """D.7: same-UserQuota-record moves must also skip get_replaced_size() — there is
        no destination lookup to make when the check itself will be skipped."""
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
    async def test_evaluate_quota_wrapper_still_skips_and_raises(self, monkeypatch):
        """D.7: evaluate_quota() has no remaining caller in this codebase after the split
        into resolve_quota_context()/check_quota_limit(), but it is kept as a public
        convenience wrapper -- this protects its contract for any caller outside this repo."""
        monkeypatch.setattr(time, 'sleep', lambda sec: None)
        src_provider = MockProvider()
        dest_provider = MockProvider()

        # Same UserQuota record: must not raise even though used + file_size > max.
        src_provider.NAME = 'osfstorage'
        src_provider.get_quota = MockCoroutine(return_value={'used': 900, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        dest_provider.get_quota = MockCoroutine(return_value={'used': 900, 'max': 1000, 'user_guid': 'user-a', 'storage_type': 1})
        await evaluate_quota('move', src_provider, dest_provider, 600)

        # Different UserQuota record: must raise when the limit is actually exceeded.
        dest_provider.get_quota = MockCoroutine(return_value={'used': 900, 'max': 1000, 'user_guid': 'user-b', 'storage_type': 1})
        with pytest.raises(exceptions.NotEnoughQuotaError) as exc:
            await evaluate_quota('move', src_provider, dest_provider, 600)
        assert exc.value.data['message_key'] == 'quota_exceeded'


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
            rename=None
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
            rename=None
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
            rename='renamed.txt'
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
