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
from waterbutler.tasks.pre_checks import run_pre_checks
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
            max_size_bytes=1000,
            check_quota=True
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
            max_size_bytes=1000,
            check_quota=True
        )
        assert src.move.called

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
