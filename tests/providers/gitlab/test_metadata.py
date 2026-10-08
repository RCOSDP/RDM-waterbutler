from urllib.parse import unquote

from waterbutler.providers.gitlab.path import GitLabPath
from waterbutler.providers.gitlab.metadata import GitLabFileMetadata, GitLabFolderMetadata


COMMIT_SHA = 'a1b2c3d4'
BRANCH = 'master'


class TestGitLabMetadataMaterializedPath:
    """materialized_path must be the decoded, human-readable name (used for display),
    while path stays percent-encoded (used to build URLs) -- they must differ for
    names containing characters that need URL-encoding.
    """

    def test_file_materialized_path_is_decoded(self):
        materialized = '/フォルダ/テスト.txt'
        _ids = [(COMMIT_SHA, BRANCH) for _ in materialized.rstrip('/').split('/')]
        gl_path = GitLabPath(materialized, _ids=_ids)
        gl_metadata = GitLabFileMetadata({}, gl_path, host='http://base.url', owner='cat', repo='food')

        assert gl_metadata.materialized_path == materialized
        assert gl_metadata.path != materialized
        assert unquote(gl_metadata.path) == materialized

    def test_folder_materialized_path_is_decoded(self):
        materialized = '/フォルダ/サブフォルダ/'
        _ids = [(None, BRANCH) for _ in materialized.rstrip('/').split('/')]
        gl_path = GitLabPath(materialized, _ids=_ids)
        gl_metadata = GitLabFolderMetadata({}, gl_path)

        assert gl_metadata.materialized_path == materialized
        assert gl_metadata.path != materialized
        assert unquote(gl_metadata.path) == materialized

    def test_materialized_path_matches_path_for_ascii_name(self):
        materialized = '/folder1/folder2/file'
        _ids = [(COMMIT_SHA, BRANCH) for _ in materialized.rstrip('/').split('/')]
        gl_path = GitLabPath(materialized, _ids=_ids)
        gl_metadata = GitLabFileMetadata({}, gl_path, host='http://base.url', owner='cat', repo='food')

        assert gl_metadata.materialized_path == materialized
        assert gl_metadata.path == materialized
