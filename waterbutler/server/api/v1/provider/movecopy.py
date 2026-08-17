import json
from http import HTTPStatus

from waterbutler import tasks
from waterbutler.sizes import MBs
from waterbutler.core import exceptions
from waterbutler.server import settings
from waterbutler.core.auth import AuthType
from waterbutler.core import remote_logging
from waterbutler.server.auth import AuthHandler
from waterbutler.core.utils import make_provider
from waterbutler.constants import DEFAULT_CONFLICT
from waterbutler.auth.osf.handler import EXPORT_DATA_FAKE_NODE_ID
from waterbutler.tasks.settings import SYNCHRONOUS_TIMEOUT
from waterbutler.tasks.pre_checks import (
    run_pre_checks, get_replaced_size, resolve_quota_context, check_quota_limit,
)

auth_handler = AuthHandler(settings.AUTH_HANDLERS)


class MoveCopyMixin:

    @property
    def json(self):
        if not hasattr(self, '_json'):
            try:
                # self.body is defined by self.data_received
                self._json = json.loads(self.body.decode())
            except ValueError:
                raise exceptions.InvalidParameters('Invalid json body')
        return self._json

    def prevalidate_post(self):
        """Validate body and query parameters before spending API calls on validating path.  We
        don't trust path yet, so I don't wanna see it being used here.  Current validations:

        1. Max body size is 1Mb.
        2. Content-Length header must be provided.
        """
        try:
            if int(self.request.headers['Content-Length']) > 1 * MBs:
                # There should be no JSON body > 1 megs
                raise exceptions.InvalidParameters('Request body must be under 1Mb', code=413)
        except (KeyError, ValueError):
            raise exceptions.InvalidParameters('Content-Length is required', code=411)

    def build_args(self):
        return ({
            'nid': self.resource,  # TODO rename to anything but nid
            'path': self.path,
            'provider': self.provider.serialized()
        }, {
            'nid': self.dest_resource,
            'path': self.dest_path,
            'provider': self.dest_provider.serialized()
        })

    async def move_or_copy(self):
        """Copy, move, and rename files and folders.

        **Auth actions**: ``copy``, ``move``, or ``rename``

        **Provider actions**: ``copy`` or ``move``

        *Auth actions* come from the ``action`` body parameter in the request and are used by the
        auth handler.

        *Provider actions* are determined from the *auth action*.  A "rename" is a special case of
        the "move" provider action that implies that the destination resource, provider, and parent
        path will all be the same as the source.
        """

        auth_action = self.json.get('action', 'null')
        if auth_action not in ('copy', 'move', 'rename'):
            raise exceptions.InvalidParameters('Auth action must be "copy", "move", or "rename", '
                                               'not "{}"'.format(auth_action))

        # Provider setup is delayed so the provider action can be updated from the auth action.
        provider = self.path_kwargs.get('provider', '')
        provider_action = auth_action
        if auth_action == 'rename':
            if not self.json.get('rename', ''):
                raise exceptions.InvalidParameters('"rename" field is required for renaming')
            provider_action = 'move'

        if self.resource == EXPORT_DATA_FAKE_NODE_ID:
            self.location_id = self.get_query_argument('location_id', default=None)

        self.auth = await auth_handler.get(
            self.resource,
            provider,
            self.request,
            action=auth_action,
            auth_type=AuthType.SOURCE,
            path=self.path,
            version=self.requested_version,
            location_id=self.location_id,
        )
        self.provider = make_provider(
            provider,
            self.auth['auth'],
            self.auth['credentials'],
            self.auth['settings']
        )
        self.path = await self.provider.validate_v1_path(self.path, **self.arguments)
        check_kwargs = {}
        if auth_action == 'rename':  # 'rename' implies the file/folder does not change location
            self.dest_auth = self.auth
            self.dest_provider = self.provider
            self.dest_path = self.path.parent
            self.dest_resource = self.resource
            conflict = self.json.get('conflict', DEFAULT_CONFLICT)
        else:
            path = self.json.get('path', None)
            if path is None:
                raise exceptions.InvalidParameters('"path" field is required for moves or copies')
            if not path.endswith('/'):
                raise exceptions.InvalidParameters(
                    '"path" field requires a trailing slash to indicate it is a folder'
                )

            # TODO optimize for same provider and resource

            # for copy action, `auth_action` is the same as `provider_action`
            if auth_action == 'copy' and self.path.is_root and not self.json.get('rename'):
                raise exceptions.InvalidParameters('"rename" field is required for copying root')

            # Note: attached to self so that _send_hook has access to these
            self.dest_resource = self.json.get('resource', self.resource)

            if self.dest_resource == EXPORT_DATA_FAKE_NODE_ID:
                self.location_id = self.get_query_argument('location_id', default=None)

            self.dest_auth = await auth_handler.get(
                self.dest_resource,
                self.json.get('provider', self.provider.NAME),
                self.request,
                action=auth_action,
                auth_type=AuthType.DESTINATION,
                path=path,
                location_id=self.location_id,
            )
            self.dest_provider = make_provider(
                self.json.get('provider', self.provider.NAME),
                self.dest_auth['auth'],
                self.dest_auth['credentials'],
                self.dest_auth['settings']
            )
            self.dest_path = await self.dest_provider.validate_path(**self.json)

            conflict = self.json.get('conflict', DEFAULT_CONFLICT)

            # Check if the file/folder is oversized
            max_size_mb = self.dest_auth['settings'].get('max_file_size')
            max_size_bytes = (int(max_size_mb) * 1024 * 1024) if max_size_mb else None

            if not self.path.is_dir:
                # Single-file path: read metadata once and check inline.
                # No recursion needed — the item is guaranteed to be a file.
                file_meta = await self.provider.metadata(
                    self.path, version=None, revision=None
                )
                file_size = int(file_meta.size)

                # Check max_file_size
                if max_size_bytes and file_size > max_size_bytes:
                    raise exceptions.InvalidParameters({
                        'message': 'Move/Copy Failed due to oversized files.',
                        'oversized_files': [{'name': file_meta.name, 'size': file_size}],
                        'max_size': max_size_bytes,
                    }, code=413)

                # Check quota (osfstorage only)
                if self.dest_provider.NAME == 'osfstorage':
                    skip, dest_quota = await resolve_quota_context(
                        provider_action, self.provider, self.dest_provider
                    )
                    if not skip:
                        resolved_name = self.json.get('rename') or self.path.name
                        replaced_size = await get_replaced_size(
                            self.dest_provider, self.dest_path, resolved_name, conflict
                        )
                        check_quota_limit(dest_quota, file_size, replaced_size)
                check_kwargs = {
                    'max_size_bytes': None,
                    'check_quota': False,
                }
            else:
                check_kwargs = {
                    'max_size_bytes': max_size_bytes,
                    'check_quota': (self.dest_provider.NAME == 'osfstorage'),
                }

        if not getattr(self.provider, 'can_intra_' + provider_action)(self.dest_provider, self.path):
            # this weird signature syntax courtesy of py3.4 not liking trailing commas on kwargs
            conflict = self.json.get('conflict', DEFAULT_CONFLICT)
            task_kwargs = {}
            if provider_action == 'copy':
                # Only copy API has additional 'version' argument
                task_kwargs = {'version': self.requested_version}
            result = await getattr(tasks, provider_action).adelay(
                rename=self.json.get('rename'),
                conflict=conflict,
                request=remote_logging._serialize_request(self.request),
                *self.build_args(),
                **task_kwargs,
                **check_kwargs,
            )
            synchronous = self.json.get('synchronous', 'false')
            synchronous = True if isinstance(synchronous, bool) and synchronous is True else False
            if synchronous:
                # Use SYNCHRONOUS_TIMEOUT value for synchronous processes
                metadata, created = await tasks.wait_on_celery(result, timeout=SYNCHRONOUS_TIMEOUT)
            else:
                # Use default timeout value for asynchronous processes
                metadata, created = await tasks.wait_on_celery(result)
        else:
            async def _intra_task():
                if self.path.is_dir:
                    await run_pre_checks(
                        self.provider, self.path, self.dest_provider,
                        dest_path=self.dest_path,
                        operation=provider_action,
                        conflict=conflict,
                        rename=self.json.get('rename'),
                        **check_kwargs
                    )
                return await getattr(self.provider, provider_action)(
                    self.dest_provider,
                    self.path,
                    self.dest_path,
                    rename=self.json.get('rename'),
                    conflict=conflict,
                )

            metadata, created = await tasks.backgrounded(_intra_task)

        self.dest_meta = metadata

        if created:
            self.set_status(int(HTTPStatus.CREATED))
        else:
            self.set_status(int(HTTPStatus.OK))

        self.write({'data': metadata.json_api_serialized(self.dest_resource)})
