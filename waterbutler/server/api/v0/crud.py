import os
import socket
import asyncio
from http import HTTPStatus

import tornado.web
import tornado.gen
import tornado.platform.asyncio

from waterbutler.core import mime_types
from waterbutler.server import utils
from waterbutler.server.api.v0 import core
from waterbutler.core.utils import make_disposition
from waterbutler.core.streams import RequestStreamReader

TRUTH_MAP = {
    'true': True,
    'false': False,
}


@tornado.web.stream_request_body
class CRUDHandler(core.BaseProviderHandler):

    ACTION_MAP = {
        'GET': 'download',
        'PUT': 'upload',
        'DELETE': 'delete',
        'POST': 'create_folder',
    }
    STREAM_METHODS = ('PUT', )

    async def prepare(self):
        await super().prepare()
        await self.prepare_stream()

    async def prepare_stream(self):
        if self.request.method in self.STREAM_METHODS:
            self.rsock, self.wsock = socket.socketpair()
            self.rsock.setblocking(False)
            self.wsock.setblocking(False)

            self.rfd = os.fdopen(self.rsock.detach(), 'rb', 0)
            self.wfd = os.fdopen(self.wsock.detach(), 'wb', 0)

            self.reader = asyncio.StreamReader()
            reader_protocol = asyncio.StreamReaderProtocol(self.reader)
            loop = asyncio.get_running_loop()
            await loop.connect_read_pipe(lambda: reader_protocol, self.rfd)

            writer_transport, _ = await loop.connect_write_pipe(asyncio.Protocol, self.wfd)
            self.writer = asyncio.StreamWriter(writer_transport, reader_protocol, self.reader, loop)

            self.stream = RequestStreamReader(self.request, self.reader)

            self.uploader = asyncio.ensure_future(self.provider.upload(self.stream,
                                                 **self.arguments))
        else:
            self.stream = None

    async def data_received(self, chunk):
        """Note: Only called during uploads."""
        self.bytes_uploaded += len(chunk)
        if self.stream:
            self.writer.write(chunk)
            await self.writer.drain()

    async def get(self):
        """Download a file."""
        try:
            self.arguments['accept_url'] = TRUTH_MAP[self.arguments.get('accept_url', 'true').lower()]
        except KeyError:
            raise tornado.web.HTTPError(status_code=400)

        if 'Range' in self.request.headers:
            request_range = utils.parse_request_range(self.request.headers['Range'])
        else:
            request_range = None

        result = await self.provider.download(range=request_range, **self.arguments)

        if isinstance(result, str):
            self.redirect(result)
            self._send_hook('download_file', path=self.path)
            return

        if getattr(result, 'partial', None):
            # Use getattr here as not all stream may have a partial attribute
            # Plus it fixes tests
            self.set_status(206)
            self.set_header('Content-Range', result.content_range)

        if result.content_type is not None:
            self.set_header('Content-Type', result.content_type)

        if result.size is not None:
            self.set_header('Content-Length', str(result.size))

        # Build `Content-Disposition` header from `displayName` override,
        # headers of provider response, or file path, whichever is truthy first
        name = self.arguments.get('displayName') or getattr(result, 'name', None) or self.path.name
        self.set_header('Content-Disposition', make_disposition(name))

        _, ext = os.path.splitext(name)
        # If the file extention is in mime_types
        # override the content type to fix issues with safari shoving in new file extensions
        if ext in mime_types:
            self.set_header('Content-Type', mime_types[ext])

        await self.write_stream(result)
        self._send_hook('download_file', path=self.path)

    async def post(self):
        """Create a folder"""
        metadata = await self.provider.create_folder(**self.arguments)

        self.set_status(201)
        self.write(metadata.serialized())

        self._send_hook('create_folder', metadata)

    async def put(self):
        """Upload a file."""
        self.writer.write_eof()

        metadata, created = await self.uploader

        if created:
            self.set_status(201)
        self.write(metadata.serialized())

        self.writer.close()
        await self.writer.wait_closed()
        self.wsock.close()
        self.rsock.close()
        self.rfd.close()
        self.wfd.close()

        self._send_hook(
            'create' if created else 'update',
            metadata,
        )

    async def delete(self):
        """Delete a file."""

        await self.provider.delete(**self.arguments)
        self.set_status(int(HTTPStatus.NO_CONTENT))

        self._send_hook('delete', path=self.path)
