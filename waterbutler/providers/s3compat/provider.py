import os
import hashlib
import functools
from http import HTTPStatus
from urllib import parse
import re
import logging
import xml.sax.saxutils
from xml.parsers.expat import ExpatError
from io import BytesIO
import base64

import xmltodict
from botocore.auth import HmacV1QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from waterbutler.core import streams, provider, exceptions
from waterbutler.core.path import WaterButlerPath
from waterbutler.core.utils import make_disposition
from waterbutler.providers.s3compat import settings
from waterbutler.providers.s3compat.metadata import (
    S3CompatRevision,
    S3CompatFileMetadata,
    S3CompatFolderMetadata,
    S3CompatFolderKeyMetadata,
    S3CompatFileMetadataHeaders,
)

logger = logging.getLogger(__name__)


def compute_md5(fp):
    """Compute MD5 hash for file-like object."""
    m = hashlib.md5()
    data = fp.read()
    m.update(data)
    fp.seek(0)
    return m.digest(), base64.b64encode(m.digest()).decode('utf-8')


class S3CompatConnection:
    """Builds signature-version-2 URLs for the S3 compatible storage.

    Requests are assembled here (path-style URL with the bucket as the first path segment,
    sub-resources and query parameters as sent) and signed with botocore's query-string
    signer, so the signature always covers exactly what is sent, including Content-MD5,
    Content-Type and x-amz-* headers. Signature version 2 is kept on purpose: the storages
    this provider targets do not necessarily support signature version 4.
    """

    # query parameter names as used by the S3 REST API, keyed by the names callers pass
    QUERY_PARAMETERS = {
        'Prefix': 'prefix',
        'Delimiter': 'delimiter',
        'MaxKeys': 'max-keys',
        'Marker': 'marker',
        'KeyMarker': 'key-marker',
        'VersionIdMarker': 'version-id-marker',
        'VersionId': 'versionId',
        'UploadId': 'uploadId',
        'PartNumber': 'partNumber',
        'EncodingType': 'encoding-type',
        'ResponseContentDisposition': 'response-content-disposition',
        'ResponseContentType': 'response-content-type',
        'ResponseContentEncoding': 'response-content-encoding',
        'ResponseContentLanguage': 'response-content-language',
        'ResponseCacheControl': 'response-cache-control',
        'ResponseExpires': 'response-expires',
    }

    # sub-resource that identifies each operation, when the operation has one
    SUBRESOURCES = {
        'list_object_versions': 'versions',
        'create_multipart_upload': 'uploads',
        'delete_objects': 'delete',
    }

    # operations whose listing responses are requested URL-encoded
    URL_ENCODED_LISTINGS = ('list_objects', 'list_object_versions')

    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None, endpoint_url=None):
        self.endpoint_url = endpoint_url.rstrip('/')
        self.credentials = Credentials(aws_access_key_id, aws_secret_access_key)

    @staticmethod
    def copy_source_header(copy_source):
        """The x-amz-copy-source header value for ``bucket/key``."""
        return '/' + parse.quote(copy_source)

    def generate_presigned_url(self, ClientMethod, Params=None, ExpiresIn=settings.TEMP_URL_SECS,
                               HttpMethod=None, Headers=None):
        """Return a signed URL for the operation ``ClientMethod``.

        :param str ClientMethod: operation name (``list_objects``, ``put_object``, ...)
        :param dict Params: ``Bucket``, optional ``Key`` and the operation's parameters
        :param int ExpiresIn: lifetime of the signature in seconds
        :param str HttpMethod: HTTP method the caller will use
        :param dict Headers: request headers the caller will send that take part in the
            signature (Content-MD5, Content-Type, x-amz-*); they must be sent unchanged
        """
        params = dict(Params or {})
        bucket = params.pop('Bucket')
        key = params.pop('Key', '')

        headers = {}
        if 'ServerSideEncryption' in params:
            headers['x-amz-server-side-encryption'] = params.pop('ServerSideEncryption')
        if 'CopySource' in params:
            headers['x-amz-copy-source'] = self.copy_source_header(params.pop('CopySource'))
        headers.update(Headers or {})

        query = []
        subresource = self.SUBRESOURCES.get(ClientMethod)
        if subresource:
            query.append((subresource, None))
        for name, value in params.items():
            if name not in self.QUERY_PARAMETERS:
                raise ValueError('Unsupported parameter for {}: {}'.format(ClientMethod, name))
            query.append((self.QUERY_PARAMETERS[name], str(value)))
        if ClientMethod in self.URL_ENCODED_LISTINGS:
            query.append(('encoding-type', 'url'))

        # Sub-resources are signed without a value; the storage canonicalizes them the same
        # way. They are sent as ``name=`` afterwards (see below).
        query_string = '&'.join(
            name if value is None else '{}={}'.format(name, parse.quote(value, safe=''))
            for name, value in query
        )
        url = '{}/{}/{}'.format(self.endpoint_url, bucket, parse.quote(key, safe='/'))
        if query_string:
            url += '?' + query_string

        request = AWSRequest(method=HttpMethod, url=url, headers=headers)
        HmacV1QueryAuth(self.credentials, expires=ExpiresIn).add_auth(request)

        # The signer copies x-amz-* headers into the query string; they are sent as headers,
        # so drop the copies. Every query element is sent as ``name=value``: storages that
        # verify query-string signatures strictly reject a bare sub-resource name.
        scheme, netloc, path, _, signed_query, _ = parse.urlparse(request.url)
        pairs = []
        for element in signed_query.split('&'):
            name = element.split('=', 1)[0]
            if name.lower().startswith('x-amz-'):
                continue
            pairs.append(element if '=' in element else element + '=')
        return parse.urlunparse((scheme, netloc, path, '', '&'.join(pairs), ''))


class S3CompatProvider(provider.BaseProvider):
    """Provider for S3 Compatible Storage (SigV4) service.

    API docs: http://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html

    Quirks:

    * On S3, folders are not first-class objects, but are instead inferred
      from the names of their children.  A regular DELETE request issued
      against a folder will not work unless that folder is completely empty.
      To fully delete an occupied folder, we must delete all of the comprising
      objects.  Amazon provides a bulk delete operation to simplify this.

    * A GET prefix query against a non-existent path returns 200
    """

    NAME = 's3compat'
    ACCEPTS_FILE_SIZE_FOR_INTRA = True
    CHUNK_SIZE = settings.CHUNK_SIZE
    CONTIGUOUS_UPLOAD_SIZE_LIMIT = settings.CONTIGUOUS_UPLOAD_SIZE_LIMIT
    FILE_SIZE_INTRA_COPY_LIMIT = settings.FILE_SIZE_INTRA_COPY_LIMIT

    def __init__(self, auth, credentials, settings, **kwargs):
        """
        :param dict auth: Not used
        :param dict credentials: Dict containing `access_key`, `secret_key`, `host`
        :param dict settings: Dict containing `bucket` and optional `region`, `prefix`
        """
        super().__init__(auth, credentials, settings, **kwargs)

        host = credentials['host']
        port = 443
        m = re.match(r'^(.+)\:([0-9]+)$', host)
        if m is not None:
            host = m.group(1)
            port = int(m.group(2))

        is_secure = (port == 443)
        protocol = 'https' if is_secure else 'http'
        if port in (80, 443):
            endpoint_url = '{}://{}'.format(protocol, host)
        else:
            endpoint_url = '{}://{}:{}'.format(protocol, host, port)

        self.bucket_name = self.settings['bucket']
        self.encrypt_uploads = self.settings.get('encrypt_uploads', False)
        self.region = self.settings.get('region', None)
        self.prefix = self.settings.get('prefix', '')

        self.connection = S3CompatConnection(
            aws_access_key_id=credentials['access_key'],
            aws_secret_access_key=credentials['secret_key'],
            endpoint_url=endpoint_url,
        )

    async def validate_v1_path(self, path, **kwargs):
        wbpath = WaterButlerPath(path, prepend=self.prefix)
        if path == '/':
            return wbpath

        implicit_folder = path.endswith('/')

        prefix = wbpath.full_path.lstrip('/')  # '/' -> '', '/A/B' -> 'A/B'
        if implicit_folder:
            query_parameters = {
                'Bucket': self.bucket_name,
                'Prefix': prefix,
                'Delimiter': '/',
            }
            resp = await self.make_request(
                'GET',
                functools.partial(
                    self.connection.generate_presigned_url,
                    'list_objects',
                    Params=query_parameters,
                    HttpMethod='GET',
                ),
                expects=(
                    HTTPStatus.OK,
                    HTTPStatus.NOT_FOUND,
                ),
                throws=exceptions.MetadataError,
            )
        else:
            query_parameters = {'Bucket': self.bucket_name, 'Key': prefix}
            resp = await self.make_request(
                'HEAD',
                functools.partial(
                    self.connection.generate_presigned_url,
                    'head_object',
                    Params=query_parameters,
                    HttpMethod='HEAD',
                ),
                expects=(
                    HTTPStatus.OK,
                    HTTPStatus.NOT_FOUND,
                ),
                throws=exceptions.MetadataError,
            )

        await resp.release()

        if resp.status == HTTPStatus.NOT_FOUND:
            raise exceptions.NotFoundError(str(prefix))

        return wbpath

    async def validate_path(self, path, **kwargs):
        return WaterButlerPath(path, prepend=self.prefix)

    def can_duplicate_names(self):
        return True

    def can_intra_copy(self, dest_provider, path=None, file_size=None):
        if file_size is None or file_size > self.FILE_SIZE_INTRA_COPY_LIMIT:
            return False
        return type(self) is type(dest_provider) and not path.is_dir

    def can_intra_move(self, dest_provider, path=None, file_size=None):
        if file_size is None or file_size > self.FILE_SIZE_INTRA_COPY_LIMIT:
            return False
        return type(self) is type(dest_provider) and not path.is_dir

    async def intra_copy(self, dest_provider, source_path, dest_path):
        """Copy key from one S3 Compatible Storage bucket to another. The credentials specified in
        `dest_provider` must have read access to `source.bucket`.
        """
        exists = await dest_provider.exists(dest_path)

        # ensure no left slash when joining paths
        copy_source = os.path.join(self.settings['bucket'], source_path.full_path.lstrip('/'))
        headers = {'x-amz-copy-source': S3CompatConnection.copy_source_header(copy_source)}
        query_parameters = {
            'Bucket': dest_provider.bucket_name,
            'Key': dest_path.full_path,
            'CopySource': copy_source,
        }
        resp = await self.make_request(
            'PUT',
            functools.partial(
                dest_provider.connection.generate_presigned_url,
                'copy_object',
                Params=query_parameters,
                HttpMethod='PUT',
            ),
            skip_auto_headers={'CONTENT-TYPE'},
            headers=headers,
            expects=(HTTPStatus.OK,),
            throws=exceptions.IntraCopyError,
        )

        response_body = await resp.read()
        self._check_for_200_error(response_body, 'CopyObject', exceptions.IntraCopyError)

        await resp.release()
        return (await dest_provider.metadata(dest_path)), not exists

    @staticmethod
    def _check_for_200_error(
        response_body,
        s3_api_name='S3 API',
        exception_type=exceptions.UnhandledProviderError,
    ):
        """check an S3 API result with http status is 200 OK.

        try to parse response body as a xml.
        if the xml has an 'Error' element then raise an exception.

        :param str response_body: API response body.
        :param str s3_api_name: S3 API name for logging.
        :param type exception_type: raise Exception type
        """
        try:
            # memo: If no element, the parser will raise an ExpatError.
            result = xmltodict.parse(response_body)
        except ExpatError:
            logger.warning('Couldn\'t parse %s result', s3_api_name)
            raise

        if 'Error' in result:
            error_code = result['Error'].get('Code', 'Unknown')
            logger.warning('%s returned with an error: %s', s3_api_name, error_code)
            raise exception_type(
                f'{s3_api_name} returned with an error.',
                code=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    async def download(self, path, accept_url=False, revision=None, range=None, **kwargs):
        r"""Returns a ResponseWrapper (Stream) for the specified path
        raises FileNotFoundError if the status from S3 is not 200

        :param path: ( :class:`.WaterButlerPath` ) Path to the key you want to download
        :param kwargs: (dict) Additional arguments that are ignored
        :rtype: :class:`waterbutler.core.streams.ResponseStreamReader`
        :raises: :class:`waterbutler.core.exceptions.DownloadError`
        """
        if not path.is_file:
            raise exceptions.DownloadError('No file specified for download', code=HTTPStatus.BAD_REQUEST)

        # MEMO: This is a workaround for the bug on some callers.
        if revision is None and 'version' in kwargs:
            revision = kwargs['version']

        try:
            pre_size, pre_etag = await self._get_content_whole_size(path, revision)
            if range is not None:
                # MEMO: range type is (int, int)
                # see: core/provider.py _build_range_header()
                s, e = range
                if s is None or e is None:
                    pre_size = None
                elif s < 0 or s >= pre_size or e < 0 or e >= pre_size or e < s:
                    pre_size = None
                else:
                    pre_size = e - s + 1
        except exceptions.MetadataError:
            logger.debug('Could not retrieve metadata for pre-flight check, skipping')
            pre_size = None
            pre_etag = None

        if not revision or revision.lower() == 'latest':
            query_parameters = None
        else:
            query_parameters = {'VersionId': revision}

        display_name = kwargs.get('display_name') or path.name
        response_headers = {
            'ResponseContentDisposition': make_disposition(display_name)
        }

        query_parameters_dict = {'Bucket': self.bucket_name, 'Key': path.full_path}
        if query_parameters:
            query_parameters_dict.update(query_parameters)
        query_parameters_dict.update(response_headers)

        headers = {}
        resp = await self.make_request(
            'GET',
            functools.partial(
                self.connection.generate_presigned_url,
                'get_object',
                Params=query_parameters_dict,
                HttpMethod='GET',
            ),
            range=range,
            headers=headers,
            expects=(HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT),
            throws=exceptions.DownloadError,
        )

        try:
            get_etag = resp.headers['ETag'].replace('"', '')
            if get_etag != pre_etag:
                pre_size = None
        except KeyError:
            # ETag header may not be present in all responses
            pass

        download_stream = streams.ResponseStreamReader(resp)

        if hasattr(download_stream, '_size') and download_stream._size is None:
            # if the GetObject API doesn't return Content-Length header,
            # use metadata content-size or range size instead of it.
            download_stream._size = pre_size

        return download_stream

    async def _get_content_whole_size(self, path: WaterButlerPath, revision=None):
        """get content whole size from path."""
        metadata = await self.metadata(path, revision)
        try:
            size = metadata.size_as_int
            etag = metadata.etag
        except KeyError:
            raise exceptions.MetadataError('Cannot get content size and ETag')
        return size, etag

    async def upload(self, stream, path, conflict='replace', **kwargs):
        """Uploads the given stream to S3 Compatible Storage

        :param waterbutler.core.streams.RequestWrapper stream: The stream to put to S3 Compatible Storage
        :param path: ( :class:`.WaterButlerPath` ) The full path of the key to upload to/into

        :rtype: dict, bool
        """
        path, exists = await self.handle_name_conflict(path, conflict=conflict)

        if stream.size < self.CONTIGUOUS_UPLOAD_SIZE_LIMIT:
            await self._contiguous_upload(stream, path)
        else:
            await self._chunked_upload(stream, path)

        return (await self.metadata(path, **kwargs)), not exists

    async def _contiguous_upload(self, stream, path):
        """Uploads the given stream in one request."""

        stream.add_writer('md5', streams.HashStreamWriter(hashlib.md5))

        headers = {'Content-Length': str(stream.size)}
        query_parameters = {'Bucket': self.bucket_name, 'Key': path.full_path}

        # this is usually set in boto3 presigned url, but do it here
        # to be explicit about our header payloads for signing purposes
        if self.encrypt_uploads:
            headers['x-amz-server-side-encryption'] = 'AES256'
            query_parameters['ServerSideEncryption'] = 'AES256'

        resp = await self.make_request(
            'PUT',
            functools.partial(
                self.connection.generate_presigned_url,
                'put_object',
                Params=query_parameters,
                HttpMethod='PUT',
            ),
            data=stream,
            skip_auto_headers={'CONTENT-TYPE'},
            headers=headers,
            expects=(
                HTTPStatus.OK,
                HTTPStatus.CREATED,
            ),
            throws=exceptions.UploadError,
        )
        await resp.release()

        # md5 is returned as ETag header as long as server side encryption is not used.
        if stream.writers['md5'].hexdigest != resp.headers['ETag'].replace('"', ''):
            raise exceptions.UploadChecksumMismatchError()

    async def _chunked_upload(self, stream, path):
        """Uploads the given stream to S3 over multiple chunks"""

        # Step 1. Create a multi-part upload session
        session_upload_id = await self._create_upload_session(path)

        try:
            # Step 2. Break stream into chunks and upload them one by one
            parts_metadata = await self._upload_parts(stream, path, session_upload_id)
            # Step 3. Commit the parts and end the upload session
            await self._complete_multipart_upload(path, session_upload_id, parts_metadata)
        except Exception as err:
            msg = 'An unexpected error has occurred during the multi-part upload.'
            logger.error('{} upload_id={} error={!r}'.format(msg, session_upload_id, err))
            aborted = await self._abort_chunked_upload(path, session_upload_id)
            if aborted:
                msg += '  The abort action failed to clean up the temporary file parts generated ' \
                       'during the upload process.  Please manually remove them.'
            raise exceptions.UploadError(msg)

    async def _create_upload_session(self, path):
        """This operation initiates a multipart upload and returns an upload ID. This upload ID is
        used to associate all of the parts in the specific multipart upload. You specify this upload
        ID in each of your subsequent upload part requests (see Upload Part). You also include this
        upload ID in the final request to either complete or abort the multipart upload request.

        Docs: https://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadInitiate.html
        """

        headers = {}
        query_parameters = {'Bucket': self.bucket_name, 'Key': path.full_path}
        # "Initiate Multipart Upload" supports AWS server-side encryption
        if self.encrypt_uploads:
            headers = {'x-amz-server-side-encryption': 'AES256'}
            query_parameters['ServerSideEncryption'] = 'AES256'

        resp = await self.make_request(
            'POST',
            functools.partial(
                self.connection.generate_presigned_url,
                'create_multipart_upload',
                Params=query_parameters,
                ExpiresIn=200,
                HttpMethod='POST',
            ),
            headers=headers,
            skip_auto_headers={'CONTENT-TYPE'},
            expects=(
                HTTPStatus.OK,
                HTTPStatus.CREATED,
            ),
            throws=exceptions.UploadError,
        )
        upload_session_metadata = await resp.read()
        session_data = xmltodict.parse(upload_session_metadata, strip_whitespace=False)
        # Session upload id is the only info we need
        return session_data['InitiateMultipartUploadResult']['UploadId']

    async def _upload_parts(self, stream, path, session_upload_id):
        """Uploads all parts/chunks of the given stream to S3 one by one."""

        metadata = []
        parts = [self.CHUNK_SIZE for i in range(0, stream.size // self.CHUNK_SIZE)]
        if stream.size % self.CHUNK_SIZE:
            parts.append(stream.size - (len(parts) * self.CHUNK_SIZE))
        logger.debug('Multipart upload segment sizes: {}'.format(parts))
        for chunk_number, chunk_size in enumerate(parts):
            logger.debug('  uploading part {} with size {}'.format(chunk_number + 1, chunk_size))
            metadata.append(await self._upload_part(stream, path, session_upload_id,
                                                    chunk_number + 1, chunk_size))
        return metadata

    async def _upload_part(self, stream, path, session_upload_id, chunk_number, chunk_size):
        """Uploads a single part/chunk of the given stream to S3.

        :param int chunk_number: sequence number of chunk. 1-indexed.
        """

        cutoff_stream = streams.CutoffStream(stream, cutoff=chunk_size)

        headers = {'Content-Length': str(chunk_size)}
        query_parameters = {
            'Bucket': self.bucket_name,
            'Key': path.full_path,
            'PartNumber': chunk_number,
            'UploadId': session_upload_id,
        }

        resp = await self.make_request(
            'PUT',
            functools.partial(
                self.connection.generate_presigned_url,
                'upload_part',
                Params=query_parameters,
                ExpiresIn=200,
                HttpMethod='PUT',
            ),
            data=cutoff_stream,
            skip_auto_headers={'CONTENT-TYPE'},
            headers=headers,
            expects=(
                HTTPStatus.OK,
                HTTPStatus.CREATED,
            ),
            throws=exceptions.UploadError,
        )
        await resp.release()
        return resp.headers

    async def _abort_chunked_upload(self, path, session_upload_id):
        """This operation aborts a multipart upload. After a multipart upload is aborted, no
        additional parts can be uploaded using that upload ID. The storage consumed by any
        previously uploaded parts will be freed. However, if any part uploads are currently in
        progress, those part uploads might or might not succeed. As a result, it might be necessary
        to abort a given multipart upload multiple times in order to completely free all storage
        consumed by all parts. To verify that all parts have been removed, so you don't get charged
        for the part storage, you should call the List Parts operation and ensure the parts list is
        empty.

        Docs: https://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadAbort.html

        Quirks:

        If the ABORT request is successful, the session may be deleted when the LIST PARTS request
        is made.  The criteria for successful abort thus is ether LIST PARTS request returns 404 or
        returns 200 with an empty parts list.
        """

        headers = {}
        query_parameters = {
            'Bucket': self.bucket_name,
            'Key': path.full_path,
            'UploadId': session_upload_id,
        }

        iteration_count = 0
        is_aborted = False
        while iteration_count < settings.CHUNKED_UPLOAD_MAX_ABORT_RETRIES:
            try:
                # ABORT
                resp = await self.make_request(
                    'DELETE',
                    functools.partial(
                        self.connection.generate_presigned_url,
                        'abort_multipart_upload',
                        Params=query_parameters,
                        HttpMethod='DELETE',
                    ),
                    skip_auto_headers={'CONTENT-TYPE'},
                    headers=headers,
                    expects=(HTTPStatus.NO_CONTENT,),
                    throws=exceptions.UploadError,
                )
                await resp.release()

                # LIST PARTS
                resp_xml, session_deleted = await self._list_uploaded_chunks(path, session_upload_id)

                if session_deleted:
                    # Abort is successful if the session has been deleted
                    is_aborted = True
                    break

                uploaded_chunks_list = xmltodict.parse(resp_xml, strip_whitespace=False)
                parsed_parts_list = uploaded_chunks_list['ListPartsResult'].get('Part', [])
                if len(parsed_parts_list) == 0:
                    # Abort is successful when there is no part left
                    is_aborted = True
                    break
            except Exception as err:
                msg = 'An unexpected error has occurred during the aborting a multipart upload.'
                logger.error('{} upload_id={} error={!r}'.format(msg, session_upload_id, err))

            iteration_count += 1

        if is_aborted:
            logger.debug('Multi-part upload has been successfully aborted: retries={} '
                         'upload_id={}'.format(iteration_count, session_upload_id))
            return True

        logger.error('Multi-part upload has failed to abort: retries={} '
                     'upload_id={}'.format(iteration_count, session_upload_id))
        return False

    async def _list_uploaded_chunks(self, path, session_upload_id):
        """This operation lists the parts that have been uploaded for a specific multipart upload.

        Docs: https://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadListParts.html
        """

        headers = {}
        query_parameters = {
            'Bucket': self.bucket_name,
            'Key': path.full_path,
            'UploadId': session_upload_id,
        }

        resp = await self.make_request(
            'GET',
            functools.partial(
                self.connection.generate_presigned_url,
                'list_parts',
                Params=query_parameters,
                HttpMethod='GET',
            ),
            skip_auto_headers={'CONTENT-TYPE'},
            headers=headers,
            expects=(
                HTTPStatus.OK,
                HTTPStatus.CREATED,
                HTTPStatus.NOT_FOUND,
            ),
            throws=exceptions.UploadError,
        )
        session_deleted = resp.status == HTTPStatus.NOT_FOUND
        resp_xml = await resp.read()

        return resp_xml, session_deleted

    async def _complete_multipart_upload(self, path, session_upload_id, parts_metadata):
        """This operation completes a multipart upload by assembling previously uploaded parts.

        Docs: https://docs.aws.amazon.com/AmazonS3/latest/API/mpUploadComplete.html
        """

        payload = ''.join([
            '<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload>',
            ''.join(
                ['<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>'.format(
                    i + 1,
                    xml.sax.saxutils.escape(part['ETAG'])
                ) for i, part in enumerate(parts_metadata)]
            ),
            '</CompleteMultipartUpload>',
        ]).encode('utf-8')
        headers = {
            'Content-Length': str(len(payload)),
            'Content-MD5': compute_md5(BytesIO(payload))[1],
            'Content-Type': 'text/xml',
        }
        query_parameters = {
            'Bucket': self.bucket_name,
            'Key': path.full_path,
            'UploadId': session_upload_id
        }

        resp = await self.make_request(
            'POST',
            functools.partial(
                self.connection.generate_presigned_url,
                'complete_multipart_upload',
                Params=query_parameters,
                ExpiresIn=200,
                HttpMethod='POST',
                Headers=headers,
            ),
            data=payload,
            headers=headers,
            expects=(
                HTTPStatus.OK,
                HTTPStatus.CREATED,
            ),
            throws=exceptions.UploadError,
        )

        response_body = await resp.read()
        self._check_for_200_error(response_body, "CompleteMultipartUpload", exceptions.UploadError)

        await resp.release()

    async def delete(self, path, confirm_delete=0, **kwargs):
        """Delete the key and all its versions at the specified path

        :param path: ( :class:`.WaterButlerPath` ) The path of the key to delete
        :param int confirm_delete: Must be 1 to confirm root folder delete
        """
        if path.is_root:
            if not confirm_delete == 1:
                raise exceptions.DeleteError(
                    'confirm_delete=1 is required for deleting root provider folder',
                    code=HTTPStatus.BAD_REQUEST,
                )
        logger.debug('Deleting path: %s', path.full_path)
        if path.is_file:
            # Retrieve and delete all versions (batched) similar to S3 provider
            try:
                prefix = path.full_path.lstrip('/')
                query_params = {
                    'Prefix': prefix,
                    'Delimiter': '/',
                    'VersionIdMarker': '',
                }
                _, versions, delete_markers = await self.get_full_revision(query_params)
                full_version_list = versions + delete_markers
                if full_version_list:
                    version_dict = {
                        path.full_path: [
                            v.get('VersionId')
                            for v in full_version_list
                            if v.get('VersionId')
                        ]
                    }

                    version_ids = version_dict[path.full_path]
                    # AWS allows max 1000 objects per delete_objects call
                    for i in range(0, len(version_ids), 1000):
                        batch = version_ids[i: i + 1000]
                        delete_list = [
                            {'Key': path.full_path, 'VersionId': vid} for vid in batch
                        ]
                        response = await self._delete_objects(delete_list)
                        # Check for errors in response
                        if 'Errors' in response and response['Errors']:
                            error_count = len(response['Errors'])
                            error_codes = [e.get('Code', 'Unknown') for e in response['Errors']]
                            logger.error(
                                'Errors deleting objects: count=%d, codes=%s', error_count, error_codes
                            )
                            raise exceptions.DeleteError(
                                'Failed to delete some objects: {} error(s)'.format(error_count)
                            )
                        deleted_count = len(response.get('Deleted', []))
                        logger.debug('Batch deleted %d versions', deleted_count)
                else:
                    # No versions -> delete current object directly
                    query_parameters = {
                        'Bucket': self.bucket_name,
                        'Key': path.full_path,
                    }
                    resp = await self.make_request(
                        'DELETE',
                        functools.partial(
                            self.connection.generate_presigned_url,
                            'delete_object',
                            Params=query_parameters,
                            HttpMethod='DELETE',
                        ),
                        expects=(
                            HTTPStatus.OK,
                            HTTPStatus.NO_CONTENT,
                        ),
                        throws=exceptions.DeleteError,
                    )
                    await resp.release()
            except exceptions.MetadataError:
                # Versions cannot be retrieved (e.g. MinIO without versioning).
                # Fall back to deleting the current version directly.
                logger.debug('Version listing not available, falling back to direct delete')
                query_parameters = {'Bucket': self.bucket_name, 'Key': path.full_path}
                resp = await self.make_request(
                    'DELETE',
                    functools.partial(
                        self.connection.generate_presigned_url,
                        'delete_object',
                        Params=query_parameters,
                        HttpMethod='DELETE',
                    ),
                    expects=(
                        HTTPStatus.OK,
                        HTTPStatus.NO_CONTENT,
                    ),
                    throws=exceptions.DeleteError,
                )
                await resp.release()
        else:
            await self._delete_folder(path, **kwargs)

    async def _delete_objects(self, objects):
        """Delete up to 1000 objects (optionally specific versions) with one request.

        :param list objects: ``{'Key': ..., 'VersionId': ...}`` dicts, ``VersionId`` optional
        :rtype: dict with ``Deleted`` and ``Errors`` lists as returned by the storage
        """
        entries = []
        for obj in objects:
            entry = '<Key>{}</Key>'.format(xml.sax.saxutils.escape(obj['Key']))
            if obj.get('VersionId'):
                entry += '<VersionId>{}</VersionId>'.format(xml.sax.saxutils.escape(obj['VersionId']))
            entries.append('<Object>{}</Object>'.format(entry))
        payload = '<?xml version="1.0" encoding="UTF-8"?><Delete>{}</Delete>'.format(
            ''.join(entries)
        ).encode('utf-8')
        headers = {
            'Content-Length': str(len(payload)),
            'Content-MD5': compute_md5(BytesIO(payload))[1],
            'Content-Type': 'text/xml',
        }
        resp = await self.make_request(
            'POST',
            functools.partial(
                self.connection.generate_presigned_url,
                'delete_objects',
                Params={'Bucket': self.bucket_name},
                HttpMethod='POST',
                Headers=headers,
            ),
            data=payload,
            headers=headers,
            expects=(HTTPStatus.OK,),
            throws=exceptions.DeleteError,
        )
        contents = await resp.read()
        await resp.release()
        parsed = xmltodict.parse(contents.decode('utf-8'), strip_whitespace=False).get('DeleteResult') or {}
        result = {}
        for name in ('Deleted', 'Error'):
            items = parsed.get(name, [])
            result['Errors' if name == 'Error' else name] = [items] if isinstance(items, dict) else list(items)
        return result

    async def _delete_folder_prefix(self, prefix):
        """Delete the folder prefix object (e.g. 'foldername/') from S3."""
        query_parameters = {'Bucket': self.bucket_name, 'Key': prefix}
        resp = await self.make_request(
            'DELETE',
            functools.partial(
                self.connection.generate_presigned_url,
                'delete_object',
                Params=query_parameters,
                HttpMethod='DELETE',
            ),
            expects=(
                HTTPStatus.OK,
                HTTPStatus.NO_CONTENT,
            ),
            throws=exceptions.DeleteError,
        )
        await resp.release()

    async def _folder_prefix_exists(self, folder_prefix):
        # Even if the storage is MinIO, Contents with a leaf folder is
        # returned when a last slash of a prefix is removed.
        query_parameters = {
            'Bucket': self.bucket_name,
            'Prefix': folder_prefix.rstrip('/'),  # 'A/B/' -> 'A/B'
            'Delimiter': '/'
        }
        resp = await self.make_request(
            'GET',
            functools.partial(
                self.connection.generate_presigned_url,
                'list_objects',
                Params=query_parameters,
                HttpMethod='GET',
            ),
            expects=(HTTPStatus.OK,),
            throws=exceptions.MetadataError,
        )
        response_body = await resp.read()
        parsed = xmltodict.parse(response_body, strip_whitespace=False)['ListBucketResult']
        common_prefixes = parsed.get('CommonPrefixes', [])
        if parsed.get('EncodingType') == 'url':
            for item in (common_prefixes if isinstance(common_prefixes, list) else [common_prefixes]):
                if 'Prefix' in item:
                    item['Prefix'] = parse.unquote(item['Prefix'])
        # common_prefixes is dict when returned prefix is one.
        if not isinstance(common_prefixes, list):
            common_prefixes = [common_prefixes]
        for common_prefix in common_prefixes:
            val = common_prefix.get('Prefix')
            if val == folder_prefix:  # with last slash
                return True
        return False

    async def _delete_folder(self, path, **kwargs):
        """Query for recursive contents of folder and delete in batches of 1000

        Called from: func: delete if not path.is_file

        Calls: func: self.make_request
               func: self.connection.generate_presigned_url

        :param *ProviderPath path: Path to be deleted

        On S3, folders are not first-class objects, but are instead inferred
        from the names of their children.  A regular DELETE request issued
        against a folder will not work unless that folder is completely empty.
        To fully delete an occupied folder, we must delete all of the comprising
        objects.  Amazon provides a bulk delete operation to simplify this.
        """
        if not path.full_path.endswith('/'):
            raise exceptions.InvalidParameters('not a folder: {}'.format(str(path)))

        prefix = path.full_path.lstrip('/')
        list_query_params = {'Prefix': prefix}
        try:
            parsed, versions, delete_markers = await self.get_full_revision(dict(list_query_params))
        except exceptions.MetadataError:
            # Versioning not supported. Fall back to a plain object listing.
            all_objects = []
            marker = None
            while True:
                query_params = {
                    'Bucket': self.bucket_name,
                    'Prefix': prefix,
                    'MaxKeys': 1000,
                }
                if marker:
                    query_params['Marker'] = marker
                resp = await self.make_request(
                    'GET',
                    functools.partial(
                        self.connection.generate_presigned_url,
                        'list_objects',
                        Params=query_params,
                        HttpMethod='GET',
                    ),
                    expects=(HTTPStatus.OK,),
                    throws=exceptions.MetadataError,
                )
                contents = await resp.read()
                parsed = xmltodict.parse(
                    contents.decode('utf-8'),
                    strip_whitespace=False,
                )['ListBucketResult']
                objects = parsed.get('Contents', [])
                if isinstance(objects, dict):
                    objects = [objects]
                if parsed.get('EncodingType') == 'url':
                    for obj in objects:
                        if 'Key' in obj:
                            obj['Key'] = parse.unquote(obj['Key'])
                all_objects.extend({'Key': obj['Key']} for obj in objects if obj.get('Key'))

                if parsed.get('IsTruncated') == 'true':
                    marker = parsed.get('NextMarker') or (all_objects[-1]['Key'] if all_objects else None)
                else:
                    break

            if all_objects:
                for i in range(0, len(all_objects), 1000):
                    batch = all_objects[i:i + 1000]
                    response = await self._delete_objects(batch)
                    if response.get('Errors'):
                        error_count = len(response['Errors'])
                        error_codes = [e.get('Code', 'Unknown') for e in response['Errors']]
                        logger.error('_delete_folder fallback: %d delete error(s), codes=%s', error_count, error_codes)
                        raise exceptions.DeleteError(
                            'Failed to delete some objects: {} error(s)'.format(error_count)
                        )
            # Also clean up folder prefix
            try:
                await self._delete_folder_prefix(prefix)
            except exceptions.DeleteError:
                logger.warning('Failed to clean up folder prefix in _delete_folder fallback: %s', prefix)
            return

        if not versions and not delete_markers:
            # No objects/versions -> treat as missing (parity with S3 provider)
            raise exceptions.NotFoundError(str(path))

        version_map = {}
        keys_without_version = []
        for item in versions + delete_markers:
            key = item.get('Key')
            if not key:
                continue
            version_id = item.get('VersionId')
            if version_id:
                version_map.setdefault(key, []).append(version_id)
            else:
                keys_without_version.append({'Key': key})

        all_objects = [
            {'Key': k, 'VersionId': v} for k, vids in version_map.items() for v in vids
        ] + keys_without_version
        # AWS allows max 1000 objects per delete_objects call
        for i in range(0, len(all_objects), 1000):
            batch = all_objects[i: i + 1000]
            response = await self._delete_objects(batch)
            # Check for errors in response
            if 'Errors' in response and response['Errors']:
                error_count = len(response['Errors'])
                error_codes = [e.get('Code', 'Unknown') for e in response['Errors']]
                logger.error(
                    'Errors deleting folder objects: count=%d, codes=%s', error_count, error_codes
                )
                raise exceptions.DeleteError(
                    'Failed to delete some objects: {} error(s)'.format(error_count)
                )
            deleted_count = len(response.get('Deleted', []))
            logger.debug('Batch deleted %d objects from folder', deleted_count)

        # Clean up folder prefix object if it still exists
        if await self._folder_prefix_exists(prefix):
            await self._delete_folder_prefix(prefix)

    async def get_full_revision(self, query_params):
        """
        Get all versions and delete markers of the requested object
        :param query_params: The query parameters to be used in the request
        :return: The dict of response content, list versions and delete_markers
        """
        versions = []
        delete_markers = []
        more_to_come = True

        while more_to_come:
            query_parameters_dict = {'Bucket': self.bucket_name}
            query_parameters_dict.update(query_params)
            resp = await self.make_request(
                'GET',
                functools.partial(
                    self.connection.generate_presigned_url,
                    'list_object_versions',
                    Params=query_parameters_dict,
                    HttpMethod='GET',
                ),
                expects=(HTTPStatus.OK,),
                throws=exceptions.MetadataError,
            )

            response_body = await resp.read()
            parsed = xmltodict.parse(response_body.decode('utf-8'), strip_whitespace=False)['ListVersionsResult']

            # Append current page's versions and delete markers
            current_versions = parsed.get('Version', [])
            current_delete_markers = parsed.get('DeleteMarker', [])

            if isinstance(current_versions, dict):
                current_versions = [current_versions]
            if isinstance(current_delete_markers, dict):
                current_delete_markers = [current_delete_markers]

            # boto3 automatically adds encoding-type=url to presigned URLs
            # for list_object_versions, causing MinIO to return URL-encoded
            # keys (e.g. Japanese characters). Decode them so that
            # delete_objects receives the actual key names.
            if parsed.get('EncodingType') == 'url':
                for item in current_versions:
                    if 'Key' in item:
                        item['Key'] = parse.unquote(item['Key'])
                for item in current_delete_markers:
                    if 'Key' in item:
                        item['Key'] = parse.unquote(item['Key'])

            versions.extend(current_versions)
            delete_markers.extend(current_delete_markers)

            # Check if more pages are available
            more_to_come = parsed.get('IsTruncated') == 'true'
            if more_to_come:
                query_params['KeyMarker'] = parsed.get('NextKeyMarker')
                if parsed.get('EncodingType') == 'url' and query_params['KeyMarker']:
                    query_params['KeyMarker'] = parse.unquote(query_params['KeyMarker'])
                query_params['VersionIdMarker'] = parsed.get('NextVersionIdMarker')

        return parsed, versions, delete_markers

    async def revisions(self, path, **kwargs):
        """Get past versions of the requested key

        :param path: ( :class:`.WaterButlerPath` ) The path to a key
        :rtype list:
        """
        prefix = path.full_path.lstrip('/')  # '/' -> '', '/A/B' -> 'A/B'
        query_parameters = {
            'Bucket': self.bucket_name,
            'Prefix': prefix,
            'Delimiter': '/'
        }
        list_url = self.connection.generate_presigned_url('list_object_versions', Params=query_parameters, ExpiresIn=settings.TEMP_URL_SECS, HttpMethod='GET')
        try:
            resp = await self.make_request(
                'GET',
                list_url,
                expects=(HTTPStatus.OK,),
                throws=exceptions.MetadataError,
            )
        except exceptions.MetadataError as e:
            # MinIO may not support "versions" from boto3 presigned url.
            # (And, MinIO does not support ListObjectVersions yet.)
            logger.info('ListObjectVersions may not be supported: %s', str(e))
            return []

        response_body = await resp.read()
        xml = xmltodict.parse(response_body.decode('utf-8'))
        versions = xml['ListVersionsResult'].get('Version') or []

        if isinstance(versions, dict):
            versions = [versions]

        return [
            S3CompatRevision(item)
            for item in versions
            if item['Key'] == prefix
        ]

    async def metadata(self, path, revision=None, **kwargs):
        """Get Metadata about the requested file or folder

        :param WaterButlerPath path: The path to a key or folder
        :rtype: dict or list
        """
        if path.is_dir:
            if 'next_token' in kwargs:
                return await self._metadata_folder(path, kwargs['next_token'])
            return (await self._metadata_folder(path))

        return (await self._metadata_file(path, revision=revision))

    def handle_data(self, data):
        token = None
        if not isinstance(data, S3CompatFileMetadataHeaders):
            token = data.pop()

        return data, token or ''

    async def create_folder(self, path, folder_precheck=True, **kwargs):
        """
        :param path: ( :class:`.WaterButlerPath` ) The path to create a folder at
        """
        WaterButlerPath.validate_folder(path)

        if folder_precheck:
            if (await self.exists(path)):
                raise exceptions.FolderNamingConflict(path.name)

        query_parameters = {'Bucket': self.bucket_name, 'Key': path.full_path}

        async with self.request(
            'PUT',
            functools.partial(
                self.connection.generate_presigned_url,
                'put_object',
                Params=query_parameters,
                HttpMethod='PUT',
            ),
            skip_auto_headers={'CONTENT-TYPE'},
            expects=(
                HTTPStatus.OK,
                HTTPStatus.CREATED,
            ),
            throws=exceptions.CreateFolderError,
        ):
            return S3CompatFolderMetadata(self, {'Prefix': path.full_path})

    async def _metadata_file(self, path, revision=None):
        if revision == 'Latest':
            revision = None
        query_parameters = {'Bucket': self.bucket_name, 'Key': path.full_path}
        if revision:
            query_parameters['VersionId'] = revision

        resp = await self.make_request(
            'HEAD',
            functools.partial(
                self.connection.generate_presigned_url,
                'head_object',
                Params=query_parameters,
                HttpMethod='HEAD',
            ),
            expects=(HTTPStatus.OK,),
            throws=exceptions.MetadataError,
        )
        await resp.release()
        return S3CompatFileMetadataHeaders(self, path.full_path, resp.headers)

    async def _metadata_folder(self, path, next_token=None):
        prefix = path.full_path.lstrip('/')  # '/' -> '', '/A/B' -> 'A/B'
        query_parameters = {
            'Bucket': self.bucket_name,
            'Prefix': prefix,
            'Delimiter': '/',
            'MaxKeys': 1000,
        }
        if next_token:
            query_parameters['Marker'] = next_token

        resp = await self.make_request(
            'GET',
            functools.partial(
                self.connection.generate_presigned_url,
                'list_objects',
                Params=query_parameters,
                HttpMethod='GET',
            ),
            expects=(HTTPStatus.OK,),
            throws=exceptions.MetadataError,
        )

        contents = await resp.read()
        parsed = xmltodict.parse(contents.decode('utf-8'), strip_whitespace=False)['ListBucketResult']

        next_token_string = parsed.get('NextMarker', '')
        contents = parsed.get('Contents', [])
        prefixes = parsed.get('CommonPrefixes', [])

        if isinstance(contents, dict):
            contents = [contents]
        if isinstance(prefixes, dict):
            prefixes = [prefixes]

        # boto3 adds encoding-type=url to the presigned URL, so the storage may return
        # URL-encoded keys. Decode them after XML parsing.
        if parsed.get('EncodingType') == 'url':
            for item in contents:
                if 'Key' in item:
                    item['Key'] = parse.unquote(item['Key'])
            for item in prefixes:
                if 'Prefix' in item:
                    item['Prefix'] = parse.unquote(item['Prefix'])
            if next_token_string:
                next_token_string = parse.unquote(next_token_string)

        if not contents and not prefixes and not path.is_root:
            # If contents and prefixes are empty then this "folder"
            # must exist as a key with a / at the end of the name
            # if the path is root there is no need to test if it exists
            query_parameters = {'Bucket': self.bucket_name, 'Key': prefix}
            resp = await self.make_request(
                'HEAD',
                functools.partial(
                    self.connection.generate_presigned_url,
                    'head_object',
                    Params=query_parameters,
                    HttpMethod='HEAD',
                ),
                expects=(HTTPStatus.OK,),
                throws=exceptions.MetadataError,
            )
            await resp.release()

        items = [
            S3CompatFolderMetadata(self, item)
            for item in prefixes
        ]

        for content in contents:
            if content['Key'] == path.full_path:  # self
                continue

            if content['Key'].endswith('/'):
                items.append(S3CompatFolderKeyMetadata(self, content))
            else:
                items.append(S3CompatFileMetadata(self, content))

        if next_token_string:
            items.append(next_token_string)
        return items
