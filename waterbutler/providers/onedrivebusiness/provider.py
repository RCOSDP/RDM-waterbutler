import logging

from waterbutler.core import provider
from waterbutler.providers.onedrive import OneDriveProvider
from waterbutler.providers.onedrive import settings
from waterbutler.providers.osfstorage import settings
from waterbutler import settings as wb_settings
import json
from waterbutler.core import signing
QUERY_METHODS = ('GET', 'DELETE')

logger = logging.getLogger(__name__)


class OneDriveBusinessProvider(OneDriveProvider):

    NAME = 'onedrivebusiness'

    def __init__(self, auth, credentials, settings, **kwargs):
        super().__init__(auth, credentials, settings, **kwargs)
        logger.info('settings: {}'.format(settings))
        self.drive_id = settings['drive_id']
        self.nid = settings['nid']

    def _build_drive_url(self, *segments, **query) -> str:
        base_url = settings.BASE_URL
        if self.drive_id is None:
            return provider.build_url(base_url, 'drive', *segments, **query)
        else:
            return provider.build_url(base_url, 'drives', self.drive_id, *segments, **query)

    def _build_item_url(self, *segments, **query) -> str:
        base_url = settings.BASE_URL
        if self.drive_id is None:
            return provider.build_url(base_url, 'drive', 'items', *segments, **query)
        else:
            return provider.build_url(base_url, 'drives', self.drive_id, 'items', *segments, **query)

    def build_signed_url(self, method, url, data=None, params=None, ttl=100, **kwargs):
        signer = signing.Signer(settings.HMAC_SECRET, settings.HMAC_ALGORITHM)
        if method.upper() in QUERY_METHODS:
            signed = signing.sign_data(signer, params or {}, ttl=ttl)
            params = signed
        else:
            signed = signing.sign_data(signer, json.loads(data or {}), ttl=ttl)
            data = json.dumps(signed)

        # Ensure url ends with a /
        if not url.endswith('/'):
            if '?' not in url:
                url += '/'
            elif url[url.rfind('?') - 1] != '/':
                url = url.replace('?', '/?')

        return url, data, params

    async def make_signed_request(self, method, url, data=None, params=None, ttl=100, **kwargs):
        url, data, params = self.build_signed_url(
            method,
            url,
            data=data,
            params=params,
            ttl=ttl,
            **kwargs
        )
        return await self.make_request(method, url, data=data, params=params, **kwargs)

    async def get_quota(self):
        resp = await self.make_signed_request(
            'POST',
            '{}/api/v1/project/{}/institution_storage_user_quota/'.format(wb_settings.OSF_URL, self.nid),
            data=json.dumps({
                'provider': self.NAME,
                'path': self.path
            }),
            headers={'Content-Type': 'application/json'},
            expects=(200, )
        )
        body = await resp.json()
        await resp.release()
        return body
