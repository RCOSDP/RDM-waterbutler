import json
from waterbutler.core import signing
from waterbutler.providers.dropbox import DropboxProvider
from waterbutler.providers.osfstorage import settings
from waterbutler import settings as wb_settings
QUERY_METHODS = ('GET', 'DELETE')


class DropboxBusinessProvider(DropboxProvider):

    NAME = 'dropboxbusiness'

    def __init__(self, auth, credentials, settings, **kwargs):
        super().__init__(auth, credentials, settings, **kwargs)
        self.admin_dbmid = self.settings['admin_dbmid']
        self.team_folder_id = self.settings['team_folder_id']

    @property
    def default_headers(self) -> dict:
        return dict(super().default_headers, **{
            'Dropbox-API-Select-Admin': self.admin_dbmid,
            'Dropbox-API-Path-Root': json.dumps({
                '.tag': 'namespace_id',
                'namespace_id': self.team_folder_id,
            })
        })

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
