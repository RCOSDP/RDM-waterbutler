from waterbutler.providers.s3compat import S3CompatProvider
from waterbutler.providers.osfstorage import settings
from waterbutler import settings as wb_settings
import json
from waterbutler.core import signing
QUERY_METHODS = ('GET', 'DELETE')


class S3CompatInstitutionsProvider(S3CompatProvider):
    NAME = 's3compatinstitutions'

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
