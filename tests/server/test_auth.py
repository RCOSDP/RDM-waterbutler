from unittest import mock

import tornado

from tests import utils
from tests.server.api.v1.utils import ServerTestCase
from waterbutler.auth.osf import settings as osf_settings
from waterbutler.auth.osf.handler import EXPORT_DATA_FAKE_NODE_ID
from waterbutler.core.auth import AuthType
from waterbutler.server import settings
from waterbutler.server.auth import AuthHandler


class TestAuthHandler(ServerTestCase):

    def setUp(self):
        super().setUp()

        self.handler = AuthHandler(settings.AUTH_HANDLERS)
        self.handler.manager = mock.Mock()
        self.request = tornado.httputil.HTTPServerRequest(uri=osf_settings.API_URL)

        self.mock_credential = utils.MockCoroutine()
        self.handler.manager.extensions = [self.mock_credential]

    def tearDown(self):
        super().tearDown()

    @tornado.testing.gen_test
    async def test_auth_get_credential(self):
        resource = EXPORT_DATA_FAKE_NODE_ID
        provider = 'test'
        action = 'copy'
        auth_type = AuthType.SOURCE
        self.request.method = 'post'

        self.mock_credential.obj.get.return_value = {'storage': {}, 'callback_url': 'test.com'}
        credential = await self.handler.get(resource, provider, self.request, action=action, auth_type=auth_type, location_id=1)
        self.mock_credential.obj.get.assert_called_with(resource, provider, self.request, action=action, auth_type=auth_type,
                                                        path='', version=None, callback_log=True, location_id=1,
                                                        upload_datetime=None, task_id=None)
        assert credential == {'storage': {}, 'callback_url': 'test.com'}
