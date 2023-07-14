import time

import mock
import pytest

from waterbutler.core import remote_logging


class TestLogToCallback:

    @pytest.mark.asyncio
    @mock.patch('waterbutler.core.remote_logging.utils.send_signed_request')
    async def test_log_to_callback(self, mock_send_signed_request):
        action = 'download_file'
        callback_url = 'http://192.168.168.167:5000/api/v1/project/test/waterbutler/logs/'
        mock_destination = mock.Mock()
        mock_destination.auth = {'callback_url': callback_url}
        mock_destination.serialize = mock.Mock(return_value={})
        start_time = time.time()
        mock_source = mock.Mock({})
        mock_source.auth = {'callback_url': callback_url}
        mock_source.serialize = mock.Mock(return_value={'provider': 'test_provider'})
        request = {
            'request': {
                'method': 'GET',
                'url': 'test',
                'headers': [],
            },
            'referrer': {
                'url': '/test'
            },
            'tech': {
                'ua': 'console'
            }
        }

        mock_send_signed_request.return_value = (200, b'a')
        await remote_logging.log_to_callback(action, source=mock_source, destination=mock_destination, start_time=start_time, errors=[],
                                             request=request)
        mock_send_signed_request.assert_called()

    @pytest.mark.asyncio
    @mock.patch('waterbutler.core.remote_logging.utils.send_signed_request')
    async def test_log_to_callback_failed(self, mock_send_signed_request):
        action = 'move'
        callback_url = 'http://192.168.168.167:5000/api/v1/project/test/waterbutler/logs/'
        mock_destination = mock.Mock()
        mock_destination.auth = {'callback_url': callback_url}
        mock_destination.serialize = mock.Mock(return_value={})
        start_time = time.time()
        mock_source = mock.Mock({})
        mock_source.auth = {'callback_url': callback_url}
        mock_source.serialize = mock.Mock(return_value={'provider': 'test_provider'})
        request = {
            'request': {
                'method': 'GET',
                'url': 'test',
                'headers': [],
            },
            'referrer': {
                'url': '/test'
            },
            'tech': {
                'ua': 'console'
            }
        }

        mock_send_signed_request.return_value = (400, b'a')
        with pytest.raises(Exception):
            await remote_logging.log_to_callback(action, source=mock_source, destination=mock_destination, start_time=start_time, errors=[],
                                                 request=request)
        mock_send_signed_request.assert_called()

    @pytest.mark.asyncio
    @mock.patch('waterbutler.core.remote_logging.utils.send_signed_request')
    async def test_log_to_callback_without_cb_url(self, mock_send_signed_request):
        action = 'move'
        callback_url = ''
        mock_destination = mock.Mock()
        mock_destination.auth = {'callback_url': callback_url}
        mock_destination.serialize = mock.Mock(return_value={})
        start_time = time.time()
        mock_source = mock.Mock({})
        mock_source.auth = {'callback_url': callback_url}
        mock_source.serialize = mock.Mock(return_value={'provider': 'test_provider'})
        request = {
            'request': {
                'method': 'GET',
                'url': 'test',
                'headers': [],
            },
            'referrer': {
                'url': '/test'
            },
            'tech': {
                'ua': 'console'
            }
        }

        mock_send_signed_request.return_value = (200, b'a')
        await remote_logging.log_to_callback(action, source=mock_source, destination=mock_destination, start_time=start_time, errors=[],
                                             request=request)
        mock_send_signed_request.assert_not_called()


class TestScrubPayloadForKeen:

    def test_flat_dict(self):
        payload = {
            'key': 'value',
            'key2': 'value2'
        }

        result = remote_logging._scrub_headers_for_keen(payload)

        assert result == {
            'key': 'value',
            'key2': 'value2'
        }

    def test_flat_dict_needs_scrubbing(self):
        payload = {
            'key.test': 'value',
            'key2': 'value2'
        }

        result = remote_logging._scrub_headers_for_keen(payload)

        assert result == {
            'key-test': 'value',
            'key2': 'value2'
        }

    def test_scrub_and_rename(self):
        payload = {
            'key.test': 'unique value',
            'key-test': 'value2'
        }

        result = remote_logging._scrub_headers_for_keen(payload)

        # "key.test" sorts after "key-test" and will therefore be renamed
        assert result == {
            'key-test': 'value2',
            'key-test-1': 'unique value'
        }

    def test_scrub_and_loop_rename(self):
        payload = {
            'key.test': 'value1',
            'key-test': 'value2',
            'key-test-1': 'value3'
        }

        result = remote_logging._scrub_headers_for_keen(payload)

        assert result == {
            'key-test': 'value2',
            'key-test-2': 'value1',
            'key-test-1': 'value3'

        }

    def test_max_iteration(self):
        payload = {
            'key.test': 'value1',
            'key-test': 'value2',
            'key-test-1': 'value3'
        }

        result = remote_logging._scrub_headers_for_keen(payload, MAX_ITERATIONS=1)

        assert result == {
            'key-test': 'value2',
            'key-test-1': 'value3'
        }
