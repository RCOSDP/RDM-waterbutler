from waterbutler import settings
# Clear all celery settings
settings.config['TASKS_CONFIG'] = {
    'WAIT_TIME_OUT': 30,
    'CELERY_ALWAYS_EAGER': True,
    'CELERY_RESULT_BACKEND': 'redis://'
}

import inspect
from unittest import mock

import aiohttp
import aiohttpretty
from aiohttp.base_protocol import BaseProtocol


# aiohttp 3.14 added a required ``stream_writer`` argument to ``ClientResponse``, which the
# mocked responses built by aiohttpretty 25.0.0 do not pass. Supply it until aiohttpretty does.
if 'stream_writer' in inspect.signature(aiohttp.ClientResponse.__init__).parameters:
    # ``import aiohttpretty`` yields the module's singleton instance, so reach the module
    # namespace through one of its methods.
    _aiohttpretty_globals = type(aiohttpretty).fake_request.__globals__
    _ClientResponse = _aiohttpretty_globals['ClientResponse']

    class _ClientResponseWithStreamWriter(_ClientResponse):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault('stream_writer', mock.Mock())
            super().__init__(*args, **kwargs)

    _aiohttpretty_globals['ClientResponse'] = _ClientResponseWithStreamWriter


# aiohttp 3.14 attaches the HTTP parser to ``BaseProtocol`` and asserts it is there when a
# stream's buffer passes its high-water mark (64 KiB) and reading has to pause. The protocol
# aiohttpretty 25.0.0 builds for a mocked body has no parser, so a mocked response body over
# 64 KiB fails to be fed. Nothing is read from a socket here, so pausing is a no-op.
if 'parser' in inspect.signature(BaseProtocol.__init__).parameters:
    _aiohttpretty_globals = type(aiohttpretty).fake_request.__globals__

    class _MockStreamProtocol(BaseProtocol):
        def pause_reading(self):
            self._reading_paused = True

        def resume_reading(self, resume_parser=True):
            self._reading_paused = False

    _aiohttpretty_globals['BaseProtocol'] = _MockStreamProtocol


def pytest_configure(config):
    config.addinivalue_line(
        'markers',
        'aiohttpretty: mark tests to activate aiohttpretty'
    )


def pytest_runtest_setup(item):
    if 'aiohttpretty' in item.keywords:
        aiohttpretty.clear()
        aiohttpretty.activate()


def pytest_runtest_teardown(item, nextitem):
    if 'aiohttpretty' in item.keywords:
        aiohttpretty.deactivate()
