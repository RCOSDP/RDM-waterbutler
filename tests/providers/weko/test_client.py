import pytest

import aiohttpretty

from waterbutler.core import exceptions
from waterbutler.providers.weko import WEKOProvider
from waterbutler.providers.weko.client import Client


fake_weko_host = 'https://test.sample.nii.ac.jp/sword/'
fake_weko_indices = [
    {
        'id': 100,
        'name': 'Sample Index',
        'children': [
            {
                'id': 'more',
            },
            {
                'id': 'dummy',
            }
        ],
    },
    {
        'id': 'more',
    },
]
fake_weko_item = {
    'id': 1000,
    'metadata': {
        'title': 'Sample Item',
    },
}
fake_weko_items = {
    'hits': {
        'hits': [
            fake_weko_item,
            {
                'id': 'dummy',
            },
            {
                'id': 'empty-metadata-1',
                'metadata': {},
            },
            {
                'id': 'empty-metadata-2',
                'metadata': {
                    '_item_metadata': {},
                },
            },
            {
                'id': 'invalid-metadata-1',
                'metadata': {
                    '_item_metadata': {
                        'title': [],
                    },
                },
            },
            {
                'id': 'invalid-metadata-2',
                'metadata': {
                    '_item_metadata': {},
                    'title': [],
                },
            },
            {
                'id': 'title-on-root-str',
                'metadata': {
                    '_item_metadata': {},
                    'title': 'Sample Item-Text',
                },
            },
            {
                'id': 'title-on-root-list',
                'metadata': {
                    '_item_metadata': {},
                    'title': ['Sample Item-List'],
                },
            },
            {
                'id': 'title-on-_item-metadata-str',
                'metadata': {
                    '_item_metadata': {
                        'title': 'Sample Item-Text',
                    },
                },
            },
            {
                'id': 'title-on-_item-metadata-list',
                'metadata': {
                    '_item_metadata': {
                        'title': ['Sample Item-List'],
                    },
                },
            },
        ]
    },
}

@pytest.fixture
def auth():
    return {
        'name': 'cat',
        'email': 'cat@cat.com'
    }


@pytest.fixture(scope='module', params=['token'])
def credentials(request):
    return {
        request.param: 'open inside',
        'user_id': 'requester'
    }


@pytest.fixture
def settings():
    return {
        'url': 'http://localhost/test',
        'index_id': 'that kerning',
        'index_title': 'sample archive',
        'nid': 'project_id'
    }


@pytest.fixture
def provider(auth, credentials, settings):
    provider = WEKOProvider(auth, credentials, settings)
    return provider

@pytest.fixture
def client(provider):
    return Client(provider, fake_weko_host)


class TestWEKOClient:
    @pytest.mark.asyncio
    @pytest.mark.aiohttpretty
    async def test_weko_get_indices(self, client):
        aiohttpretty.register_json_uri(
            'GET',
            'https://test.sample.nii.ac.jp/api/tree?action=browsing',
            body=fake_weko_indices,
        )
        indices = await client.get_indices()
        assert len(indices) == 1
        assert indices[0].title == 'Sample Index'
        assert indices[0].identifier == 100

    @pytest.mark.asyncio
    @pytest.mark.aiohttpretty
    async def test_weko_get_indices_404(self, client):
        aiohttpretty.register_uri(
            'GET',
            'https://test.sample.nii.ac.jp/api/tree?action=browsing',
            status=404,
        )
        with pytest.raises(exceptions.MetadataError):
            indices = await client.get_indices()

    @pytest.mark.asyncio
    @pytest.mark.aiohttpretty
    async def test_weko_get_index_by_id(self, client):
        aiohttpretty.register_json_uri(
            'GET',
            'https://test.sample.nii.ac.jp/api/tree?action=browsing',
            body=fake_weko_indices,
        )
        index = await client.get_index_by_id(100)
        assert index.title == 'Sample Index'
        assert index.identifier == 100

        with pytest.raises(ValueError):
            await client.get_index_by_id(101)

    @pytest.mark.asyncio
    @pytest.mark.aiohttpretty
    async def test_weko_get_items(self, client):
        aiohttpretty.register_json_uri(
            'GET',
            'https://test.sample.nii.ac.jp/api/tree?action=browsing',
            body=fake_weko_indices,
        )
        aiohttpretty.register_json_uri(
            'GET',
            'https://test.sample.nii.ac.jp/api/index/?page=1&size=1000&sort=-createdate&q=100',
            body=fake_weko_items,
        )

        index = await client.get_index_by_id(100)
        items = await index.get_items()

        assert len(items) == 5
        assert items[0].title == 'Sample Item'
        assert items[0].primary_title == 'Sample Item'
        assert items[0].identifier == 1000
        assert items[1].title == 'Sample Item-Text'
        assert items[1].primary_title == 'Sample Item-Text'
        assert items[1].identifier == 'title-on-root-str'
        assert items[2].title == 'Sample Item-List'
        assert items[2].primary_title == 'Sample Item-List'
        assert items[2].identifier == 'title-on-root-list'
        assert items[3].title == 'Sample Item-Text'
        assert items[3].primary_title == 'Sample Item-Text'
        assert items[3].identifier == 'title-on-_item-metadata-str'
        assert items[4].title == 'Sample Item-List'
        assert items[4].primary_title == 'Sample Item-List'
        assert items[4].identifier == 'title-on-_item-metadata-list'

    @pytest.mark.asyncio
    @pytest.mark.aiohttpretty
    async def test_weko_get_item_by_id(self, client):
        aiohttpretty.register_json_uri(
            'GET',
            'https://test.sample.nii.ac.jp/api/tree?action=browsing',
            body=fake_weko_indices,
        )
        aiohttpretty.register_json_uri(
            'GET',
            'https://test.sample.nii.ac.jp/api/records/1000',
            body=fake_weko_item,
        )

        index = await client.get_index_by_id(100)
        item = await index.get_item_by_id(1000)

        assert item.title == 'Sample Item'
        assert item.identifier == 1000
