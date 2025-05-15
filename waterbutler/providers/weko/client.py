import logging
from typing import Union, List
from typing_extensions import Self
from waterbutler.core import exceptions


logger = logging.getLogger(__name__)


def _flatten_indices(indices):
    r = []
    for i in indices:
        r.append(i)
        r += _flatten_indices(i.children)
    return r


def _is_valid_index(desc):
    if 'name' in desc and 'id' in desc:
        return True
    if 'id' in desc and desc['id'] == 'more':
        return False
    logger.warning('Unexpected index description: %s', desc)
    return False


def _is_valid_item(desc):
    if 'metadata' not in desc:
        logger.warning('Unexpected item description: %s', desc)
        return False
    item = Item(desc)
    if item.title == '':
        logger.warning('Item without title: %s', desc)
        return False
    return True


class Client(object):
    """
    WEKO3 Client
    """
    provider = None
    host = None
    token = None
    username = None
    password = None

    def __init__(self, provider, host, token=None, username=None, password=None):
        self.provider = provider
        self.host = host
        self.token = token
        self.username = username
        self.password = password
        if not self.host.endswith('/'):
            self.host += '/'

    async def get_indices(self):
        """
        Get all indices from the WEKO3.
        """
        root = await self._get('api/tree?action=browsing')
        indices = []
        for desc in root:
            if not _is_valid_index(desc):
                continue
            indices.append(Index(self, desc))
        return indices

    async def get_index_by_id(self, index_id):
        indices_ = await self.get_indices()
        indices = [i for i in _flatten_indices(indices_) if str(i.identifier) == str(index_id)]
        if len(indices) == 0:
            raise ValueError(f'No index for id = {index_id}')
        return indices[0]

    def get_item_records_url(self, item_id):
        return self._base_host + 'records/' + item_id

    def get_index_items_url(self, index_id):
        return self._base_host + 'search?q=' + index_id

    async def deposit(self, files, headers=None):
        return await self._post('sword/service-document', files=files, headers=headers)

    def request_headers(self, headers=None):
        return self._requests_args(headers=headers).get('headers', {})

    @property
    def _base_host(self):
        if not self.host.endswith('/sword/'):
            return self.host
        return self.host[:-6]

    async def _get(self, path):
        resp = await self.provider.make_request(
            'GET',
            self._base_host + path,
            expects=(200, ),
            throws=exceptions.MetadataError,
            **self._requests_args(),
        )
        return await resp.json()

    async def _post(self, path, files, headers=None):
        resp = await self.provider.make_request(
            'POST',
            self._base_host + path,
            files=files,
            expects=(200, 201, 202, ),
            throws=exceptions.MetadataError,
            **self._requests_args(),
        )
        return await resp.json()

    def _requests_args(self, headers=None):
        if self.token is not None:
            headers = headers.copy() if headers is not None else {}
            token = self.token.decode('utf8') if isinstance(self.token, bytes) else self.token
            headers['Authorization'] = 'Bearer ' + token
            return {'headers': headers}
        elif headers is not None:
            return {'auth': (self.username, self.password), 'headers': headers}
        else:
            return {'auth': (self.username, self.password)}


class Index(object):
    """
    WEKO3 Index
    """
    client = None
    raw = None
    parent: Self = None

    def __init__(self, client, desc, parent: Self=None):
        self.client = client
        self.parent = parent
        self.raw = desc

    @property
    def title(self):
        return self.raw['name']

    @property
    def identifier(self) -> str:
        return self.raw['id']

    @property
    def children(self):
        if 'children' not in self.raw:
            return []
        return [
            Index(self.client, i, parent=self)
            for i in self.raw['children']
            if _is_valid_index(i)
        ]

    async def get_items(self, page: int = 1, size: int = 1000):
        queries = f'page={page}&size={size}&sort=-createdate'
        root = await self.client._get(f'api/index/?{queries}&q={self.identifier}')
        logger.debug(f'get_items: {root}')
        items = []
        for entry in root['hits']['hits']:
            if not _is_valid_item(entry):
                continue
            logger.debug(f'get_item: {entry}')
            items.append(Item(entry))
        return items

    async def get_item_by_id(self, item_id):
        root = await self.client._get(f'api/records/{item_id}')
        logger.debug(f'get_item: {root}')
        return Item(root)


class Item(object):
    """
    WEKO3 Item
    """
    raw = None
    index = None

    def __init__(self, desc, index=None):
        self.raw = desc
        self.index = index

    @property
    def identifier(self) -> Union[str, int]:
        return self.raw['id']

    @property
    def primary_title(self) -> str:
        v = self._get_metadata_value('title', '')
        if isinstance(v, str):
            return v
        if isinstance(v, list) and len(v) == 1:
            return v[0]
        return ''

    @property
    def title(self) -> str:
        return self.primary_title

    @property
    def updated(self):
        return self._get_metadata_value('updated')

    @property
    def _metadata(self):
        metadata = self.raw['metadata']
        if '_item_metadata' in metadata:
            return metadata['_item_metadata']
        return metadata

    def _get_metadata_value(self, key: str, default=None) -> Union[str, List[str], None]:
        metadata = self.raw['metadata']
        if '_item_metadata' in metadata and key in metadata['_item_metadata']:
            return metadata['_item_metadata'][key]
        if key in metadata:
            return metadata[key]
        return default

    @property
    def files(self):
        file_items = [k
                      for k, v in self._metadata.items()
                      if k.startswith('item_') and 'attribute_type' in v and v['attribute_type'] == 'file']
        return [File(file_item) for file_item in self._metadata[file_items[0]]['attribute_value_mlt']]


class File(object):
    """
    WEKO3 File
    """
    raw = None
    item = None

    def __init__(self, desc, item=None):
        self.raw = desc
        self.item = item

    @property
    def filename(self):
        return self.raw['filename']

    @property
    def format(self):
        if 'format' not in self.raw:
            return None
        return self.raw['format']

    @property
    def version_id(self):
        return self.raw['version_id']

    @property
    def download_url(self):
        return self.raw['url']['url']
