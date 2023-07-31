from waterbutler.providers.nextcloud import NextcloudProvider


class NextcloudInstitutionsProvider(NextcloudProvider):
    NAME = 'nextcloudinstitutions'

    async def _metadata_file(self, path, **kwargs):
        # Nextcloud for Institutions: Add support for getting metadata of previous file version
        revision = None
        if 'revision' in kwargs and kwargs['revision']:
            revision = kwargs['revision']

        if revision is None:
            items = await self._metadata_folder(path, skip_first=False, **kwargs)
            return items[0]
        else:
            revisions = await self._metadata_revision(path)
            items = []
            file_href = None
            latest = len(revisions)
            for i in range(latest):
                r = revisions[i]
                if i == 0:
                    file_href = r._href
                ver = str(r.etag_noquote)
                if ver == revision:
                    if file_href:
                        r._href = file_href
                    items.append(r)
            return items[0]
