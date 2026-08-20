from waterbutler.core import exceptions


async def _fetch_all_pages(provider, path):
    """Fetch all children with pagination support."""
    all_data = []
    next_token = None
    while True:
        data = await provider.metadata(path, version=None, revision=None, next_token=next_token)
        if data and isinstance(data[-1], str):
            data, next_token = provider.handle_data(data)
        else:
            next_token = None
        all_data.extend(data)
        if not next_token:
            break
    return all_data


async def _get_total_size(provider, data):
    """Recursively calculate total size of all files."""
    size = 0
    for item in data:
        if item.kind == 'file':
            size += int(item.size)
        else:
            child_path = await provider.validate_path(item.path)
            children = await _fetch_all_pages(provider, child_path)
            size += await _get_total_size(provider, children)
    return size


async def _get_oversized_files(provider, data, max_size_bytes):
    """Recursively find files exceeding max_size_bytes."""
    oversized = []
    for item in sorted(data, key=lambda i: (0 if i.kind == 'folder' else 1, i.name.lower())):
        if item.kind == 'file':
            if int(item.size) > max_size_bytes:
                oversized.append({'name': item.name, 'size': int(item.size)})
        else:
            child_path = await provider.validate_path(item.path)
            children = await _fetch_all_pages(provider, child_path)
            oversized.extend(await _get_oversized_files(provider, children, max_size_bytes))
    return oversized


async def get_replaced_size(dest_provider, dest_container_path, resolved_name, conflict,
                            src_kind):
    """Size of the existing file/folder being overwritten on replace, else 0.

    ``src_kind`` is the kind ('file' or 'folder') of the item being moved/copied. Only a
    destination child of that same kind is actually overwritten: osfstorage allows a file
    and a folder to share one name (``can_duplicate_names()`` is True), so matching on the
    name alone would subtract the size of an item that survives the operation and let the
    user push ``used`` past ``max``.
    """
    if conflict != 'replace' or dest_container_path is None:
        return 0

    children = await _fetch_all_pages(dest_provider, dest_container_path)
    existing = next((child for child in children
                     if child.name == resolved_name and child.kind == src_kind), None)
    if existing is None:
        return 0

    if existing.kind == 'file':
        return int(existing.size)

    existing_path = await dest_provider.validate_path(existing.path)
    existing_children = await _fetch_all_pages(dest_provider, existing_path)
    return await _get_total_size(dest_provider, existing_children)


async def resolve_quota_context(operation, src_provider, dest_provider):
    """Fetch the destination quota and decide whether the check can be skipped outright.

    Returns ``(skip, dest_quota)``. When ``skip`` is True the operation stays inside one
    UserQuota record, so ``used`` cannot grow and no size needs to be computed at all --
    callers should bail out *before* walking the source tree or looking up the item being
    replaced, since neither result would change the outcome.

    ``dest_quota`` is returned so callers can hand it straight to check_quota_limit()
    instead of re-fetching it; this keeps the number of creator_quota requests identical
    to the previous single-function implementation.
    """
    dest_quota = await dest_provider.get_quota()

    if operation == 'move' and src_provider.NAME == 'osfstorage':
        src_quota = await src_provider.get_quota()
        src_user_guid = src_quota.get('user_guid')
        if (src_user_guid is not None and
                src_user_guid == dest_quota.get('user_guid') and
                src_quota.get('storage_type') == dest_quota.get('storage_type')):
            return True, dest_quota

    return False, dest_quota


def check_quota_limit(dest_quota, file_size, replaced_size=0):
    """Raise NotEnoughQuotaError when the operation would push `used` past `max`."""
    if dest_quota['used'] + file_size - replaced_size > dest_quota['max']:
        raise exceptions.NotEnoughQuotaError({
            'message_key': 'quota_exceeded',
            'message': 'You do not have enough available quota.',
        })


def should_skip_size_check(operation, src_provider, dest_provider, src_nid, dest_nid):
    """True when a move stays within the same storage and location (size can't change).

    For osfstorage, "same location" means same region (``is_same_region()``), since a
    same-region move never changes which bucket holds the data. Other providers fall back
    to node-match via the caller-supplied ``src_nid``/``dest_nid`` -- not ``provider.nid``,
    which is usually ``None`` on both sides and would wrongly match every cross-project move.

    Independent from resolve_quota_context()'s skip: the two can diverge (e.g. different
    creator keeps this skip but not quota's; cross-region keeps quota's skip but not this).
    """
    if operation != 'move' or src_provider.NAME != dest_provider.NAME:
        return False
    if src_provider.NAME == 'osfstorage':
        return src_provider.is_same_region(dest_provider)
    return src_nid == dest_nid


async def run_pre_checks(src_provider, src_path, dest_provider, dest_path=None,
                         max_size_bytes=None, check_quota=False, operation=None,
                         conflict='replace', rename=None, src_nid=None, dest_nid=None):
    """Run max_file_size and quota pre-checks inside the Celery task.

    The two checks have independent skip conditions: see should_skip_size_check() and
    resolve_quota_context(). The quota check (and its creator_quota fetch) is deferred
    until *after* the max_file_size check has run and passed, so an oversized file is
    rejected with 413 without ever calling creator_quota.
    """
    run_size_check = max_size_bytes is not None and not should_skip_size_check(
        operation, src_provider, dest_provider, src_nid, dest_nid)

    if not run_size_check and not check_quota:
        return

    data = None

    # Check 1: max file size. Only fetches source data when the check actually applies,
    # so a same-storage/same-project move that also skips quota never walks the tree.
    if run_size_check:
        if src_path.is_dir:
            data = await _fetch_all_pages(src_provider, src_path)
        else:
            data = [await src_provider.metadata(src_path, version=None, revision=None)]

        oversized = await _get_oversized_files(src_provider, data, max_size_bytes)
        if oversized:
            raise exceptions.InvalidParameters({
                'message': 'Move/Copy Failed due to oversized files.',
                'oversized_files': oversized,
                'max_size': max_size_bytes,
            }, code=413)

    if not check_quota:
        return

    # Check 2: quota -- resolved only now that check 1 has passed (or didn't apply).
    skip, dest_quota = await resolve_quota_context(operation, src_provider, dest_provider)
    if skip:
        return

    if data is None:
        if src_path.is_dir:
            data = await _fetch_all_pages(src_provider, src_path)
        else:
            data = [await src_provider.metadata(src_path, version=None, revision=None)]

    file_size = await _get_total_size(src_provider, data)
    resolved_name = rename or src_path.name
    src_kind = 'folder' if src_path.is_dir else 'file'
    replaced_size = await get_replaced_size(dest_provider, dest_path,
                                            resolved_name, conflict, src_kind)
    check_quota_limit(dest_quota, file_size, replaced_size)
