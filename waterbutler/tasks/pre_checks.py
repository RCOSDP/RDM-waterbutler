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


async def get_replaced_size(dest_provider, dest_container_path, resolved_name, conflict):
    """Size of the existing file/folder being overwritten on replace, else 0."""
    if conflict != 'replace' or dest_container_path is None:
        return 0

    children = await _fetch_all_pages(dest_provider, dest_container_path)
    existing = next((child for child in children if child.name == resolved_name), None)
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
    replaced, both of which evaluate_quota() would otherwise discard.

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


async def evaluate_quota(operation, src_provider, dest_provider, file_size, replaced_size=0):
    """Check destination quota, skipping moves within the same UserQuota record.

    Convenience wrapper for callers that already know both sizes. Callers that would have
    to do expensive work to learn them should call resolve_quota_context() first and bail
    out on skip, then call check_quota_limit() directly.
    """
    skip, dest_quota = await resolve_quota_context(operation, src_provider, dest_provider)
    if skip:
        return
    check_quota_limit(dest_quota, file_size, replaced_size)


async def run_pre_checks(src_provider, src_path, dest_provider, dest_path=None,
                         max_size_bytes=None, check_quota=False, operation=None,
                         conflict='replace', rename=None):
    """Run max_file_size and quota pre-checks inside the Celery task."""
    # Only fetch data once, reuse for both checks
    needs_check = max_size_bytes is not None or check_quota
    if not needs_check:
        return

    if src_path.is_dir:
        data = await _fetch_all_pages(src_provider, src_path)
    else:
        data = [await src_provider.metadata(src_path, version=None, revision=None)]

    # Check 1: max file size
    if max_size_bytes is not None:
        oversized = await _get_oversized_files(src_provider, data, max_size_bytes)
        if oversized:
            raise exceptions.InvalidParameters({
                'message': 'Move/Copy Failed due to oversized files.',
                'oversized_files': oversized,
                'max_size': max_size_bytes,
            }, code=413)

    # Check 2: quota
    if check_quota:
        skip, dest_quota = await resolve_quota_context(operation, src_provider, dest_provider)
        if not skip:
            file_size = await _get_total_size(src_provider, data)
            resolved_name = rename or src_path.name
            replaced_size = await get_replaced_size(dest_provider, dest_path,
                                                    resolved_name, conflict)
            check_quota_limit(dest_quota, file_size, replaced_size)
