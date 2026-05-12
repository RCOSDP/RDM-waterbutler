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


async def run_pre_checks(src_provider, src_path, dest_provider,
                         max_size_bytes=None, check_quota=False):
    """
    Run max_file_size and quota pre-checks inside the Celery task.
    Raises InvalidParameters (413) or NotEnoughQuotaError if checks fail.
    """
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
        file_size = await _get_total_size(src_provider, data)
        quota = await dest_provider.get_quota()
        if quota['used'] + file_size > quota['max']:
            raise exceptions.NotEnoughQuotaError({
                'message_key': 'quota_exceeded',
                'message': 'You do not have enough available quota.',
            })
