"""NSF folder creation and verified Classic source deletion."""

import logging

from .... import nested_share_folder as _nsf, sync_down
from ....display import bcolors
from ....error import CommandError
from ....nested_share_folder.common import NSF_FOLDER_BATCH_SIZE
from .conversion_planning import FolderConversionPlanner
from .conversion_utils import _escape_non_printable
from ..helpers import _folder_depth


class FolderConversionTree:
    """Create the planned NSF tree and safely remove emptied Classic sources."""

    @staticmethod
    def _destination_depth(params, destination_uid):
        """Return the destination's current depth, or zero at the vault root."""
        if not destination_uid:
            return 0
        depth = _folder_depth(params, destination_uid)
        if depth <= 0:
            raise CommandError(
                'nsf-convert-folder',
                f'Could not determine the depth of destination folder {destination_uid}.')
        return depth

    @staticmethod
    def _validate_folder_keys(params, destination_uid):
        """Ensure required vault and destination keys are available before writes."""
        if not getattr(params, 'data_key', None):
            raise CommandError(
                'nsf-convert-folder', 'User data key is unavailable; run sync-down and retry.')
        if destination_uid:
            try:
                _nsf.get_folder_key(params, destination_uid, raise_on_missing=True)
            except Exception as exc:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Destination folder key is unavailable; run sync-down and retry. {exc}')

    @staticmethod
    def _create_target_tree(params, nodes, target_levels, target_parent_sources,
                            destination_uid, show_progress, existing_target_uids=None):
        """Create missing target folders one depth at a time in bounded batches."""
        if getattr(params, 'nested_share_folders', None) is None:
            params.nested_share_folders = {}
        target_uids = dict(existing_target_uids or {})
        if len(set(target_uids.values())) != len(target_uids):
            raise CommandError(
                'nsf-convert-folder',
                'The retry mapping selects the same NSF folder more than once.')

        def normalized_parent(folder_uid):
            """Normalize the parent UID to the existing NSF tree."""
            parent_uid = (params.nested_share_folders.get(folder_uid) or {}).get('parent_uid') or ''
            return parent_uid if parent_uid in params.nested_share_folders else None

        for source_uid, target_uid in target_uids.items():
            target_folder = params.nested_share_folders.get(target_uid)
            parent_source_uid = target_parent_sources[source_uid]
            expected_parent_uid = (
                target_uids.get(parent_source_uid) if parent_source_uid else destination_uid)
            if (not target_folder or
                    target_folder.get('name') != nodes[source_uid].name or
                    normalized_parent(target_uid) != expected_parent_uid):
                raise CommandError(
                    'nsf-convert-folder',
                    f'Retry target folder {target_uid} no longer matches Classic folder '
                    f'{source_uid}; run sync-down and inspect before retrying.')

        for target_level in sorted(set(target_levels.values())):
            source_uids = [
                uid for uid, level in target_levels.items()
                if level == target_level and uid not in target_uids
            ]
            if not source_uids:
                continue
            for start in range(0, len(source_uids), NSF_FOLDER_BATCH_SIZE):
                chunk = source_uids[start:start + NSF_FOLDER_BATCH_SIZE]
                specs = []
                for source_uid in chunk:
                    source_node = nodes[source_uid]
                    parent_source_uid = target_parent_sources[source_uid]
                    parent_uid = (
                        target_uids[parent_source_uid] if parent_source_uid
                        else destination_uid
                    )
                    specs.append({
                        'name': source_node.name,
                        'parent_uid': parent_uid,
                        'color': getattr(source_node, 'color', None),
                        # NSF permissions inherit along the reconstructed tree;
                        # each Classic share boundary is granted separately.
                        'inherit_permissions': bool(parent_uid),
                    })

                # Ensure an uncertain transport failure triggers a refresh;
                # the batch API allocates UIDs internally before sending.
                params.sync_data = True
                try:
                    results = _nsf.create_folders_batch_v3(params, specs)
                except Exception as exc:
                    raise CommandError(
                        'nsf-convert-folder',
                        'The outcome of an NSF folder creation request is unknown. '
                        'Run sync-down and inspect the destination before retrying; '
                        f'the Classic source tree was left intact. {exc}')
                if len(results) != len(chunk):
                    params.sync_data = True
                    raise CommandError(
                        'nsf-convert-folder',
                        'Folder creation returned an incomplete result set; '
                        'the Classic source tree was left intact.')
                failures = []
                for source_uid, result in zip(chunk, results):
                    if not result.get('success'):
                        failures.append(
                            f"{_escape_non_printable(nodes[source_uid].name)} "
                            f"({source_uid}): "
                            f"{result.get('message') or result.get('status')}")
                        continue
                    target_uid = result['folder_uid']
                    target_uids[source_uid] = target_uid
                    entry = {
                        'name': result.get('name') or nodes[source_uid].name,
                        'parent_uid': result.get('parent_uid') or
                                      (target_uids.get(target_parent_sources[source_uid])
                                       if target_parent_sources[source_uid]
                                       else destination_uid or ''),
                        'folder_key_unencrypted': result['folder_key_unencrypted'],
                    }
                    color = getattr(nodes[source_uid], 'color', None)
                    if color and color != 'none':
                        entry['color'] = color
                    params.nested_share_folders[target_uid] = entry

                if failures:
                    params.sync_data = True
                    raise CommandError(
                        'nsf-convert-folder',
                        'Could not create the full NSF folder tree; any folders already '
                        'created were left in place and the Classic source tree was left '
                        'intact. Review the partial NSF structure and rerun with --retry '
                        'to reconcile. ' + '; '.join(failures[:5]))

                if show_progress:
                    print(
                        f'  {bcolors.OKGREEN}✓{bcolors.ENDC} Created '
                        f'{len(chunk)} NSF folder(s) at target depth {target_level}.')
        return target_uids

    @staticmethod
    def _print_uid_mapping(nodes, target_uids):
        """Display the UID mapping between the source and destination trees."""
        print('  Folder UID mapping:')
        for source_uid, target_uid in target_uids.items():
            print(
                f'    {_escape_non_printable(nodes[source_uid].name)} '
                f'({source_uid}) -> {target_uid}')

    @staticmethod
    def _delete_classic_source(params, source_uid):
        """Delete only a freshly verified empty subtree; return None if outcome is unknown."""
        from ...folder import FolderRemoveCommand

        try:
            sync_down.sync_down(params)
            folder_cache = getattr(params, 'folder_cache', {}) or {}
            if source_uid not in folder_cache:
                return True
            _, _, _, records_by_folder = (
                FolderConversionPlanner._collect_classic_subtree(params, source_uid))
            remaining = {
                folder_uid: record_uids
                for folder_uid, record_uids in records_by_folder.items()
                if record_uids
            }
            if remaining:
                details = '; '.join(
                    f'{folder_uid}: {", ".join(record_uids[:5])}'
                    for folder_uid, record_uids in remaining.items())
                logging.warning(
                    'Classic source tree %s still contains record placements; '
                    'skipping recursive deletion. %s', source_uid, details)
                return False

            FolderRemoveCommand().execute(
                params, pattern=[source_uid], force=True, quiet=True)
            sync_down.sync_down(params)
            if source_uid in (getattr(params, 'folder_cache', {}) or {}):
                logging.warning(
                    'The conversion succeeded, but Classic source folder %s '
                    'still appears after deletion.', source_uid)
                return False
            logging.info('Classic source folder tree deleted.')
            return True
        except Exception as exc:
            logging.warning(
                'Conversion succeeded, but the Classic source tree deletion status '
                'could not be confirmed: %s', exc)
            return None


