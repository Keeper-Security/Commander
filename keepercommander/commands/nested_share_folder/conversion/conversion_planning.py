"""Classic folder tree discovery and destination planning."""

from collections import deque

from ....error import CommandError
from ....subfolder import (
    BaseFolderNode, SharedFolderFolderNode, SharedFolderNode, try_resolve_path,
)
from ....nested_share_folder.common import MAX_NESTED_SHARE_FOLDER_DEPTH
from .conversion_utils import _escape_non_printable, _pam_record_details


_CLASSIC_FOLDER_TYPES = {
    BaseFolderNode.UserFolderType,
    BaseFolderNode.SharedFolderType,
    BaseFolderNode.SharedFolderFolderType,
}


class FolderConversionPlanner:
    """Discover Classic subtrees and plan their NSF folder layout."""

    @staticmethod
    def _resolve_classic_folder(params, identifier):
        """Resolve one Classic folder by UID, path, or an unambiguous title."""
        folders = getattr(params, 'folder_cache', {}) or {}
        if identifier in folders:
            return identifier

        result = try_resolve_path(params, identifier, find_all_matches=True)
        resolved = []
        if result is not None:
            nodes, tail = result
            if not tail:
                resolved.extend(node.uid for node in nodes if node and node.uid)

        resolved = list(dict.fromkeys(resolved))
        if len(resolved) == 1:
            return resolved[0]
        if len(resolved) > 1:
            raise CommandError(
                'nsf-convert-folder',
                f"Folder '{_escape_non_printable(identifier)}' is ambiguous. "
                'Use a folder UID or full path.')

        matches = [
            uid for uid, node in folders.items()
            if getattr(node, 'name', None) and
            node.name.casefold() == identifier.casefold()
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise CommandError(
                'nsf-convert-folder',
                f"Folder '{_escape_non_printable(identifier)}' is ambiguous. "
                'Use a folder UID or full path.')
        return None

    @staticmethod
    def _classic_scope_uid(node):
        """Return the Classic Shared Folder ACL scope for a node, if any."""
        if isinstance(node, SharedFolderNode):
            return node.uid
        if isinstance(node, SharedFolderFolderNode):
            return node.shared_folder_uid
        return None

    @staticmethod
    def _collect_classic_subtree(params, root_uid):
        """Snapshot the selected Classic subtree and its direct record placements."""
        folder_cache = getattr(params, 'folder_cache', {}) or {}
        record_cache = getattr(params, 'subfolder_record_cache', {}) or {}
        nodes = {}
        parents = {}
        depths = {}
        record_placements = {}

        queue = deque([(root_uid, None, 1)])
        while queue:
            folder_uid, parent_uid, depth = queue.popleft()
            if folder_uid in nodes:
                raise CommandError(
                    'nsf-convert-folder',
                    'The source folder tree contains a cycle or duplicate reference at '
                    f'{folder_uid}.')
            node = folder_cache.get(folder_uid)
            if node is None:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Folder {folder_uid} is missing from the local cache; '
                    'run sync-down and retry.')
            if node.type not in _CLASSIC_FOLDER_TYPES:
                raise CommandError(
                    'nsf-convert-folder',
                    f"'{getattr(node, 'name', folder_uid)}' is not a Classic folder.")
            if not node.name:
                raise CommandError(
                    'nsf-convert-folder',
                    f'Folder {folder_uid} has no name in the local cache.')

            nodes[folder_uid] = node
            parents[folder_uid] = parent_uid
            depths[folder_uid] = depth
            record_placements[folder_uid] = sorted(record_cache.get(folder_uid) or [])

            for child_uid in getattr(node, 'subfolders', []) or []:
                if child_uid not in folder_cache:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Child folder {child_uid} is missing from the local cache; '
                        'run sync-down and retry.')
                queue.append((child_uid, folder_uid, depth + 1))

        return nodes, parents, depths, record_placements

    @staticmethod
    def _folder_plan(parents, depths, destination_depth):
        """Map source UIDs to destination levels/parents, flattening overflow.

        Every source folder remains a distinct destination folder. Source folders
        deeper than the available depth become siblings under the deepest allowed
        source ancestor; their names are deliberately not used as identity.
        """
        available_depth = MAX_NESTED_SHARE_FOLDER_DEPTH - destination_depth
        if available_depth < 1:
            raise CommandError(
                'nsf-convert-folder',
                f'The destination is already at the maximum folder depth '
                f'({MAX_NESTED_SHARE_FOLDER_DEPTH}).')

        target_levels = {
            uid: min(depth, available_depth)
            for uid, depth in depths.items()
        }
        target_parent_sources = {}
        for uid, source_depth in depths.items():
            if source_depth <= available_depth:
                target_parent_sources[uid] = parents[uid]
                continue

            # All overflow folders are promoted to the last representable level.
            # Find the source ancestor at the preceding level (or the external
            # destination when only one level is available).
            promoted_parent = None
            cursor = parents[uid]
            while cursor and depths[cursor] >= available_depth:
                cursor = parents[cursor]
            if cursor and depths[cursor] == available_depth - 1:
                promoted_parent = cursor
            target_parent_sources[uid] = promoted_parent

        return available_depth, target_levels, target_parent_sources

    @staticmethod
    def _collect_records(params, nodes, records_by_folder, allow_converted=False):
        """Collect supported records and their placements in the source tree."""
        nested_records = getattr(params, 'nested_share_records', {}) or {}
        record_cache = getattr(params, 'record_cache', {}) or {}
        records = set()
        placements = {}
        skipped_pam_records = {}
        for folder_uid in nodes:
            for record_uid in records_by_folder.get(folder_uid) or []:
                if record_uid in nested_records and not allow_converted:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is already a Nested Share Record.')
                if record_uid not in record_cache and record_uid not in nested_records:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is missing from the Classic record cache; '
                        'run sync-down and retry.')
                pam_record = _pam_record_details(params, record_uid)
                if pam_record:
                    skipped_pam_records.setdefault(record_uid, pam_record)
                    continue
                owner_info = (getattr(params, 'record_owner_cache', {}) or {}).get(record_uid)
                if owner_info is not None and getattr(owner_info, 'owner', None) is False:
                    raise CommandError(
                        'nsf-convert-folder',
                        f'Record {record_uid} is not owned by the caller and cannot be converted.')
                records.add(record_uid)
                placements.setdefault(record_uid, []).append(folder_uid)
        # Placements retain tree order so the primary target is deterministic.
        ordered_records = sorted(records)
        for record_uid in placements:
            placements[record_uid] = list(dict.fromkeys(placements[record_uid]))
        return ordered_records, placements, list(skipped_pam_records.values())

    @staticmethod
    def _external_placements(params, records, selected_folder_uids):
        """Find selected records that also occur outside the converted subtree."""
        all_placements = getattr(params, 'subfolder_record_cache', {}) or {}
        result = {}
        for record_uid in records:
            outside = sorted(
                folder_uid for folder_uid, record_uids in all_placements.items()
                if record_uid in (record_uids or set()) and
                folder_uid not in selected_folder_uids)
            if outside:
                result[record_uid] = outside
        return result

