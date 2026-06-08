import re
from typing import Set, Optional

from ... import api
from ...error import CommandError
from ...params import KeeperParams
from ...subfolder import try_resolve_path

# Block shell chaining markers in `get` lookup tokens.
_GET_LOOKUP_CONTROL_CHARS_RE = re.compile(r'[\r\n\x00]')
_GET_LOOKUP_SHELL_METACHAR_RE = re.compile(r'[;|]')
_GET_LOOKUP_CHAIN_RE = re.compile(r'&&')


def raise_if_unsafe_get_lookup_token(token, command='get'):
    # type: (str, str) -> None
    if not token:
        raise CommandError(command, 'Invalid record identifier: forbidden characters')
    if (_GET_LOOKUP_CONTROL_CHARS_RE.search(token)
            or _GET_LOOKUP_SHELL_METACHAR_RE.search(token)
            or _GET_LOOKUP_CHAIN_RE.search(token)):
        raise CommandError(command, 'Invalid record identifier: forbidden characters')


# Get record UID(s) given one of its identifiers: name (if current folder contains the record), path, or UID
def get_record_uids(params, name):  # type: (KeeperParams, str) -> Set[Optional[str]]
    uids = set()
    if name in params.record_cache:
        uids = [name]
    else:
        rs = try_resolve_path(params, name, find_all_matches=True)
        # if rs is not None:
        folders, name = rs
        if folders and name is not None:
            for folder in folders:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for r_uid in params.subfolder_record_cache[folder_uid]:
                        r = api.get_record(params, r_uid)
                        if r.title.lower() == name.lower():
                            uids.add(r_uid)
    return uids
