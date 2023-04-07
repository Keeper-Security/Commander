from typing import Set, Optional

from keepercommander import api
from keepercommander.params import KeeperParams
from keepercommander.subfolder import try_resolve_path


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
