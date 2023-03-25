from keepercommander import api
from keepercommander.params import KeeperParams
from keepercommander.subfolder import try_resolve_path


# Get record UID given one of its identifiers: name (if current folder contains the record), path, or UID
def get_record_uid(params, name):   # type: (KeeperParams, str) -> str or None
    uid = None
    if name in params.record_cache:
        uid = name
    else:
        rs = try_resolve_path(params, name)
        if rs is not None:
            folder, name = rs
            if folder is not None and name is not None:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for r_uid in params.subfolder_record_cache[folder_uid]:
                        r = api.get_record(params, r_uid)
                        if r.title.lower() == name.lower():
                            uid = r_uid
                            break
    return uid
