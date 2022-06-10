from ..vault import KeeperRecord


def rotate(record, newpassword):   # type: (KeeperRecord, str) -> bool
    record.password = newpassword
    return True
