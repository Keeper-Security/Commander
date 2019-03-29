from ..record import Record


def rotate(record, newpassword):
    # type: (Record, str) -> bool
    record.password = newpassword
    return True
