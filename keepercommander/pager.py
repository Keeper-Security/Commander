from pypager.pager import Pager


class TablePagerException(Exception):
    pass

class TableNotYetAssignedException(TablePagerException):
    pass

class TablePager(Pager):
    table = None
    headers = None
    
    def __init__(self, tbl, hdr):
        TablePager.table = tbl
        TablePager.headers = hdr
        super().__init__()
   
    @classmethod
    def get_uid(cls, uid: str) -> str or None:
        ''' Resolve uid by line number of previous list command
            Raise TablePagerException if not proper number
        '''
        if not cls.table:
            raise TableNotYetAssignedException("Record number specify needs to be after pager or web showed records.")
        import re
        mt = re.fullmatch(r"(\d{1,4})", uid)
        if mt:
            num = int(mt.group(0))
            if not 0 < num < 10000:
                raise TablePagerException(f"Specify number 1 or less than 10000.")
            lines = TablePager.table
            if num > len(lines):
                raise TablePagerException(f"Specify (0 < number <= ({len(lines)}).")
            return lines[num - 1][1]
        else:
            return None