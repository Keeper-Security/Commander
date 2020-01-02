# How to use:
 ## List records sorted by date: the last modified record is printed last
  - list -m 
  - list -m -r
 ## Search : use sort by revision
  - search **pattern** -s revision
 ## Pager (show by page) option
  - list -p
 ## Get command accepts # number by pager as record_uid
  - get # (# is a number of 1st column shown by pager output of List command)
# Modified parts
 - cli.py ```print exception location```
  - api.py : sync after login
  - keepercommander/commands/record.py:
        sort by any field:
            list_parser.add_argument('-s', '--sort', dest='sort', action='store', choices=['record_uid', 'folder', 'title', 'login', 'password', 'revision', 'notes', 'login_url'], default='title', help="Sort records by record_uid, folder, title, login, password, revision, notes or login_url")
 ## Logger: put info. out into a logging file 'keeper.log'
  - ```__main__.py``` : logger = logging.getLogger()

## keepercommander/commands/record.py is moved to keepercommander/commands/record/commands.py and keepercommander/commands/record/__init__.py is added
 ### Why change? : script file name 'record.py' is duplicating. : confusing to find in editor tab
 - ```__init__.py``` : from .commands import *
 - commands.py : change all "from ..(file/module) import" to "from ...(file/module) import" ; 3 dots means 2-level up
  

