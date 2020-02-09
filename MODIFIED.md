# How to use:
 ## List records sorted by date: the last modified record is printed first
  - list -m -r
  ### List sorted by titles: Sort order is language-wise by locale setting(environment variable : LANG)
     - list -s title
 ## Search : use sort by revision
  - search **pattern** -s revision
 ## Pager (show by page) option : no uid is shown in pager view
  - list -p
 ## Web view option : port 6080
  - list -w
 ## Get command accepts # number by pager as record_uid( ** pending **)
  - get # (# is a number of 1st column shown by pager output of List command)
# Modified parts
# Added files:
 - locale.py under keepercommander
# Modified files:
 - requirements.txt += ['pypager']
 - setup.py : added modules: ```install_requires = [
     ...
    'pypager',
    'pyicu'
    ]
    ```
 - cli.py ```print exception location```
  - api.py : sync after login
  - keepercommander/commands/record.py:
        sort by any field:
            list_parser.add_argument('-s', '--sort', dest='sort', action='store', choices=['record_uid', 'folder', 'title', 'login', 'password', 'revision', 'notes', 'login_url'], const='title', help="Sort records by record_uid, folder, title, login, password, revision, notes or login_url")
 
 ## Logging: print file name and line number by logging format
  - keepercommander/__init__.py : __logging_format__
 
 ## keepercommander/commands/record.py is moved to keepercommander/commands/record/commands.py and keepercommander/commands/record/__init__.py is added
    ### Why change? : script file name 'record.py' is duplicating. : confusing to find in editor tab
    - ```__init__.py``` : from .commands import *
    - commands.py : change all "from ..(module) import" to "from ...(module) import" ; 3 dots means 2-level up
  

