# Modified parts
 - cli.py ```print exception location```
  - api.py : sync after login
  - keepercommander/commands/record.py:
        sort by any field:
            list_parser.add_argument('-s', '--sort', dest='sort', action='store', choices=['record_uid', 'folder', 'title', 'login', 'password', 'revision', 'notes', 'login_url'], default='title', help="Sort records by record_uid, folder, title, login, password, revision, notes or login_url")
# How to use:
 ## List records sorted by date: the last modified record is printed last
  - list -s revision
 ## Search is same as List: But it might be better if sort object is selected from fields..
  - sort **pattern** -s revision