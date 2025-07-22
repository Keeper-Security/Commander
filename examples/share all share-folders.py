from keepercommander.params import KeeperParams
from keepercommander import api
from keepercommander import cli

my_params = KeeperParams()
my_params.user = input('User email: ')

share_users = input('User(s)/Team(s) to share with (comma-separated): ').strip(' ').split(',')

api.login(my_params)
api.sync_down(my_params)
list = api.search_shared_folders(my_params,'') # Can enter searchstring in '' to restrict list of shared folders to share

for shared_folder in list:
    for user in share_users:
        cli.do_command(my_params, f"sf '{shared_folder.shared_folder_uid}' -e '{user}' -p on -o on")