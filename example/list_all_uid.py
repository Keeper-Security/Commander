# Show all UIDs in Vault
import sys
import os
import getpass
sys.path.append(".")
sys.path.append("../.venv/lib/python3.6/dist-packages")
from keepercommander import api, params # set PYTHONPATH=<absolute path to keepercommander>


class KeeperLogin(object):
    ''' Login and sync_down automatically 
        user-ID is gotten from $KEEPER_USER
        user password if from $KEEPER_PASSWORD
        or parameters as with(user, password) '''

    USER = 'KEEPER_USER'
    PASSWORD = 'KEEPER_PASSWORD'

    def __enter__(self, user=None, password=None, user_prompt='User:', password_prompt='Password:'):
        self.params = params.KeeperParams()
        self.params.user = user or os.getenv(KeeperLogin.USER) or input(user_prompt)
        self.params.password = password or os.getenv(KeeperLogin.PASSWORD) or getpass.getpass(password_prompt)
        api.login(self.params)
        api.sync_down(self.params)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.params.clear_session()  # clear internal variables

def check_record_cache_with_list_command():
    pass

if __name__ == '__main__':
    import logging
    logger = logging.getLogger(__file__)
    logger.setLevel(logging.INFO)
    inspects = [] # put UID to inspect as string literal like 'abc', comma separated 
    with KeeperLogin() as keeper_login:
        for uid in keeper_login.params.record_cache:
            record = api.get_record(keeper_login.params, uid) 
            print(f"{uid}\t{record.title}\t{record.login_url.split('?')[0]}")  # cut ?-trailing parameter
            if uid in inspects:
                pass # breakpoint

    exit(0)
