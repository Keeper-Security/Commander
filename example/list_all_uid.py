# Show all UIDs in Vault
import sys
import os
sys.path.append("..")
from keepercommander import api, params
import getpass

class KeeperLogin(object):
    ''' Login and sync_down automatically 
        user-ID is gotten from $KEEPER_USER
        user password if from $KEEPER_PASSWORD
        or parameters as with(user, password) ''' 
        
    USER = 'KEEPER_USER'
    PASSWORD = 'KEEPER_PASSWORD'
    
    def __enter__(self, user=None, password=None, user_prompt='User:', password_prompt='Password:'):
        self.params = params.KeeperParams()
        if user:
            self.user = user
        else: 
            try:
                self.params.user = os.environ[KeeperLogin.USER] # getpass.getuser()
            except:
                self.params.user = input(user_prompt)
        if password:
            self.params.password = password
        else:
            try:
                self.params.password = os.environ[KeeperLogin.PASSWORD]
            except:
                self.params.password = getpass.getpass(password_prompt)
        api.login(self.params)
        api.sync_down(self.params)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass
    
if __name__ == '__main__':
    import logging
    logger = logging.getLogger(__file__)
    logger.setLevel(logging.INFO)

    with KeeperLogin() as keeper_login:
        for uid in keeper_login.params.record_cache:
            record = api.get_record(keeper_login.params, uid) 
            print(f"{uid}\t{record.title}")

    exit(0)