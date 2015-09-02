import json

VERSION = '0.1'

class KeeperAPI:
    """Communicates with the Keeper API"""

    def __init__(self):
        self.server = ''
        self.email = ''
        self.password = ''
        self.mfa_token = ''
        self.command = ''
        self.debug = True

    def dump(self):
        if self.debug == True:
            print ('Version: ' + VERSION)
            print ('Server: ' + self.server)
            print ('Email: ' + self.email)
            print ('Password: ' + self.password)
            print ('MFA token: ' + self.mfa_token)
            print ('Command: ' + self.command)

    def login(self):
        print('Login')

    def logout(self):
        print('Logout')

    def ping(self):
        print('Ping')

    def go(self):
        print('Go baby!')

