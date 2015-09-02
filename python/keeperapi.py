import sys
import json
import requests

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
        if not self.server:
            print('Error: server is not defined.')
            sys.exit()

        if not self.email:
            print('Error: email is not defined.')
            sys.exit()

        if not self.password:
            print('Error: password is not defined.')
            sys.exit()

        if not self.command:
            print('Prompt user for command')
            self.command = self.promptCommand()

        print('Logging in...')
        self.login() 

    def promptCommand(self):
        print('prompting for command string')
