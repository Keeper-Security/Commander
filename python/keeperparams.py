class KeeperParams:
    """Defines the input parameters for the session"""

    def __init__(self,server='',email='',password='',mfa_token='',command='',debug=False):
        self.server = server 
        self.email = email 
        self.password = password 
        self.mfa_token = mfa_token 
        self.command = command 
        self.debug = debug

    def dump(self):
        if self.debug:
            print ('Server: ' + self.server)
            print ('Email: ' + self.email)
            print ('Password: ' + self.password)
            print ('MFA token: ' + self.mfa_token)
            print ('Command: ' + self.command)
            print ('Debug: ' + str(self.debug))

