class KeeperParams:
    """Defines the input parameters for the session"""

    def __init__(self,server='',email='',password='',mfa_token='',
                 command='',debug=False):
        self.server = server 
        self.email = email 
        self.password = password 
        self.mfa_token = mfa_token 
        self.command = command 
        self.debug = debug

    def dump(self):
        if self.server:
            print ('Server: ' + self.server)

        if self.email:
            print ('Email: ' + self.email)

        if self.password:
            print ('Password: ' + self.password)

        if self.mfa_token:
            print ('MFA token: ' + self.mfa_token)

        if self.command:
            print ('Command: ' + self.command)

        if self.debug:
            print ('Debug: ' + str(self.debug))

