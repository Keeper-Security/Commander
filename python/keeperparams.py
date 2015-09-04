class KeeperParams:
    """Defines the input parameters for the session"""

    def __init__(self,server='',email='',password='',mfa_token='',
                 mfa_type='',command='',session_token='',
                 salt='',iterations='',debug=False):
        self.server = server 
        self.email = email 
        self.password = password 
        self.mfa_token = mfa_token 
        self.command = command 
        self.session_token = session_token 
        self.salt = salt 
        self.iterations = iterations 
        self.debug = debug

    def logout(self):
        self.mfa_token = '' 
        self.session_token = '' 

    def dump(self):
        if self.server:
            print ('>> Server: ' + self.server)

        if self.email:
            print ('>> Email: ' + self.email)

        if self.password:
            print ('>> Password: ' + self.password)

        if self.mfa_token:
            print ('>> 2FA token: ' + self.mfa_token)

        if self.mfa_type:
            print ('>> 2FA type: ' + self.mfa_type)

        if self.command:
            print ('>> Command: ' + self.command)

        if self.session_token:
            print ('>> Session Token: ' + str(self.session_token))

        if self.salt:
            print ('>> Salt: ' + str(self.salt))

        if self.iterations:
            print ('>> Iterations: ' + str(self.iterations))

        if self.debug:
            print ('>> Debug: ' + str(self.debug))


