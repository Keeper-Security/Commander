from subprocess import Popen, PIPE

class UnixPasswd:
    """Commander Plugin for Unix Passwd Command"""
    def __init__(self, password=''):
        self.password = password

	def login(self):
	    return

	def logout(self):
	    return

	def rotate(self):
		proc = Popen(['/usr/bin/sudo', '/usr/bin/passwd', 'keepertest'])
		proc.communicate('password2')
		proc.communicate('password3')
		proc.communicate('password3')
