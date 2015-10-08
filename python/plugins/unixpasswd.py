#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from subprocess import Popen, PIPE

"""Commander Plugin for Unix Passwd Command"""
def login():
	return

def logout():
	return

def rotate():
	proc = Popen(['/usr/bin/sudo', '/usr/bin/passwd', 'keepertest'])
	proc.communicate('password2')
	proc.communicate('password3')
	proc.communicate('password3')
