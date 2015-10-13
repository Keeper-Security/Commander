# -*- coding: utf-8 -*-
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

import pexpect

"""Commander Plugin for Unix Passwd Command"""
def rotate(user, oldpassword, newpassword):
	child = pexpect.spawn("/usr/bin/passwd %s"%(user))
	i = child.expect(['[Oo]ld [Pp]assword', '.current.*password', '[Nn]ew [Pp]assword'])
	if i == 0 or i == 1:
		child.sendline(oldpassword)
		child.expect('[Nn]ew [Pp]assword')
	child.sendline(newpassword)
	child.expect("Retype New Password:")
	child.sendline(newpassword)
	child.expect(pexpect.EOF)
	child.close()
