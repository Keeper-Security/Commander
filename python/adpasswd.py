#!/usr/bin/env python
"""adpasswd.py Command line interface to change Active Directory 
Passwords via LDAP.
Copyright 2009 Craig Sawyer
email: csawyer@yumaed.org
license: GPLv2 see LICENSE.txt
"""
import os
import sys
import ldaplib
import ConfigParser
import getpass
CONFIG_FILENAME='.adpasswd.cfg'

class InvalidConfigException(Exception): pass

def GetConfig():
	cf = None
	if os.path.exists(CONFIG_FILENAME):
		configfile = CONFIG_FILENAME
	else:
		homedrive = None
		if os.name == 'posix':
			path = os.environ['HOME']
		elif os.name == 'nt':
			if os.environ.has_key('HOMEPATH'):
				homedrive = os.environ['HOMEDRIVE'] 
				path = os.environ['HOMEPATH']
		configfile = os.path.join(homedrive, path,CONFIG_FILENAME)
	if os.path.exists(configfile):
		fd = open(configfile,'r')
		config = ConfigParser.ConfigParser()
		config.readfp(fd)
		if config.has_section('ad'):
			cf = dict()
			for name,value in config.items('ad'):
				cf[name] = value
		else:
			raise InvalidConfigException()
			print( 'Config file seems misconfigured.. no [ad] section')
	else:
		print( "we need a config file here %s or the cwd. " % (configfile))
		print( """example config:
		[ad]
	host: ad.blah.com
	port: 636
	binddn: cn=Administrator,CN=Users,DC=ad,DC=blah,DC=com
	bindpw: changemequickly	
	searchdn: DC=ad,DC=blah,DC=com		
		""")
		raise InvalidConfigException()
		print( "No valid config file. Quitting.")
	return cf
	
	
class ADInterface(object):
	
	def __init__(self,config):
		"""config must be a dictionary of items (use GetConfig)"""
		self.config = config
		self.connect()
	
	def connect(self):
		"""Connect to AD thru LDAP"""
		self.l = ldaplib.ldap_connection((self.config['host'],\
            int(self.config['port'])))
		x = self.l.bind(self.config['binddn'],self.config['bindpw'])
		if x is not None:
			print( 'bind error:',x.resultcode,'error:',x.errorMessage)
			sys.exit(x)
			
	def makepassword(self,pw):
		"""Make a unicodePwd String for Windows AD junk."""
		unicode1 = unicode("\"" + pw + "\"", "iso-8859-1")
		unicode2 = unicode1.encode("utf-16-le")
		password_value = unicode2
		del pw
		return password_value

	def modify(self,dn,attr,values,mode='replace'):
		"""values must be a []"""
		#[[operation,type,[vals]],[operation,type,[vals]]]
		#print( 'Modify called:',dn,attr,values,mode)
		x = self.l.modify(dn,[[mode,attr,values]])
		if x.errorMessage:
			#['__doc__', '__init__', '__module__', 'app_code', 'args', \
            #'buffer', 'decode', 'decode_sequence', 'encode', 'errorMessage', \
            #'keyvals', 'matcheddn', 'messageid', 'myargs', 'resultcode']
			print( 'dn:',dn)
			print( 'Modify Operation failure res:',x.resultcode,'error:',x.errorMessage)
			#print( 'buffer:',x.buffer,'decode',x.decode())
			#print( dir(x))
		return True

	def findUser(self,name):
		userDN = None
		x = self.l.search('sAMAccountName=%s' % (name),self.config['searchdn'],attributes=['distinguishedName'])
		#print( 'num results:',len(x))
		if len(x) > 1:
		 	#print( 'returned:',x[0].keyvals)
			userDN = x[0].keyvals['distinguishedName'][0]
		return userDN
	
	# Begin API Calls
	def changepass(self,user,passwd):
		"""call with string, user and passwd """
		passwd = self.makepassword(passwd)
		user = self.findUser(user)
		if not user:
			raise 'Invalid Username, user not found.'
		self.modify(user,'unicodePwd',[passwd])
			

def Main():
	user = None
	password = None
	if len(sys.argv) == 3:
		user = sys.argv[1]
		password = sys.argv[2]
	if len(sys.argv) == 2:
		user = sys.argv[1]
		password = getpass.getpass()
	if user and password:
		cf = GetConfig()
		l = ADInterface(cf)
		l.changepass(user,password)
	else:
		print( "adpasswd.py: You must specify <username> and (optionally) <password>")
		print( "usage: adpasswd.py username [password]")
		sys.exit(1)
if __name__ == "__main__":
	Main()
