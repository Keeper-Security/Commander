#!/usr/bin/env python
"""adpasswd.py Command line interface to change Active Directory 
Passwords via LDAP.
Copyright 2009 Craig Sawyer
email: csawyer@yumaed.org
license: GPLv2 see LICENSE.txt
"""
import os
import sys
import configparser
import getpass
import socket
import struct

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
		config = configparser.ConfigParser()
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
			

def XXXXX():
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


#---------------- Additional Classes -------------- # 
"""
Originally from sourceforge project:
ldaplib.py from http://sourceforge.net/projects/ldaplibpy/
email:   	 scmgre@users.sourceforge.net
licence: GPL (according to SF.net)

changes made by Craig Sawyer
email: csawyer@yumaed.org
	* Added SSL support
	* Added some documentation. 


"""

AND=0x00			 #[0] SET OF Filter
OR=0x01				 #[1] SET OF Filter,
NOT=0x02			 #[2] Filter,
EQUALITYMATCH=0x03	 #[3] AttributeValueAssertion,
SUBSTRINGS=0x04		 #[4] SubstringFilter,
GREATEROREQUAL=0x05	 #[5] AttributeValueAssertion,
LESSOREQUAL=0x06	 #[6] AttributeValueAssertion,
PRESENT=0x07		 #[7] AttributeDescription,
APPROXMATCH=0x08	 #[8] AttributeValueAssertion,
EXTENSIBLEMATCH=0x09 #[9] MatchingRuleAssertion }

LDAPVERSION1=0x01
LDAPVERSION2=0x02
LDAPVERSION3=0x03
#cls
UNIVERSAL=0x00
APPLICATION=0x40
CONTEXT=0x80
PRIVATE=0xc0

#pc
PRIMITIVE=0x00
CONSTRUCTED=0x20
#number
EOC=0x00
BOOLEAN=0x01
INTEGER=0x02
BITSTRING=0x03
OCTETSTRING=0x04
NULL=0x05
OID=0x06
OD=0x07
EXTERNAL=0x08
REAL=0x09
ENUMERATED=0x0A
EMBEDDED=0x0B
UTF8String=0x0C
RELATIVEOID=0x0D
SEQUENCE=0x10
SET=0x11
NumericString=0x12
PrintableString=0x13
T61String=0x14
VideotexString=0x15
IA5String=0x16
UTCTime=0x17
GraphicString=0x19
VisibleString=0x1A
GeneralString=0x1B
UniversalString=0x1C
CHARACTERSTRING=0x1D
BMPString=0x1E
#LDAP MOD CODES
ADD=0x00
DELETE=0x01
REPLACE=0x02
#LDAP application codes

BIND=0x00
BINDRESP=0x01
UNBIND=0x02
SEARCHREQ=0x03
SEARCHRESENTRY=0x04
SEARCHRESDONE=0x05
SEARCHRESREF=0x06
MODIFYREQUEST=0x06
MODIFYRESP=0x07
ADDREQUEST=0x08
ADDRESP=0x09
DEL=0x0a
DELRESP=0x0b
MODIFYRDN=0x0c
MODIFYRDNRESP=0x0d
COMPARE=0x0e
COMPARERESP=0x0f
ABANDON=0x10
EXTENDEDREQ=0x11
EXTENDEDRESP=0x12

#LDAP MOD CODES
modifyops = {
	'add':0,
	'delete':1,
	'replace':2
}

class sock:
	"""Lightweight Wrapper around Socket and SSL, so we can use the same code 
    everywhere else and ignore if SSL is actually on the link or not.
	NOTE: SSL is just magically trusted, keys and stuff are beyond this code!
	Not for using across an insecure link!
	"""
	def __init__(self):
		self.socket = socket.socket()
		self.ssl = False
		
	def connect(self,address,ssl=None):
		"""Address should look like: ('ad.yumaed.org',389)
		if SSL = True, then start an SSL connection. otherwise regular.
		Or if port is 636, then auto-start SSL connection.
		"""
		if address[1] == 636:
			ssl = True
		self.socket.connect(address)
		if ssl:
			#print 'adding SSL to the connection'
			self.ssl = socket.ssl(self.socket)
	def recv(self,options=None):
		if self.ssl:
			return self.ssl.read(options)
		else:
			return self.socket.recv(options)
	
	def send(self,data):
		if self.ssl:
			return self.ssl.write(data)
		else:
			return self.socket.send(data)
			
class ldap_command:
	def __init__(self):
		"""overloaded in inherited classes"""
		pass

	def encode(self):
		buffer=""
		for arg in self.myargs:
			cls,pc,no,data=arg
			buffer+=ber_encode(cls,pc,no,data)
		buffer=ber_encode(APPLICATION,CONSTRUCTED,self.app_code,buffer)
		messageid=get_sqn()
		buffer=ber_encode(UNIVERSAL,PRIMITIVE,INTEGER,messageid)+buffer
		buffer=ber_encode(UNIVERSAL,CONSTRUCTED,SEQUENCE,buffer)
		return buffer

	def decode(self,parent=1,cls=None,pc=None,buffer=None,remainder=None,no=None):
		self.keyvals={}
		if parent:
			cls,pc,no,self.messageid,remainder=ber_decode(self.buffer)
			cls,pc,self.app_code,buffer,remainder=ber_decode(remainder)
			self.args=[]
		while 1:
			if pc == PRIMITIVE and not(len(remainder)):
				return
			if pc == PRIMITIVE:
				cls,pc,no,buffer,remainder=ber_decode(remainder)
				if pc==PRIMITIVE: self.args.append((cls,pc,no,buffer))
				#self.args.append((cls,pc,no,buffer))
			else:
				if no==SEQUENCE:
					
					res=self.decode_sequence(buffer)
					self.args.append((cls,pc,no,res))
					if len(remainder):
						c,p,n,b,r=ber_decode(remainder)
						if p==PRIMITIVE: self.args.append((c,p,n,b))
						self.decode(parent=0,cls=c,no=n,pc=p,buffer=b,remainder=r)
					return	  
				cls,pc,no,buffer,remainder=ber_decode(buffer)
				if pc==PRIMITIVE:
					self.args.append((cls,pc,no,buffer))
				if len(remainder):
					c,p,n,b,r=ber_decode(remainder)
					if p==PRIMITIVE: self.args.append((c,p,n,b))
					self.decode(parent=0,cls=c,no=n,pc=p,buffer=b,remainder=r)
				
				#self.args.append((cls,pc,no,buffer))

	def decode_sequence(self,buff):
		r2=buff
		while len(r2):
			cls,pc,no,r1,r2=ber_decode(r2)
			while len(r1):
				cls,pc,no,key,r1=ber_decode(r1)
				if not len(r1):
					break
				cls,pc,no,buff,remainder=ber_decode(r1)
				cls,pc,no,buff,remainder=ber_decode(buff)
				self.keyvals[key]=[buff]
				while len(remainder):
					cls,pc,no,buff,remainder=ber_decode(remainder)
					self.keyvals[key].append(buff)

class bind(ldap_command):
	app_code=BIND
	def __init__(self, username, password,version=LDAPVERSION2):
		self.myargs=[]
		self.myargs.append((UNIVERSAL,PRIMITIVE,INTEGER,chr(version)))
		self.myargs.append((UNIVERSAL,PRIMITIVE,OCTETSTRING,username))
		self.myargs.append((CONTEXT,PRIMITIVE,0x00,password))


class bindresp(ldap_command):
	def __init__(self,buffer):
		self.buffer=buffer
		self.decode()
		if self.app_code!=BINDRESP:
			raise Exception('BUFFER_MISMATCH',"%s!=%s"%(self.app_code,BINDRESP))
		self.resultcode=ord(self.args[0][3])
		self.matcheddn=self.args[1][3]
		self.errorMessage=self.args[2][3]

class unbind(ldap_command):
	app_code=UNBIND
	def __init__(self):
		self.myargs=[]
		"""there are no arguments"""
		return
	
class search(ldap_command):
	app_code=SEARCHREQ
	def __init__(self,filter,base="o=solution.cmg.nl",scope='\x02',derefaliases='\x00',sizelimit='\x00',timelimit='\x03',typesonly='\x00',attribs=[]):
		self.myargs=[]
		self.myargs.append((UNIVERSAL,PRIMITIVE,OCTETSTRING,base))
		self.myargs.append((UNIVERSAL,PRIMITIVE,ENUMERATED,scope))
		self.myargs.append((UNIVERSAL,PRIMITIVE,ENUMERATED,derefaliases))
		self.myargs.append((UNIVERSAL,PRIMITIVE,INTEGER,sizelimit))
		self.myargs.append((UNIVERSAL,PRIMITIVE,INTEGER,timelimit))
		self.myargs.append((UNIVERSAL,PRIMITIVE,BOOLEAN,typesonly))
		if "=" in filter:
			f1,f2=filter.split("=")
			ctx=EQUALITYMATCH
		if ">" in filter:
			f1,f2=filter.split(">")
			ctx=GREATEROREQUAL
		if "<" in filter:
			f1,f2=filter.split("<")
			ctx=LESSOREQUAL
		#have no time to worry about nessted filters 
		#project requires it works
		filterbuff=ber_encode(UNIVERSAL,PRIMITIVE,OCTETSTRING,f1)
		filterbuff+=ber_encode(UNIVERSAL,PRIMITIVE,OCTETSTRING,f2)
		filterbuff=ber_encode(CONTEXT,CONSTRUCTED,ctx,filterbuff)
		self.myargs.append((CONTEXT,CONSTRUCTED,EOC,filterbuff))
		attribbuff=''
		for attrib in attribs:
			attribbuff+=ber_encode(UNIVERSAL,PRIMITIVE,OCTETSTRING,attrib)
		self.myargs.append((UNIVERSAL,CONSTRUCTED,SEQUENCE,attribbuff))

class searchresentry(ldap_command):
	def __init__(self,buffer):
		self.myargs=[]
		self.buffer=buffer
		self.decode()
		if self.app_code==SEARCHRESDONE:
			self.resultcode=self.args[0][3]
			self.matcheddn=self.args[1][3]
			self.errorMessage=self.args[2][3]
		else:
			return

class modify(ldap_command):
	app_code=MODIFYREQUEST
	def __init__(self,dn,commands):#commands=[[operation,type,[vals]],[operation,type,[vals]]]	
		self.myargs=[]
		self.myargs.append((UNIVERSAL,PRIMITIVE,OCTETSTRING,dn))
		attribbuffer=""
		itembuff=""
		for i in commands:
			op,type,vals=i
			op = modifyops[op]
			minibuff=""
			type=ber_encode(UNIVERSAL,PRIMITIVE,OCTETSTRING,type)
			op=ber_encode(UNIVERSAL,PRIMITIVE,ENUMERATED,chr(op))
			valbuff=""
			for val in vals:
				valbuff+=ber_encode(UNIVERSAL,PRIMITIVE,OCTETSTRING,val)
			valbuff=type+ber_encode(UNIVERSAL,CONSTRUCTED,SET,valbuff)
			valbuff=op+ber_encode(UNIVERSAL,CONSTRUCTED,SEQUENCE,valbuff)
			itembuff+=ber_encode(UNIVERSAL,CONSTRUCTED,SEQUENCE,valbuff)
		self.myargs.append((UNIVERSAL,CONSTRUCTED,SEQUENCE,itembuff))

class modify_resp(ldap_command):
	def __init__(self,buffer):
		self.myargs=[]
		self.buffer=buffer
		self.decode()
		if self.app_code!=MODIFYRESP:
			raise Exception('BUFFER_MISMATCH',"%s!=%s"%(self.app_code,MODIFYRESP))
		self.resultcode=self.args[0][3]
		self.matcheddn=self.args[1][3]
		self.errorMessage=self.args[2][3]

class add_entry(ldap_command):
	app_code=ADDREQUEST
	def __init__(self,dn,attribs={}):
		self.myargs=[]
		self.myargs.append((UNIVERSAL,PRIMITIVE,OCTETSTRING,dn))
		attribbuffer=""
		keys=attribs.keys()
		
		for key in keys:
			itemvalbuff=ber_encode(UNIVERSAL,PRIMITIVE,OCTETSTRING,key)
			valbuff=""
			for val in attribs[key]:
				valbuff+=ber_encode(UNIVERSAL,PRIMITIVE,OCTETSTRING,val)
			itemvalbuff+=ber_encode(UNIVERSAL,CONSTRUCTED,SET,valbuff)
			attribbuffer+=ber_encode(UNIVERSAL,CONSTRUCTED,SEQUENCE,itemvalbuff)
		self.myargs.append((UNIVERSAL,CONSTRUCTED,SEQUENCE,attribbuffer))
		
class add_resp(ldap_command):
	def __init__(self,buffer):
		self.myargs=[]
		self.buffer=buffer
		self.decode()
		if self.app_code!=ADDRESP:
			raise Exception('BUFFER_MISMATCH',"%s!=%s"%(self.app_code,ADDRESP))
		self.resultcode=self.args[0][3]
		self.matcheddn=self.args[1][3]
		self.errorMessage=self.args[2][3]


class del_entry(ldap_command):
	app_code=DEL
	def __init__(self,dn):
		self.myargs=[]
		self.dn=dn
		self.myargs.append((UNIVERSAL,PRIMITIVE,OCTETSTRING,dn))

	def encode(self):
		buffer=ber_encode(APPLICATION,PRIMITIVE,self.app_code,self.dn)
		messageid=get_sqn()
		buffer=ber_encode(UNIVERSAL,PRIMITIVE,INTEGER,messageid)+buffer
		buffer=ber_encode(UNIVERSAL,CONSTRUCTED,SEQUENCE,buffer)
		return buffer

class del_resp(ldap_command):
	def __init__(self,buffer):
		self.myargs=[]
		self.buffer=buffer
		self.decode()
		if self.app_code!=DELRESP:
			raise Exception('BUFFER_MISMATCH',"%s!=%s"%(self.app_code,DELRESP))
		self.resultcode=self.args[0][3]
		self.matcheddn=self.args[1][3]
		self.errorMessage=self.args[2][3]

class modifyrdn(ldap_command):
	app_code=MODIFYRDN

class compare(ldap_command):
	app_code=COMPARE

class abandon(ldap_command):
	app_code=ABANDON


sqn=0

def get_sqn():
	global sqn
	sqn+=1
	if sqn>255:
		sqn=1
	return chr(sqn)

def ber_encode(cls,pc,no,data):
	encoded_data=chr(cls+pc+no)
	if len(data)<0x80:
		encoded_data+=chr(len(data))
	else:
		length=struct.pack(">Q", len(data)).replace("\x00","")
		encoded_data+=chr(0x80+len(length))+length		  
	encoded_data+=data
	return encoded_data

def ber_decode(buffer):
	res=[]
	header=ord(buffer[0])
	if header < 64:
		cl=UNIVERSAL
	elif header < 128:
		cl=APPLICATION
		header=header-64
	elif header < 192:
		cl=CONTEXT
		header=header-128
	else:
		cl=PRIVATE
		header=header-192
	if header < 32:
		pr=0
	else:
		pr=1
		header=header-32
	num=header
	length=ord(buffer[1])
	buffer=buffer[2:]
	if length > 127:
		noofbytes=length-128
		bytes=buffer[:noofbytes]
		buffer=buffer[noofbytes:]
		length=0
		counter=1
		while len(bytes):
			length+=(ord(bytes[-1])*counter)
			counter=counter*0x100
			bytes=bytes[:-1]
	unusedbuffer=buffer[length:]
	buffer=buffer[:length]
	return (cl,pr,num,buffer,unusedbuffer)

BER_ERROR=""

class ldap_connection:
	def __init__(self,address):
		self.address=address
		self.conn=sock()
		self.conn.connect(address)
		#self.conn=socket.ssl(conn)
		
	def get_buff(self):
		header=self.conn.recv(2)
		if ord(header[0])!=UNIVERSAL+CONSTRUCTED+SEQUENCE:
			raise BER_ERROR
		length=ord(header[1])
		if length>0x79:
			bytes=self.conn.recv(length-0x80)
			length=0
			counter=1
			while len(bytes):
				length+=(ord(bytes[-1])*counter)
				counter=counter*0x100
				bytes=bytes[:-1]
		buffer=""
		while len(buffer)<length:
			buffer+=self.conn.recv(length-len(buffer))
		return buffer 

	def bind(self,username,password):
		"""do an ldap bind to the server"""
		data=bind(username,password)
		self.conn.send(data.encode())
		buffer=self.get_buff()
		resp=bindresp(buffer)

	def unbind(self):
		"""close the connection"""
		data=unbind()
		self.conn.send(data.encode())

	def abandon(self):
		"""do an abandon to the server"""
		data=abandon()
		self.conn.send(data.encode)

	def search(self,filter,base="o=solution.cmg.nl",attributes=[]):
		data=search(filter,base,attribs=attributes)
		self.conn.send(data.encode())
		res=[]
		while 1:
			buffer=self.get_buff()
			resp=searchresentry(buffer)
			res.append(resp)
			if resp.app_code==SEARCHRESDONE:
				break
		return res

	def compare_entry(self):
		return

	def add_entry(self,dn,attribs):
		data=add_entry(dn,attribs)
		self.conn.send(data.encode())
		buffer=self.get_buff()
		return add_resp(buffer)
		 
	def delete_entry(self,dn):
		data=del_entry(dn)
		self.conn.send(data.encode())
		buffer=self.get_buff()
		return del_resp(buffer)

	def modify(self,dn,commands):
		"""Modify takes 2 arguments, the first is a DN string.
		the second is a [].
			the first item is an operation (add,delete,replace)
			second item is the 'type' (i.e. cn, or whatever you want to change)
			the 3rd item is a list of values: ['John Smith','Tito Jones]
		returns a Modify Result Object: ['__doc__', '__init__', '__module__', 'app_code', 'args', 'buffer', 'decode', 'decode_sequence', 'encode', 'errorMessage', 'keyvals', 'matcheddn', 'messageid', 'myargs', 'resultcode']
		"""

		data=modify(dn=dn,commands=commands)
		self.conn.send(data.encode())
		buffer=self.get_buff()
		return modify_resp(buffer)
	
