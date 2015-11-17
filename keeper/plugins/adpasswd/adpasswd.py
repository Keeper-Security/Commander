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

from ldap3 import Server, Connection, ALL, MODIFY_REPLACE

"""Commander Plugin for Active Directory
   Dependencies: 
       pip3 install ldap3
"""

def rotate(record, newpassword):
    """ Grab any required fields from the record """
    user = record.login
    oldpassword = record.password

    result = False

    host = record.get('cmdr:host')
    searchdn = record.get('cmdr:searchdn')

    try:

        server = Server(host, use_ssl=True, get_info=ALL)
        dn = 'uid=%s, cn=users, cn=accounts, %s'%(user, searchdn)
        conn = Connection(server, dn, oldpassword, auto_bind=True)

        conn.modify(dn, {'password': [(MODIFY_REPLACE, newpassword)]})

        if (conn.result['result'] == 0):
            return True
        else:
            print("Server returned this message: %s"%(conn.result['message']))

        conn.unbind()
    except:
        print("Error during connection to AD server")

    return result 
