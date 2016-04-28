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

from ldap3 import Server, Connection, ALL

"""Commander Plugin for Active Directory
   Dependencies: 
       pip3 install ldap3
"""


def rotate(record, newpassword):
    result = False

    host = record.get('cmdr:host')
    user_dn = record.get('cmdr:userdn')

    try:
        server = Server(
            host=host,
            use_ssl=True,
            get_info=ALL)

        conn = Connection(
            server=server,
            user=user_dn,
            password=record.password,
            auto_bind=True)

        changePwdResult = conn.extend.microsoft.modify_password(user_dn, newpassword)

        if (changePwdResult == True):
            print('Password changed successfully')
            record.password = newpassword
            result = True
        else:
            print("Server returned this message: %s" % (changePwdResult))

        conn.unbind()
    except:
        print("Error during connection to AD server")

    return result
