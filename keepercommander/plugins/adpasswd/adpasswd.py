# -*- coding: utf-8 -*-
#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
from ldap3 import Server, Connection, ALL

from keepercommander.plugins.commands import get_v2_or_v3_custom_field_value


"""Commander Plugin for Active Directory
   Dependencies: 
       pip3 install ldap3
"""

def rotate(record, newpassword):
    result = False

    old_password = record.password
    host = get_v2_or_v3_custom_field_value(record, 'cmdr:host')
    port = get_v2_or_v3_custom_field_value(record, 'cmdr:port')
    port = int(port) if port else None
    user_dn = get_v2_or_v3_custom_field_value(record, 'cmdr:userdn')
    use_ssl = get_v2_or_v3_custom_field_value(record, 'cmdr:use_ssl')

    try:
        # print('Connecting to ' + host)

        server = Server(
            host=host,
            port=port,
            use_ssl=(use_ssl in ['True','true','yes','Yes','y','Y','T','t']),
            get_info=ALL)

        conn = Connection(
            server=server,
            user=user_dn,
            password=record.password,
            auto_bind=True)

        print('Connection: ' + str(conn))
        print('Server Info: ' + str(server.info))
        print('Whoami: ' + str(conn.extend.standard.who_am_i()))

        changePwdResult = conn.extend.microsoft.modify_password(
            user=user_dn, new_password=newpassword, old_password=old_password)

        if (changePwdResult == True):
            print('Password changed successfully')
            record.password = newpassword
            result = True
        else:
            print('Error with adpasswd change: ' + str(conn.result))

        conn.unbind()

    except Exception as e:
        print("Error during connection to AD server: %s" % str(e))

    return result
