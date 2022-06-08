# -*- coding: utf-8 -*-
#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
from ldap3 import Server, Connection, ALL


"""Commander Plugin for Active Directory
   Dependencies: 
       pip3 install ldap3
"""


class Rotator:
    def __init__(self, host, port, use_ssl, userdn, password, **kwargs):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.user_dn = userdn
        self.password = password

    def rotate(self, record, new_password):
        return rotate_adpasswd(self.host, self.port, self.use_ssl, self.user_dn, self.password, new_password)


def rotate_adpasswd(host, port, use_ssl, user_dn, old_password, new_password):
    result = False

    try:
        server = Server(
            host=host,
            port=port,
            use_ssl=(use_ssl in ['True','true','yes','Yes','y','Y','T','t']),
            get_info=ALL)

        conn = Connection(
            server=server,
            user=user_dn,
            password=old_password,
            auto_bind=True)

        print('Connection: ' + str(conn))
        print('Server Info: ' + str(server.info))
        print('Whoami: ' + str(conn.extend.standard.who_am_i()))

        result = conn.extend.microsoft.modify_password(
            user=user_dn, new_password=new_password, old_password=old_password)

        if result:
            print('Password changed successfully')
        else:
            print('Error with adpasswd change: ' + str(conn.result))

        conn.unbind()

    except Exception as e:
        print("Error during connection to AD server: %s" % str(e))

    return result
