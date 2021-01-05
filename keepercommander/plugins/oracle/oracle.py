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

import cx_Oracle

# cx_Oracle.init_oracle_client(lib_dir="/Users/[username]]/Downloads/instantclient_19_8") # To initialize

"""Commander Plugin for Oracle Database Server
   Dependencies: 
       pip3 install cx_Oracle
"""

def rotate(record, newpassword):
    """ Grab any required fields from the record """
    user = record.login
    oldpassword = record.password

    result = False

    host = ""

    if record.get('cmdr:dsn'):
        dsn_str = record.get('cmdr:dsn')
    else:
        host = record.get('cmdr:host')
        db = record.get('cmdr:db')
        dsn_str = host + '/' + db

    connection = ''

    try:
        # Connect to the database
        connection = cx_Oracle.connect(dsn=dsn_str,
                                     user=user,
                                     password=oldpassword)

        with connection.cursor() as cursor:
            print("Connected to %s" % (dsn_str if record.get('cmdr:dsn') else host))
            # Create a new record
            sql = 'ALTER USER %s IDENTIFIED BY "%s" ACCOUNT UNLOCK' % (user, newpassword)
            cursor.execute(sql)

        record.password = newpassword
        result = True
    except Exception as e:
        print("Error during connection to Oracle server: %s", e)
    finally:
        if connection:
            connection.close()

    return result