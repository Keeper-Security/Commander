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

"""Commander Plugin for Oracle Database Server
   Dependencies: 
       pip3 install cx_Oracle
"""

def rotate(record, newpassword):
    """ Grab any required fields from the record """
    user = record.login
    oldpassword = record.password

    result = False

    host = record.get('cmdr:host')
    db = record.get('cmdr:db')

    connection = ''

    try:
        # Connect to the database
        connection = cx_Oracle.connect(dsn=host + '/' + db,
                                     user=user,
                                     password=oldpassword)

        with connection.cursor() as cursor:
            print("Connected to %s"%(host))
            # Create a new record
            sql = 'ALTER USER %s IDENTIFIED BY "%s" ACCOUNT UNLOCK'%(user, newpassword)
            cursor.execute(sql)

        result = True
    except:
        print("Error during connection to Oracle server")
    finally:
        if connection:
            connection.close()

    return result 