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

import pymssql

"""Commander Plugin for Microsoft SQL Server
   Dependencies: 
       pip3 install pymssql
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
        connection = pymssql.connect(host=host,
                                     user=user,
                                     password=oldpassword,
                                     db=db)

        with connection.cursor() as cursor:
            print("Connected to %s"%(host))
            # Create a new record
            sql = 'ALTER LOGIN %s WITH PASSWORD="%s";'%(user, newpassword)
            cursor.execute(sql)

        # connection is not autocommit by default. So you must commit to save
        # your changes.
        connection.commit()

        result = True
    except:
        print("Error during connection to Microsoft SQL server")
    finally:
        if connection:
            connection.close()

    return result 