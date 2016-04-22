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

import pymysql.cursors

"""Commander Plugin for MySQL Database Server
   Dependencies: 
       pip3 install pymysql
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
        connection = pymysql.connect(host=host,
                                     user=user,
                                     password=oldpassword,
                                     db=db,
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)

        with connection.cursor() as cursor:
            print("Connected to %s"%(host))
            # Create a new record
            sql = 'SET PASSWORD FOR "%s"@"%s"=PASSWORD("%s");'%(user, host, newpassword)
            cursor.execute(sql)

        # connection is not autocommit by default. So you must commit to save
        # your changes.
        connection.commit()

        record.password = newpassword
        result = True
    except:
        print("Error during connection to MySQL server")
    finally:
        if connection:
            connection.close()

    return result 