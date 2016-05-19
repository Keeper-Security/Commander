# -*- coding: utf-8 -*-
#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2016 Keeper Security Inc.
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
            escaped = connection.escape(newpassword)
            """ TBD - For MySQL 5.7+ use below command:
                sql = 'ALTER USER "{}"@"{}" IDENTIFIED BY "{}";'.format(
                    user, host, newpassword)
            """
            sql = 'SET PASSWORD = PASSWORD({});'.format(escaped)
            cursor.execute(sql)

        connection.commit()
        record.password = newpassword
        result = True
    except pymysql.err.OperationalError as e:
        print("MySQL Plugin Error: Unable to establish connection: " + str(e))
    except pymysql.err.ProgrammingError as e:
        print("MySQL Plugin Syntax Error: " + str(e))
    except:
        print("Error during connection to MySQL server")
    finally:
        if connection:
            connection.close()

    return result 
