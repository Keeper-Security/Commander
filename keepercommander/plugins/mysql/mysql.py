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

import pymysql
import logging

"""Commander Plugin for MySQL Database Server
   Dependencies: 
       pip3 install pymysql
"""


def rotate(record, newpassword):
    user = record.login
    oldpassword = record.password

    try:
        host = record.get('cmdr:host')
        port = record.get('cmdr:port') or '3306'
        user_host = record.get('cmdr:user_host') or '%'

        with pymysql.connect(host=host, port=int(port), user=user, password=oldpassword).cursor() as cursor:
            is_old_version = True
            affected = cursor.execute('select @@version')
            if affected == 1:
                rs = cursor.fetchone()
                version = rs[0]     # type: str
                vc = version.split('.')
                vn = 0
                if len(vc) == 3:
                    for n in vc:
                        vn *= 1000
                        vn += int(n)
                    is_old_version = vn < 5007006

            if is_old_version:
                sql = f'set password for \'{user}\'@\'{user_host}\' = password(\'{pymysql.escape_string(newpassword)}\')'
            else:
                sql = f'alter user \'{user}\'@\'{user_host}\' identified by \'{pymysql.escape_string(newpassword)}\''
            cursor.execute(sql)
            record.password = newpassword
            return True
    except pymysql.err.OperationalError as e:
        logging.error("MySQL Plugin Error: Unable to establish connection: %s", e)
    except pymysql.err.ProgrammingError as e:
        logging.error("MySQL Plugin Syntax Error: %s", e)
    except Exception as e:
        logging.error("MySQL password rotation error: %s", e)

    return False
