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

import pymysql
import logging

"""Commander Plugin for MySQL Database Server
   Dependencies: 
       pip3 install pymysql
"""


class Rotator:
    def __init__(self, host, login, password, port=3306, user_host='%', **kwargs):
        self.host = host
        self.login = login
        self.password = password
        self.port = port
        self.user_host = user_host

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        logging.info(
            f'Rotating with MySQL plugin on host "{self.host}" and port "{self.port}"'
            f' for user "{self.login}"@"{self.user_host}"...'
        )

    def revert(self, record, new_password):
        """Revert rotation of a MySQL password"""
        self.rotate(record, new_password, revert=True)

    def rotate(self, record, new_password, revert=False):
        """Rotate a MySQL password"""
        if revert:
            old_password = new_password
            new_password = self.password
        else:
            old_password = self.password

        try:
            with pymysql.connect(host=self.host, port=self.port, user=self.login,
                                 password=old_password).cursor() as cursor:
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

                escape_new_password = pymysql.converters.escape_string(new_password)
                if is_old_version:
                    sql = f"set password for '{self.login}'@'{self.user_host}' = password('{escape_new_password}')"
                else:
                    sql = f"alter user '{self.login}'@'{self.user_host}' identified by '{escape_new_password}'"
                cursor.execute(sql)
                return True
        except pymysql.err.OperationalError as e:
            logging.error("MySQL Plugin Error: Unable to establish connection: %s", e)
        except pymysql.err.ProgrammingError as e:
            logging.error("MySQL Plugin Syntax Error: %s", e)
        except Exception as e:
            logging.error("MySQL password rotation error: %s", e)

        return False
