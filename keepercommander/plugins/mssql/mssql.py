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
import logging
import pymssql

"""Commander Plugin for Microsoft SQL Server
   Dependencies: 
       pip3 install pymssql
"""


class Rotator:
    def __init__(self, login, password, host=None, port=1433, db=None, **kwargs):
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.db = db

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        host_msg = 'on default host' if self.host is None else f'on host "{self.host}"'
        db_msg = '...' if self.db is None else f' to connect to db "{self.db}"...'
        logging.info(
            f'Rotating with Microsoft SQL plugin {host_msg} and port "{self.port}" using login "{self.login}"{db_msg}'
        )

    def revert(self, record, new_password):
        """Revert rotation of a Microsoft SQL password"""
        self.rotate(record, new_password, revert=True)

    def rotate(self, record, new_password, revert=False):
        """Rotate a Microsoft SQL password"""
        if revert:
            old_password = new_password
            new_password = self.password
        else:
            old_password = self.password

        user = self.login
        kwargs = {'user': user, 'password': old_password}
        if self.host:
            kwargs['server'] = self.host
        if self.db:
            kwargs['database'] = self.db

        connection = ''
        result = False
        try:
            connection = pymssql.connect(**kwargs)
            with connection.cursor() as cursor:
                host = 'default host' if self.host is None else f'"{self.host}"'
                logging.debug(f'Connected to {host}')
                sql = f"ALTER LOGIN {user} WITH PASSWORD = '{new_password}';"
                cursor.execute(sql)
            # connection is not autocommit by default. So you must commit to save your changes.
            connection.commit()
            result = True
        except Exception as e:
            logging.error(f'Error during connection to Microsoft SQL server: {e}')
        finally:
            if connection:
                connection.close()
        return result
