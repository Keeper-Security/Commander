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
import oracledb

"""Commander Plugin for Oracle Database Server
   Dependencies: 
       pip3 install oracledb
"""


ORACLE_MAX_PASSWORD_LENGTH = 30


class Rotator:
    def __init__(self, login, password, host='localhost', port=None, db='', dsn=None, **kwargs):
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.db = db
        self.dsn = dsn

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        port_msg = '' if self.port is None else f' and on port "{self.port}"'
        db_msg = '...' if self.db is None else f' to connect to db "{self.db}"...'
        logging.info(
            f'Rotating with Oracle plugin on host "{self.host}"{port_msg} using login "{self.login}"{db_msg}'
        )

    @staticmethod
    def adjust(new_password):
        # Oracle password has a maximum length
        return new_password[:ORACLE_MAX_PASSWORD_LENGTH]

    def revert(self, record, new_password):
        """Revert rotation of an Oracle database password"""
        self.rotate(record, new_password, revert=True)

    def rotate(self, record, new_password, revert=False):
        """Rotate an Oracle database password"""
        if revert:
            old_password = new_password
            new_password = self.password
        else:
            old_password = self.password

        user = self.login
        dsn = f'{self.host}/{self.db}' if self.dsn is None else self.dsn
        kwargs = {'user': user, 'password': old_password, 'dsn': dsn}
        if self.port:
            kwargs['port'] = self.port

        connection = ''
        result = False
        try:
            connection = oracledb.connect(**kwargs)
            with connection.cursor() as cursor:
                logging.debug(f'Connected to {dsn}')
                sql = f'ALTER USER {user} IDENTIFIED BY "{new_password}" ACCOUNT UNLOCK'
                cursor.execute(sql)
            result = True
        except Exception as e:
            logging.error(f'Error during connection to Oracle server: {e}')
        finally:
            if connection:
                connection.close()
        return result
