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

import psycopg2
import logging

"""Commander Plugin for Postgres Database Server
   Dependencies: 
       pip3 install psycopg2-binary
"""


class Rotator:
    def __init__(self, host, login, password, port=5432, db='postgres', **kwargs):
        self.host = host
        self.login = login
        self.password = password
        self.port = port
        self.db = db

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        logging.info(
            f'Rotating with PostgreSQL plugin on host "{self.host}" and port "{self.port}" using login "{self.login}"'
            f' to connect to db "{self.db}"...'
        )

    def revert(self, record, new_password):
        """Revert rotation of a PostgreSQL password"""
        self.rotate(record, new_password, revert=True)

    def rotate(self, record, new_password, revert=False):
        """Rotate a PostgreSQL password"""
        if revert:
            old_password = new_password
            new_password = self.password
        else:
            old_password = self.password

        try:
            with psycopg2.connect(host=self.host, port=self.port, user=self.login, password=old_password,
                                  database=self.db) as connection:
                logging.debug(f'Connected to {self.host}')
                with connection.cursor() as cursor:
                    sql = f'alter user {self.login} with password %s'
                    cursor.execute(sql, (new_password,))
                    return True
        except Exception as e:
            if revert:
                logging.error('Error reverting password rotation of Postgres server: %s', e)
            else:
                logging.error('Error rotating password of Postgres server: %s', e)

        return False
