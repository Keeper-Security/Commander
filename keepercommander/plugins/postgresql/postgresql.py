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

    def rotate(self, record, new_password):
        """Change a password over SSH"""
        return rotate_postgresql(self.host, self.login, self.password, new_password, self.port, self.db)

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        logging.info(
            f'Rotating with PostgreSQL plugin on host "{self.host}" and port "{self.port}" using login "{self.login}"'
            f' to connect to db "{self.db}"...'
        )

    def revert(self, record, new_password):
        """Revert password change over SSH"""
        return rotate_postgresql(self.host, self.login, new_password, self.password, self.port, self.db, revert=True)


def rotate_postgresql(host, user, old_password, new_password, port=5432, db='postgres', revert=False):
    try:
        with psycopg2.connect(host=host, port=int(port), user=user, password=old_password, database=db) as connection:
            logging.debug("Connected to %s", host)
            with connection.cursor() as cursor:
                sql = f'alter user {user} with password %s'
                cursor.execute(sql, (new_password,))
                return True
    except Exception as e:
        logging.error('Error rotating password at Postgres server: %s', e)

    return False
