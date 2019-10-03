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


def rotate(record, newpassword):
    user = record.login
    oldpassword = record.password

    try:
        host = record.get('cmdr:host')
        db = record.get('cmdr:db') or 'postgres'
        port = record.get('cmdr:port') or '5432'

        with psycopg2.connect(host=host, port=int(port), user=user, password=oldpassword, database=db) as connection:
            logging.debug("Connected to %s", host)
            with connection.cursor() as cursor:
                sql = f'alter user {user} with password %s'
                cursor.execute(sql, (newpassword,))
                record.password = newpassword
                return True
    except Exception as e:
        logging.error('Error rotating password at Postgres server: %s', e)

    return False
