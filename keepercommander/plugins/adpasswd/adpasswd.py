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
import json
import ldap3
import logging
import ssl

from ...vault import KeeperRecord
from ...commands.base import RecordMixin

"""Commander Plugin for Active Directory
   Dependencies: 
       pip install ldap3
"""

PasswordChangeHeader = 'Unable to update the password.'

DomainConstraintViolation = 'The value provided for the new password does not meet ' +\
                            'the length, complexity, or history requirements for the domain.'


def rotate(record, new_password):   # type: (KeeperRecord, str) -> bool
    old_password = RecordMixin.get_record_field(record, 'password')
    if not old_password:
        raise ValueError(f'Rotate AD password: Current password is not set.')

    host = RecordMixin.get_record_field(record, 'host')
    if host:
        host, _, port = host.partition(':')
    else:
        port = ''
    if not port:
        port = RecordMixin.get_record_field(record, 'port')
    if port:
        port = int(port)
    else:
        port = None
    if not host:
        raise ValueError(f'Rotate AD password: Domain controller (\"host\") is not set.')

    user_dn = RecordMixin.get_record_field(record, 'cmdr:userdn')
    login = ''
    if not user_dn:
        login = RecordMixin.get_record_field(record, 'login')
        if login:
            if login.lower().startswith('CN='):
                user_dn = login
                login = ''

    if not login and not user_dn:
        raise ValueError(f'Rotate AD password: User login or DN is not set.')

    tls = ldap3.Tls(validate=ssl.CERT_NONE)
    server = ldap3.Server(host=host, port=port, use_ssl=True, tls=tls, connect_timeout=5, get_info=ldap3.ALL)
    with ldap3.Connection(server) as c:
        c.open()

    if user_dn:
        conn = ldap3.Connection(
            server, version=3, auto_bind=ldap3.AUTO_BIND_NONE, authentication=ldap3.SIMPLE,
            client_strategy=ldap3.SYNC, read_only=False, lazy=False,
            user=user_dn, password=old_password)
    else:
        conn = ldap3.Connection(
            server, version=3, auto_bind=ldap3.AUTO_BIND_NONE, authentication=ldap3.NTLM,
            client_strategy=ldap3.SYNC, read_only=False, lazy=False,
            user=login, password=old_password)

    if not conn.bind():
        raise ValueError(f'Rotate AD password: Bind error: {conn.result}')

    if not user_dn:
        domain, _, name = login.partition('\\')
        if not name:
            raise ValueError(f'Rotate AD password: Cannot get User DN')

        request = f'(&(objectClass=user)(sAMAccountName={name}))'
        conn.search(search_base=server.info.naming_contexts[0], search_filter=request,
                    attributes=['distinguishedName'], search_scope=ldap3.SUBTREE)
        if len(conn.entries) == 0:
            raise ValueError(f'Rotate AD password: Cannot get User DN')

        user_dn = conn.entries[0]['distinguishedName'].value

    change_result = conn.extend.microsoft.modify_password(
        user=user_dn, new_password=new_password, old_password=old_password)

    if not change_result:
        error_result = conn.result
        if isinstance(error_result, dict):
            if error_result.get('description', '') == 'constraintViolation':
                logging.info(f'{PasswordChangeHeader} {DomainConstraintViolation}')
            elif 'message' in error_result:
                logging.info(f'{PasswordChangeHeader}: %s', conn.result["message"])
            else:
                logging.info(f'{PasswordChangeHeader}: %s', json.dumps(conn.result))
        else:
            logging.info(f'{PasswordChangeHeader}: %s', str(conn.result))
    conn.unbind()

    return change_result
