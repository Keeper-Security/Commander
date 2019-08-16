#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ..importer import BaseImporter, Record, Folder

import getpass

from .vault import Vault
from .account import Account


class LastPassImporter(BaseImporter):

    def do_import(self, name):
        username = name
        password = getpass.getpass(prompt='...' + 'LastPass Password'.rjust(30) + ': ', stream=None)
        print('Press <Enter> if account is not protected with Multifactor Authentication')
        twofa_code = getpass.getpass(prompt='...' + 'Multifactor Password'.rjust(30) + ': ', stream=None)
        if not twofa_code:
            twofa_code = None

        vault = Vault.open_remote(username, password, multifactor_password=twofa_code)
        for account in vault.accounts:  # type: Account
            record = Record()
            if account.name:
                record.title = account.name.decode('utf-8')
            if account.username:
                record.login = account.username.decode('utf-8')
            if account.password:
                record.password = account.password.decode('utf-8')
            if account.url:
                record.login_url = account.url.decode('utf-8')
            if account.notes:
                record.notes = account.notes.decode('utf-8')
            if account.group:
                fol = Folder()
                fol.path = account.group.decode('utf-8')
                record.folders = [fol]

            yield record
