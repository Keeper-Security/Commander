#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ..importer import BaseImporter, Record, Folder, RecordField
import calendar
import getpass

from lastpass.vault import Vault
from lastpass.account import Account


class LastPassImporter(BaseImporter):

    def __init__(self):
        self.months = {}
        for i in range(len(calendar.month_name)):
            name = calendar.month_name[i]
            if name:
                self.months[name] = i

    def card_expiration(self, from_lastpass):   # type: (str) -> str
        if from_lastpass:
            comp = from_lastpass.split(',')
            if len(comp) == 2:
                if comp[0] in self.months:
                    return f'{self.months[comp[0]]:0>2}/{comp[1]}'
        return from_lastpass

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
                if record.login_url == 'http://sn':
                    record.login_url = None
            if account.notes:
                notes = account.notes.decode('utf-8')
                if notes:
                    typed_values = {}
                    typed = notes.split('\n')
                    if len(typed) > 1:
                        for pair in typed:
                            pos = pair.find(':')
                            if pos > 0:
                                typed_values[pair[:pos].strip()] = pair[pos+1:].strip()
                    if 'NoteType' in typed_values:
                        notes = typed_values.get('Notes')
                        note_type = typed_values['NoteType']
                        if note_type == 'Bank Account':
                            record.type = 'bankAccount'
                            bank = RecordField()
                            bank.type = 'bankAccount'
                            bank.value = {
                                'accountType': typed_values.get('Account Type') or '',
                                'routingNumber': typed_values.get('Routing Number') or '',
                                'accountNumber': typed_values.get('Account Number') or '',
                            }
                            record.fields.append(bank)
                            name = RecordField()
                            name.type = 'name'
                            name.value = typed_values.get('Bank Name') or '',
                            record.fields.append(name)

                        elif note_type == 'Credit Card':
                            record.type = 'bankCard'
                            card = RecordField()
                            card.type = 'paymentCard'
                            card.value = {
                                'cardNumber': typed_values.get('Number') or '',
                                'cardExpirationDate': self.card_expiration(typed_values.get('Expiration Date') or ''),
                                'cardSecurityCode': typed_values.get('Security Code') or ''
                            }
                            record.fields.append(card)
                            card_holder = RecordField()
                            card_holder.type = 'text'
                            card_holder.label = 'cardholderName'
                            card_holder.value = typed_values.get('Name on Card') or ''
                            record.fields.append(card_holder)
                        elif note_type == 'Address':
                            record.type = 'address'
                            address = RecordField()
                            address.type = 'address'
                            address.value = {
                                'street1': typed_values.get('Address 1') or '',
                                'street2': typed_values.get('Address 2') or '',
                                'city': typed_values.get('City / Town') or '',
                                'state': typed_values.get('State') or '',
                                'zip': typed_values.get('Zip / Postal Code') or '',
                                'country': typed_values.get('Country') or '',
                            }
                            record.fields.append(address)

                    record.notes = notes
            if account.group:
                fol = Folder()
                fol.path = account.group.decode('utf-8')
                record.folders = [fol]

            yield record
