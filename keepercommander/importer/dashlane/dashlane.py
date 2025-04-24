#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import csv
import os
import zipfile
from typing import Union, Iterable

from .. import importer
from ... import vault


class DashlaneImporter(importer.BaseFileImporter):
    def do_import(self, filename, **kwargs):
        # type: (str, dict) -> Iterable[Union[importer.Record, importer.SharedFolder, importer.File]]
        
        # Handle zip file containing multiple CSV files
        if filename.endswith('.zip'):
            with zipfile.ZipFile(filename, 'r') as zf:
                # Extract files to temporary directory
                temp_dir = kwargs.get('tmpdir') or os.path.dirname(filename)
                zf.extractall(temp_dir)
                
                # Check for files in root or in dashlane-credential-export subdirectory
                base_dirs = ['', 'dashlane-credential-export']
                
                # Process each CSV file
                for csv_file in ['credentials.csv', 'securenotes.csv', 'payments.csv', 'ids.csv', 'personalinfo.csv']:
                    for base_dir in base_dirs:
                        csv_path = os.path.join(temp_dir, base_dir, csv_file)
                        if os.path.exists(csv_path):
                            yield from self._process_csv_file(csv_path, csv_file)
                            break  # Found the file, no need to check other directories
        else:
            # Handle individual CSV file
            yield from self._process_csv_file(filename, os.path.basename(filename))

    def _process_csv_file(self, filename, file_type):
        with open(filename, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            if file_type == 'credentials.csv':
                yield from self._process_credentials(reader)
            elif file_type == 'securenotes.csv':
                yield from self._process_secure_notes(reader)
            elif file_type == 'payments.csv':
                yield from self._process_payments(reader)
            elif file_type == 'ids.csv':
                yield from self._process_ids(reader)
            elif file_type == 'personalinfo.csv':
                yield from self._process_personal_info(reader)

    def _process_credentials(self, reader):
        for row in reader:
            record = importer.Record()
            record.type = 'login'
            record.title = row.get('title', '').strip()
            record.login = row.get('username', '').strip()
            record.password = row.get('password', '').strip()
            record.login_url = row.get('url', '').strip()
            record.notes = row.get('note', '').strip()
            
            # Handle 2FA
            otp_url = row.get('otpUrl', '').strip()
            if otp_url:
                record.fields.append(importer.RecordField('oneTimeCode', '', otp_url))
            
            # Handle additional usernames
            for i in range(2, 4):  # username2 and username3
                username = row.get(f'username{i}', '').strip()
                if username:
                    record.fields.append(importer.RecordField('text', f'username{i}', username))
            
            yield record

    def _process_secure_notes(self, reader):
        for row in reader:
            record = importer.Record()
            record.type = 'encryptedNotes'
            record.title = row.get('title', '').strip()
            record.notes = row.get('note', '').strip()
            
            # Add category as a custom field
            category = row.get('category', '').strip()
            if category:
                record.fields.append(importer.RecordField('text', 'category', category))
            
            yield record

    def _process_payments(self, reader):
        for row in reader:
            record = importer.Record()
            record_type = row.get('type', '').strip().lower()
            
            if record_type == 'payment_card':
                record.type = 'bankCard'
                card = {
                    'cardNumber': row.get('cc_number', '').strip(),
                    'cardExpirationDate': f"{row.get('expiration_month', '').strip()}/{row.get('expiration_year', '').strip()}",
                    'cardSecurityCode': row.get('code', '').strip()
                }
                record.fields.append(importer.RecordField('paymentCard', '', card))
                record.title = row.get('name', '').strip()
            elif record_type == 'bank_account':
                record.type = 'bankAccount'
                account = {
                    'accountNumber': row.get('account_number', '').strip(),
                    'routingNumber': row.get('routing_number', '').strip()
                }
                record.fields.append(importer.RecordField('bankAccount', '', account))
                record.title = row.get('account_name', '').strip()
            
            # Add common fields
            if row.get('account_holder'):
                record.fields.append(importer.RecordField('text', 'accountHolder', row['account_holder']))
            if row.get('issuing_bank'):
                record.fields.append(importer.RecordField('text', 'issuingBank', row['issuing_bank']))
            if row.get('note'):
                record.notes = row['note']
            
            yield record

    def _process_ids(self, reader):
        for row in reader:
            record = importer.Record()
            record_type = row.get('type', '').strip().lower()
            
            if record_type == 'license':
                record.type = 'driverLicense'
                record.title = f"Driver's License - {row.get('name', '').strip()}"
            elif record_type == 'passport':
                record.type = 'passport'
                record.title = f"Passport - {row.get('name', '').strip()}"
            else:
                # For card, social_security, tax_number - use encryptedNotes since there's no direct match
                record.type = 'encryptedNotes'
                record.title = f"{record_type.title()} - {row.get('name', '').strip()}"
            
            # Add common fields
            if row.get('number'):
                record.fields.append(importer.RecordField('text', 'number', row['number']))
            if row.get('issue_date'):
                record.fields.append(importer.RecordField('date', 'issueDate', row['issue_date']))
            if row.get('expiration_date'):
                record.fields.append(importer.RecordField('date', 'expirationDate', row['expiration_date']))
            if row.get('place_of_issue'):
                record.fields.append(importer.RecordField('text', 'placeOfIssue', row['place_of_issue']))
            if row.get('state'):
                record.fields.append(importer.RecordField('text', 'state', row['state']))
            
            yield record

    def _process_personal_info(self, reader):
        # Group contact information by person (using login as identifier)
        contact_records = {}
        address_records = []
        
        for row in reader:
            record_type = row.get('type', '').strip().lower()
            
            if record_type == 'name':
                # Create or update contact record
                login = row.get('login', '').strip()
                if not login:
                    continue
                    
                if login not in contact_records:
                    contact_records[login] = {
                        'type': 'contact',  # Keeper's contact record type
                        'title': '',
                        'fields': [],
                        'notes': ''
                    }
                
                record = contact_records[login]
                first_name = row.get('first_name', '').strip()
                last_name = row.get('last_name', '').strip()
                record['title'] = f"{first_name} {last_name}".strip() or f"Contact - {login}"
                
                name = {
                    'first': first_name,
                    'middle': row.get('middle_name', ''),
                    'last': last_name
                }
                record['fields'].append(importer.RecordField('name', '', name))
                
                # Add date of birth if available
                dob = row.get('date_of_birth', '').strip()
                if dob:
                    record['fields'].append(importer.RecordField('date', 'birthDate', dob))
                
                # Add place of birth if available
                pob = row.get('place_of_birth', '').strip()
                if pob:
                    record['fields'].append(importer.RecordField('text', 'placeOfBirth', pob))
                
                # Add job title if available
                job = row.get('job_title', '').strip()
                if job:
                    record['fields'].append(importer.RecordField('text', 'jobTitle', job))
                
                # Add URL if available
                url = row.get('url', '').strip()
                if url:
                    record['fields'].append(importer.RecordField('url', '', url))
            
            elif record_type == 'email':
                # Add email to contact record
                login = row.get('login', '').strip()
                if login in contact_records:
                    email = row.get('email', '').strip()
                    if email:
                        contact_records[login]['fields'].append(importer.RecordField('email', '', email))
            
            elif record_type == 'phone':
                # Add phone to contact record
                login = row.get('login', '').strip()
                if login in contact_records:
                    phone = row.get('phone_number', '').strip()
                    if phone:
                        contact_records[login]['fields'].append(importer.RecordField('phone', '', phone))
            
            elif record_type == 'address':
                # Create a separate address record
                address_record = {
                    'type': 'address',  # Keeper's address record type
                    'title': '',
                    'fields': [],
                    'notes': ''
                }
                
                # Set title
                item_name = row.get('item_name', '').strip()
                address_record['title'] = f"Address - {item_name}" if item_name else "Address"
                
                # Add address fields
                address = {
                    'street1': row.get('address', ''),
                    'street2': row.get('address_apartment', ''),
                    'city': row.get('city', ''),
                    'state': row.get('state', ''),
                    'zip': row.get('zip', ''),
                    'country': row.get('country', '')
                }
                address_record['fields'].append(importer.RecordField('address', '', address))
                
                # Add recipient if available
                recipient = row.get('address_recipient', '').strip()
                if recipient:
                    address_record['fields'].append(importer.RecordField('text', 'recipient', recipient))
                
                address_records.append(address_record)
        
        # Yield contact records
        for login, data in contact_records.items():
            record = importer.Record()
            record.type = data['type']
            record.title = data['title']
            record.fields = data['fields']
            record.notes = data['notes']
            yield record
        
        # Yield address records
        for data in address_records:
            record = importer.Record()
            record.type = data['type']
            record.title = data['title']
            record.fields = data['fields']
            record.notes = data['notes']
            yield record

    def extension(self):
        return 'zip' 