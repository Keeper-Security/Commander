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
import shutil
from configparser import RawConfigParser
from os.path import expandvars, expanduser, isfile

from botocore.exceptions import ClientError

from ..aws_common import AWSRotator, AWS_INVALID_CLIENT_MSG
from ..commands import update_custom_text_fields

"""Commander Plugin for Rotating AWS Access Keys
   Dependencies:
       pip3 install boto3
"""


AWS_SYNC_CREDENTIAL_METHOD = 'shared-credentials-file'
AWS_CREDS_FILE_KEY_ID_OPTION = 'aws_access_key_id'
AWS_CREDS_FILE_KEY_SECRET_OPTION = 'aws_secret_access_key'
AWS_CREDS_FILE_BACKUP_EXTENSION = '.keeper.bak'
AWS_NEW_KEY_ID_FIELD = 'cmdr:aws_key_id'
AWS_NEW_SECRET_FIELD = 'cmdr:aws_key_secret'
AWS_ASSUME_ROLE_FIELD = 'cmdr:aws_assume_role'


class Rotator(AWSRotator):
    def __init__(self, login, aws_key_id, aws_key_secret=None, aws_assume_role=None, aws_profile=None, aws_sync_profile=None, **kwargs):
        self.login = login
        self.aws_key_id = aws_key_id
        self.aws_key_secret = aws_key_secret
        self.aws_assume_role = aws_assume_role
        self.aws_sync_profile = aws_sync_profile
        super().__init__(aws_profile)

        self.new_key_id = None
        self.new_secret = None
        self.old_key_deleted = False

    def rotate_start_msg(self):
        """Display msg before starting rotation"""
        logging.info(
            f'Rotating AWS access key id "{self.aws_key_id}" for user "{self.login}"'
        )

    def revert(self, record, new_password):
        """Revert rotation of an AWS access key"""
        if self.old_key_deleted:
            if self.aws_sync_profile:
                if self.sync_with_creds_file():
                    logging.info(
                        f'New key id "{self.new_key_id}" was updated in profile "{self.aws_sync_profile}"'
                        ' of AWS credentials file, but failed to update in Keeper record.'
                    )
                else:
                    logging.info(
                        f'New key id {self.new_key_id} failed to update in profile "{self.aws_sync_profile}"'
                        ' of AWS credentials file, and also failed to update in Keeper record.'
                    )
            return False
        else:
            self.delete_key(new_key=True)

    def revert_failed_msg(self):
        # Printed failure messages in revert method
        pass

    def update_password(self, record, new_password):
        update_custom_text_fields(
            record, {AWS_NEW_KEY_ID_FIELD: self.new_key_id, AWS_NEW_SECRET_FIELD: self.new_secret}
        )

    def sync_password(self):
        if self.aws_sync_profile:
            if not self.sync_with_creds_file():
                logging.warning(f'Failed to update {self.aws_sync_profile} in AWS credentials file.')
        if not self.old_key_deleted:
            self.delete_key()

    def delete_key(self, new_key=False):
        if new_key:
            key_type = 'new'
            key_id = self.new_key_id
        else:
            key_type = 'old'
            key_id = self.aws_key_id
        try:
            self.iam.delete_access_key(UserName=self.login, AccessKeyId=key_id)
        except Exception as e:
            logging.error(f'Error deleting {key_type} key id "{key_id}" for user "{self.login}"')
            return False
        else:
            if not new_key:
                self.old_key_deleted = True
            logging.debug(f'Deleted {key_type} key id "{key_id}" for user "{self.login}"')
            return True

    def sync_with_creds_file(self):
        sync_profile = self.aws_sync_profile
        botocore_session = self.session._session
        credential_method = self.session.get_credentials().method
        if credential_method == AWS_SYNC_CREDENTIAL_METHOD:
            providers = botocore_session._components.get_component('credential_provider').providers
            credential_provider = next((p for p in providers if p.METHOD == credential_method), None)
            creds_filename = expanduser(expandvars(credential_provider._creds_filename))
            if not isfile(creds_filename):
                logging.warning(f'Unable to find credentials file "{creds_filename}" for syncing.')
                return False
            cp = RawConfigParser()
            try:
                cp.read([creds_filename])
            except Exception as e:
                logging.warning(f'Unable to parse credentials file "{creds_filename}" for syncing.')
                return False
            if not cp.has_section(sync_profile):
                cp.add_section(sync_profile)
            elif cp.has_option(sync_profile, AWS_CREDS_FILE_KEY_ID_OPTION):
                old_key_id_option = cp.get(sync_profile, AWS_CREDS_FILE_KEY_ID_OPTION)
                if old_key_id_option != self.aws_key_id:
                    logging.warning(
                        f'Another key id already exists for sync profile "{sync_profile}" in file "{creds_filename}".'
                    )
                    return False
            cp.set(sync_profile, AWS_CREDS_FILE_KEY_ID_OPTION, self.new_key_id)
            cp.set(sync_profile, AWS_CREDS_FILE_KEY_SECRET_OPTION, self.new_secret)
            backup_file = f'{creds_filename}{AWS_CREDS_FILE_BACKUP_EXTENSION}'
            shutil.copy2(creds_filename, backup_file)
            with open(creds_filename, 'w') as f:
                cp.write(f)
            logging.info(
                f'Synced AWS key rotation with AWS credential file "{creds_filename}"'
                f' and backed up original file to "{backup_file}"'
            )
            return True

    def rotate(self, record, new_password):
        """Rotate an AWS access key"""
        if not self.set_iam_session():
            return False

        if self.aws_assume_role:
            self.assume_role(self.aws_assume_role)

        self.iam = self.session.client('iam')

        try:
            list_response = self.iam.list_access_keys(UserName=self.login)
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'InvalidClientTokenId':
                logging.error(f'Unable to connect using {self.profile_msg}. {AWS_INVALID_CLIENT_MSG}')
                return False
            else:
                logging.error(f'Error listing existing AWS keys for user "{self.login}": {e}')
                return False
        except Exception as e:
            logging.error(f'Error listing existing AWS keys for user "{self.login}": {e}')
            return False
        if isinstance(list_response, dict) and isinstance(list_response.get('AccessKeyMetadata'), list):
            found_key_id = next(
                (m for m in list_response['AccessKeyMetadata'] if m.get('AccessKeyId') == self.aws_key_id), None
            )
            if found_key_id is None:
                logging.error(f'Unable to find AWS key id "{self.aws_key_id}" to rotate for user "{self.login}"')
                return False
        else:
            logging.error(f'Invalid response listing existing AWS keys for user "{self.login}": {list_response}')
            return False

        create_response = None
        # Try create_access_key again for LimitExceededException
        for i in range(2):
            try:
                create_response = self.iam.create_access_key(UserName=self.login)
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'LimitExceeded' and not self.old_key_deleted:
                    # Continue with loop and try again
                    pass
                else:
                    logging.error(f'Error creating new key for user "{self.login}": {e}')
                    return False
            except Exception as e:
                logging.error(f'Error creating new key for user "{self.login}": {e}')
                return False
            else:
                # Successfully created key so no further action necessary
                break
            # The maximum number of keys has already been created, have to delete first
            if not self.delete_key():
                return False

        if isinstance(create_response, dict) and isinstance(create_response.get('AccessKey'), dict):
            access_key = create_response['AccessKey']
            check_response = all(k in access_key for k in ('UserName', 'Status', 'AccessKeyId', 'SecretAccessKey'))
            if check_response and access_key['UserName'] == self.login and access_key['Status'] == 'Active':
                self.new_key_id = access_key['AccessKeyId']
                self.new_secret = access_key['SecretAccessKey']
                return True
            else:
                logging.error(f'Invalid response creating new key for {self.login}: {create_response}')
                return False
        else:
            logging.error(f'Invalid response creating new key for {self.login}: {create_response}')
            return False

