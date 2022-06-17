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

from botocore.exceptions import ClientError

from ..aws_common import AWSRotator, AWS_INVALID_CLIENT_MSG

"""Commander Plugin for Rotating AWS passwords
   Dependencies:
       pip3 install boto3
"""


class Rotator(AWSRotator):
    def __init__(self, login, password=None, aws_profile=None, **kwargs):
        self.login = login
        self.password = password
        super().__init__(aws_profile)

    def revert(self, record, new_password):
        """Revert rotation of an AWS console login password"""
        self.rotate(record, new_password, revert=True)

    def create_login(self, new_password):
        """Create AWS login profile and return (success, response)"""
        try:
            create_response = self.iam.create_login_profile(UserName=self.login, Password=new_password)
        except Exception as e:
            logging.error(f'Error creating AWS login for user "{self.login}": {e}')
            return False, None
        else:
            return True, create_response

    def rotate(self, record, new_password, revert=False):
        """Rotate an AWS console login password"""
        if revert:
            if self.password:
                new_password = self.password
            else:
                return False

        if not self.set_iam_session():
            return False
        try:
            update_response = self.iam.update_login_profile(UserName=self.login, Password=new_password)
        except ClientError as e:
            client_error_code = e.response.get('Error', {}).get('Code')
            if client_error_code == 'InvalidClientTokenId':
                logging.error(f'Unable to connect using {self.profile_msg}. {AWS_INVALID_CLIENT_MSG}')
                return False
            elif client_error_code == 'NoSuchEntity':
                create_success, create_response = self.create_login(new_password)
                return create_success
            else:
                logging.error(f'Error updating AWS login for user "{self.login}": {e}')
                return False
        except Exception as e:
            logging.error(f'Error updating AWS login for user "{self.login}": {e}')
            return False
        else:
            return True
