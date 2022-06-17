#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
import logging

import boto3


AWS_INVALID_CLIENT_MSG = 'If the AWS key for this profile was recently rotated, a delay is needed before reconnecting.'


def set_session(profile):
    """Create new boto3 session"""
    session_kwargs = {}
    if profile:
        session_kwargs['profile_name'] = profile
    boto3.setup_default_session(**session_kwargs)
    return boto3.DEFAULT_SESSION


class AWSRotator:
    def __init__(self, profile):
        self.aws_profile = profile
        self.profile_msg = f'AWS profile "{profile if profile else "default"}"'
        self.session = None
        self.iam = None

    def set_iam_session(self):
        """Set session and iam properties for instance"""
        try:
            self.session = set_session(self.aws_profile)
            self.iam = boto3.client('iam')
        except Exception as e:
            logging.error(f'Unable to create AWS session using {self.profile_msg}: {e}')
            return False
        else:
            logging.debug(f'Created AWS session using {self.profile_msg}')
            return True
