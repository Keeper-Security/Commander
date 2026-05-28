#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

from ..base import GroupCommand

from .sp_commands import (
    SsoCloudListCommand, SsoCloudConfigListCommand,
    SsoCloudCreateCommand, SsoCloudDeleteCommand,
)
from .config_commands import (
    SsoCloudGetCommand, SsoCloudSetCommand,
    SsoCloudValidateCommand, SsoCloudGuideCommand,
)
from .metadata_commands import SsoCloudUploadMetadataCommand, SsoCloudDownloadMetadataCommand
from .log_commands import SsoCloudLogCommand, SsoCloudLogClearCommand


class SsoCloudCommand(GroupCommand):
    def __init__(self):
        super(SsoCloudCommand, self).__init__()
        self.register_command('create', SsoCloudCreateCommand(),
                              'Create a new SSO Cloud service provider and configuration.')
        self.register_command('get', SsoCloudGetCommand(), 'View SSO Cloud configuration details.')
        self.register_command('guide', SsoCloudGuideCommand(),
                              'Show IdP-specific setup guide.')
        self.register_command('list', SsoCloudListCommand(), 'List SSO Cloud service providers.')
        self.register_command('config-list', SsoCloudConfigListCommand(),
                              'List configurations for an SSO service provider.')
        self.register_command('upload', SsoCloudUploadMetadataCommand(),
                              'Upload IdP metadata XML to an SSO configuration.')
        self.register_command('download', SsoCloudDownloadMetadataCommand(),
                              'Download Keeper SP metadata XML.')
        self.register_command('set', SsoCloudSetCommand(),
                              'Update SSO configuration settings.')
        self.register_command('validate', SsoCloudValidateCommand(),
                              'Validate an SSO configuration.')
        self.register_command('delete', SsoCloudDeleteCommand(),
                              'Delete an SSO configuration.')
        self.register_command('log', SsoCloudLogCommand(),
                              'View SAML log entries.')
        self.register_command('log-clear', SsoCloudLogClearCommand(),
                              'Clear SAML log entries.')
        self.default_verb = 'list'


def register_commands(commands):
    commands['sso-cloud'] = SsoCloudCommand()


def register_command_info(aliases, command_info):
    command_info['sso-cloud'] = 'Manage SSO Cloud Connect service providers and configurations'
    aliases['sso'] = 'sso-cloud'
