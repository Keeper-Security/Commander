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

import argparse
import logging
import os
import re

from typing import Optional
from .. import api, crypto, utils
from ..params import KeeperParams

from .base import GroupCommand, dump_report_data
from .enterprise import EnterpriseCommand

from ..proto import automator_pb2 as automator_proto
from ..proto import ssocloud_pb2 as ssocloud

automator_list_parser = argparse.ArgumentParser(prog='automator-list')

automator_view_parser = argparse.ArgumentParser(prog='automator-view')
automator_view_parser.add_argument('target', help='Automator ID or Name.')

automator_create_parser = argparse.ArgumentParser(prog='automator-create')
automator_create_parser.add_argument('--name', dest='name', required=True, action='store', help='Automator name.')
automator_create_parser.add_argument('--node', dest='node', required=True, help='Node Name or ID.')


automator_edit_parser = argparse.ArgumentParser(prog='automator-edit')
automator_edit_parser.add_argument('target', help='Automator ID or Name.')
automator_edit_parser.add_argument('--name', dest='name', action='store', help='Automator name.')
automator_edit_parser.add_argument('--url', dest='url', action='store', help='Automator Webhook URL.')
automator_edit_parser.add_argument('--skill', dest='skill', action='append', choices=['device', 'team'],
                                   help='Automator Skills.')
automator_edit_parser.add_argument('--set', dest='setting', metavar="KEY=VALUE", action='append',
                                   help='Automator Settings. Use value: '
                                        '${file:filename} to load text file content. '
                                        '${base64:filename} to load binary file content and encode it with base64url. '
                                        '${env:environment_variable_name} to load the content of environment variable.')

automator_delete_parser = argparse.ArgumentParser(prog='automator-delete')
automator_delete_parser.add_argument('target', help='Automator ID or Name.')
automator_delete_parser.add_argument('--force', '-f', dest='force', action='store_true',
                                     help='Delete with no confirmation')

automator_action_parser = argparse.ArgumentParser(prog='automator-action')
automator_action_parser.add_argument('target', help='Automator ID or Name.')


def register_commands(commands):
    commands['automator'] = AutomatorCommand()


def register_command_info(_, command_info):
    command_info['automator'] = 'Manage Automator endpoints'


class AutomatorCommand(GroupCommand):
    def __init__(self):
        super(AutomatorCommand, self).__init__()
        self.register_command('list', AutomatorListCommand(), 'Displays a list of available automators.')
        self.register_command('view', AutomatorViewCommand(), 'Prints automator details.')
        self.register_command('create', AutomatorCreateCommand(), 'Creates automator endpoint.')
        self.register_command('edit', AutomatorEditCommand(), 'Changes automator configuration.')
        self.register_command('delete', AutomatorDeleteCommand(), 'Deletes automator.')
        self.register_command('setup', AutomatorSetupCommand(), 'Sets up automator.')
        action_command = AutomatorActionCommand()
        self.register_command('init', action_command, 'Initializes automator.')
        self.register_command('enable', action_command, 'Enables automator.')
        self.register_command('disable', action_command, 'Disables automator.')
        self.register_command('reset', action_command, 'Resets automator configuration to the default values.')
        action_command = AutomatorLogCommand()
        self.register_command('log', action_command, 'Retrieves automator logs.')
        self.register_command('log-clear', action_command, 'Clears automator logs.')

        self.default_verb = 'list'


class AutomatorMixin(object):
    @staticmethod
    def skill_to_name(skill):  # type: (automator_proto.SkillType) -> str
        if skill == automator_proto.DEVICE_APPROVAL:
            return 'Device Approval'
        elif skill == automator_proto.TEAM_APPROVAL:
            return 'Team Approval'
        else:
            return str(skill)

    @staticmethod
    def setting_to_str(setting):  # type: (automator_proto.AutomatorSettingValue) -> str
        return '{0}={1}'.format(setting.settingTag, setting.settingValue or '')

    @staticmethod
    def dump_automators(params):  # type: (KeeperParams) -> None
        table = []
        headers = ['ID', 'Name', 'Enabled', 'URL', 'Skills']
        if params.automators:
            for info in params.automators:
                row = [info.automatorId, info.name, info.enabled, info.url,
                       [AutomatorMixin.skill_to_name(x.skillType) for x in info.automatorSkills]]
                table.append(row)
        dump_report_data(table, headers=headers)

    @staticmethod
    def dump_automator(endpoint, status=False):    # type: (automator_proto.AutomatorInfo, bool) -> None
        logging.info('{0:>32s}: {1}'.format('Automator ID', endpoint.automatorId))
        logging.info('{0:>32s}: {1}'.format('Name', endpoint.name))
        logging.info('{0:>32s}: {1}'.format('URL', endpoint.url))
        logging.info('{0:>32s}: {1}'.format('Enabled', 'Yes' if endpoint.enabled else 'No'))
        if status:
            logging.info('{0:>32s}: {1}'.format('Initialized', 'Yes' if endpoint.status.initialized else 'No'))
            if endpoint.status.numberOfDevicesApproved > 0:
                logging.info('{0:>32}: {1}'.format('Approved Devices', endpoint.status.numberOfDevicesApproved))
            if endpoint.status.numberOfDevicesDenied > 0:
                logging.info('{0:>32}: {1}'.format('Denied Devices', endpoint.status.numberOfDevicesDenied))
            if endpoint.status.numberOfErrors > 0:
                logging.info('{0:>32}: {1}'.format('Number of Errors', endpoint.status.numberOfErrors))

        i = 0
        for skill in endpoint.automatorSkills:
            logging.info('{0:>32}: {1}'.format(
                'Skills' if i == 0 else '',
                AutomatorMixin.skill_to_name(skill.skillType)))
            i += 1

        visible_settings = [x for x in endpoint.automatorSettingValues if x.userVisible and x.editable]
        if visible_settings:
            logging.info('\n{0:>32s}\n'.format('Automator Settings'))
            for setting in visible_settings:
                setting_value = AutomatorMixin.setting_to_str(setting)
                value_len = len(setting_value)
                if value_len > 90:
                    value_len -= 80
                    setting_value = f'{setting_value[:80]}... {value_len} more characters.'

                logging.info('{0:>32s}: {1}'.format(setting.settingName, setting_value))

        if endpoint.logEntries:
            logging.info('\n{0:>32s}\n'.format('Automator Log'))
            for log in endpoint.logEntries:
                logging.info('<{0}> {1} - {2}'.format(log.messageLevel, log.serverTime, log.message))

    @staticmethod
    def ensure_loaded(params, force=False):   # type: (KeeperParams, bool) -> None
        if params.automators is None or force:
            enterprise_id = 0
            for node in params.enterprise['nodes']:
                enterprise_id = node['node_id'] >> 32
                break

            rq = automator_proto.AdminGetAutomatorsForEnterpriseRequest()
            rq.enterpriseId = enterprise_id
            admin_rs = api.communicate_rest(
                params, rq, 'automator/automator_get_all_for_enterprise', rs_type=automator_proto.AdminResponse)
            if admin_rs.success:
                params.automators = []
                params.automators.extend(admin_rs.automatorInfo)
            else:
                logging.warning(admin_rs.message)

    @staticmethod
    def find_automator(params, target):   # type: (KeeperParams, any) -> automator_proto.AutomatorInfo
        if not target:
            raise Exception('Automator Name cannot be empty')
        AutomatorMixin.ensure_loaded(params, False)
        if params.automators:
            try:
                target_id = int(target)
                for info in params.automators:
                    if target_id == info.automatorId:
                        return info
            except ValueError:
                pass

        name = target.lower() if type(target) == str else str(target)
        automators = [x for x in params.automators if x.name.lower() == name]
        if len(automators) == 0:
            raise Exception('Automator with name \"{0}\" not found'.format(target))
        if len(automators) > 1:
            raise Exception('There are %d automators with name \"{0})\". Use automator ID.'.format(target))
        return automators[0]


class AutomatorListCommand(EnterpriseCommand, AutomatorMixin):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return automator_list_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        self.ensure_loaded(params, True)
        self.dump_automators(params)


class AutomatorViewCommand(EnterpriseCommand, AutomatorMixin):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return automator_view_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        automator = self.find_automator(params, kwargs.get('target'))

        rq = automator_proto.AdminGetAutomatorRequest()
        rq.automatorId = automator.automatorId
        rs = api.communicate_rest(params, rq, 'automator/automator_get', rs_type=automator_proto.AdminResponse)

        self.dump_automator(rs.automatorInfo[0], status=True)
        if not rs.success:
            logging.info('')
            logging.info(rs.message)


class AutomatorCreateCommand(EnterpriseCommand, AutomatorMixin):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return automator_create_parser

    def execute(self, params, **kwargs):
        # type: (KeeperParams, **any) -> any
        name = kwargs.get('name')
        if not name:
            logging.warning('\"--name\" option is required for \"create\" command')
            return
        node = kwargs.get('node')
        nodes = list(self.resolve_nodes(params, node))
        if len(nodes) == 0:
            logging.warning('Node name \'%s\' is not found', node)
            return
        if len(nodes) > 1:
            logging.warning('Node name \'%s\' is not unique. Use Node ID.', node)
            return
        matched_node = nodes[0]

        rq = automator_proto.AdminCreateAutomatorRequest()
        rq.nodeId = matched_node['node_id']
        rq.name = name

        rs = api.communicate_rest(params, rq, 'automator/automator_create', rs_type=automator_proto.AdminResponse)
        if rs.success:
            self.dump_automator(rs.automatorInfo[0])
            params.automators = None
        else:
            logging.warning(rs.message)


class AutomatorEditCommand(EnterpriseCommand, AutomatorMixin):
    parameter_pattern = re.compile(r'^\${([^:]+?):([^}]+?)}$')

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return automator_edit_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        automator = self.find_automator(params, kwargs.get('target'))
        rq = automator_proto.AdminEditAutomatorRequest()
        rq.automatorId = automator.automatorId
        name = kwargs['name']
        if name:
            rq.name = name
        url = kwargs['url']
        if url:
            rq.url = url
        skills = kwargs.get('skill')
        if skills:
            for skill in skills:
                if skill == 'device':
                    rq.skillTypes.append(automator_proto.DEVICE_APPROVAL)
                elif skill == 'team':
                    rq.skillTypes.append(automator_proto.TEAM_APPROVAL)
                else:
                    logging.warning('Unsupported skill: \"%s\"', skill)
                    return
        settings = kwargs.get('setting')
        if settings:
            available_settings = {}
            for sv in automator.automatorSettingValues:
                available_settings[sv.settingName.lower()] = sv

            for setting in settings:
                pos = setting.find('=')
                if pos > 1:
                    key = setting[:pos].strip()
                    existing = available_settings.get(key.lower())
                    if not existing:
                        logging.warning('Invalid property name: \"%s\"', key)
                        return

                    setting_value = automator_proto.AutomatorSettingValue()
                    setting_value.settingId = existing.settingId
                    value = setting[pos+1:].strip()
                    if existing.dataType == ssocloud.INTEGER or existing.dataType == ssocloud.LONG:
                        try:
                            _ = int(value)
                        except ValueError:
                            logging.warning('Numeric property \"%s\" has incorrect value: \"%s\"', key, value)
                            return
                    elif existing.dataType == ssocloud.BOOLEAN:
                        if value.lower() in ['true', '1', 'on']:
                            value = 'true'
                        elif value.lower() in ['false', '0', 'off']:
                            value = 'false'
                        else:
                            logging.warning(
                                'Boolean property \"%s\" has incorrect value: \"%s\". Use \"true\" or \"false\"',
                                key, value)
                            return

                    match = AutomatorEditCommand.parameter_pattern.match(value.strip())
                    if match:
                        parts = match.groups()
                        if len(parts) == 2:
                            if parts[0].lower() == 'file':
                                filename = parts[1].strip()
                                if os.path.isfile(filename):
                                    with open(filename, 'r') as f:
                                        value = f.read()
                            if parts[0].lower() == 'base64':
                                filename = parts[1].strip()
                                if os.path.isfile(filename):
                                    with open(filename, 'rb') as f:
                                        data = f.read()
                                        value = utils.base64_url_encode(data)
                            elif parts[0].lower() == 'env':
                                if parts[1] in os.environ:
                                    value = os.environ[parts[1]]

                    setting_value.settingValue = value
                    rq.automatorSettingValues.append(setting_value)
                else:
                    logging.warning('Incorrect setting format \"%s\". Expected KEY=VALUE', setting)
                    return

        rs = api.communicate_rest(params, rq, 'automator/automator_edit', rs_type=automator_proto.AdminResponse)
        if rs.automatorInfo:
            self.dump_automator(rs.automatorInfo[0])
            params.automators = None
        if not rs.success:
            logging.warning(rs.message)


class AutomatorSetupCommand(EnterpriseCommand, AutomatorMixin):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return automator_action_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        automator = self.find_automator(params, kwargs.get('target'))
        rq = automator_proto.AdminSetupAutomatorRequest()
        rq.automatorId = automator.automatorId
        rq.automatorState = automator_proto.NEEDS_CRYPTO_STEP_1
        rs = api.communicate_rest(params, rq, 'automator/automator_setup',
                                  rs_type=automator_proto.AdminSetupAutomatorResponse)
        if not rs.success:
            logging.warning('Automator \"%s\" setup step #1 error: %s', automator.name, rs.message)
            return
        rq = automator_proto.AdminSetupAutomatorRequest()
        rq.automatorId = automator.automatorId
        rq.automatorState = automator_proto.NEEDS_CRYPTO_STEP_2
        automator_public_key = crypto.load_ec_public_key(rs.automatorEcPublicKey)
        keys = params.enterprise['keys']
        if 'ecc_encrypted_private_key' in keys:
            encrypted_ec_private_key = utils.base64_url_decode(keys['ecc_encrypted_private_key'])
            ec_private_key = crypto.decrypt_aes_v2(encrypted_ec_private_key, params.enterprise['unencrypted_tree_key'])
            encrypted_ec_private_key = crypto.encrypt_ec(ec_private_key, automator_public_key)
            rq.encryptedEcEnterprisePrivateKey = encrypted_ec_private_key

        if 'rsa_encrypted_private_key' in keys:
            encrypted_rsa_private_key = utils.base64_url_decode(keys['rsa_encrypted_private_key'])
            rsa_private_key = crypto.decrypt_aes_v2(encrypted_rsa_private_key, params.enterprise['unencrypted_tree_key'])
            encrypted_rsa_private_key = crypto.encrypt_ec(rsa_private_key, automator_public_key)
            rq.encryptedRsaEnterprisePrivateKey = encrypted_rsa_private_key

        rs = api.communicate_rest(params, rq, 'automator/automator_setup',
                                  rs_type=automator_proto.AdminSetupAutomatorResponse)
        if rs.success:
            logging.info('Automator \"%s\" is setup', automator.name)
        else:
            logging.warning('Automator \"%s\" setup step #2 error: %s', automator.name, rs.message)


class AutomatorDeleteCommand(EnterpriseCommand, AutomatorMixin):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return automator_delete_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        automator = self.find_automator(params, kwargs.get('target'))
        rq = automator_proto.AdminDeleteAutomatorRequest()
        rq.automatorId = automator.automatorId
        _ = api.communicate_rest(params, rq, 'automator/automator_delete', rs_type=automator_proto.AdminResponse)
        logging.info('Automator %s deleted', automator.automatorId)
        params.automators = None


class AutomatorActionCommand(EnterpriseCommand, AutomatorMixin):
    def get_parser(self):  # type: () -> argparse.ArgumentParser | None
        return automator_action_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        automator = self.find_automator(params, kwargs.get('target'))
        action = kwargs.get('action') or ''
        if action == 'reset':
            rq = automator_proto.AdminDeleteAutomatorRequest()
            endpoint = 'automator/automator_full_reset'
        elif action == 'enable' or action == 'disable':
            rq = automator_proto.AdminEnableAutomatorRequest()
            rq.enabled = action == 'enable'
            endpoint = 'automator/automator_enable'
        elif action == 'init':
            rq = automator_proto.AdminInitializeAutomatorRequest()
            endpoint = 'automator/automator_initialize'
        else:
            logging.warning('Unsupported automator action \"%s\"', action)
            return
        rq.automatorId = automator.automatorId
        rs = api.communicate_rest(params, rq, endpoint, rs_type=automator_proto.AdminResponse)
        if rs.automatorInfo:
            self.dump_automator(rs.automatorInfo[0])
            params.automators = None
        if not rs.success:
            logging.warning(rs.message)


class AutomatorLogCommand(EnterpriseCommand, AutomatorMixin):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return automator_action_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        automator = self.find_automator(params, kwargs.get('target'))
        action = kwargs.get('action') or ''
        if action == 'log':
            rq = automator_proto.AdminAutomatorLogRequest()
            endpoint = 'automator/automator_log_get'
        elif action == 'log-clear':
            rq = automator_proto.AdminAutomatorLogClearRequest()
            endpoint = 'automator/automator_log_clear'
        else:
            logging.warning('Unsupported automator action \"%s\"', action)
            return
        rq.automatorId = automator.automatorId
        rs = api.communicate_rest(params, rq, endpoint, rs_type=automator_proto.AdminResponse)
        if rs.automatorInfo:
            self.dump_automator(rs.automatorInfo[0])
