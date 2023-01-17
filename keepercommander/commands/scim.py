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
import base64
import datetime
import json
import logging
import os
from urllib.parse import urlparse, urlunparse

from .base import user_choice, dump_report_data, GroupCommand
from .enterprise import EnterpriseCommand
from .. import api
from ..display import bcolors
from ..params import KeeperParams

scim_list_parser = argparse.ArgumentParser(prog='scim-list', description='Display a list of available SCIM endpoints.')

scim_view_parser = argparse.ArgumentParser(prog='scim-view', description='Display a SCIM endpoint details.')
scim_view_parser.add_argument('target', help='SCIM ID')
scim_view_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table', help='output format.')
scim_view_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')

scim_create_parser = argparse.ArgumentParser(prog='scim-create', description='Create SCIM endpoint.')
scim_create_parser.add_argument('--node', dest='node', required=True, help='Node Name or ID.')
scim_create_parser.add_argument(
    '--prefix', dest='prefix', action='store',
    help='Role Prefix. SCIM groups staring with prefix will be imported to Keeper as Roles.')
scim_create_parser.add_argument(
    '--unique-groups', dest='unique_groups', action='store', choices=['on', 'off'], help='Unique Groups.')

scim_edit_parser = argparse.ArgumentParser(prog='scim-edit', description='Edit SCIM endpoint.')
scim_edit_parser.add_argument('target', help='SCIM ID')
scim_edit_parser.add_argument(
    '--prefix', dest='prefix', action='store',
    help='Role Prefix. SCIM groups staring with prefix will be imported to Keeper as Roles.')
scim_edit_parser.add_argument(
    '--unique-groups', dest='unique_groups', action='store', choices=['on', 'off'], help='Unique Groups.')

scim_delete_parser = argparse.ArgumentParser(prog='scim-delete', description='Delete SCIM endpoint.')
scim_delete_parser.add_argument('target', help='SCIM ID')
scim_delete_parser.add_argument('--force', '-f', dest='force', action='store_true', help='Delete with no confirmation')


def register_commands(commands):
    commands['scim'] = ScimCommand()


def register_command_info(aliases, command_info):
    command_info['scim'] = 'Manage SCIM endpoints'


class ScimCommand(GroupCommand):
    def __init__(self):
        super(ScimCommand, self).__init__()
        self.register_command('list', ScimListCommand())
        self.register_command('view', ScimViewCommand())
        self.register_command('create', ScimCreateCommand())
        self.register_command('edit', ScimEditCommand())
        self.register_command('delete', ScimDeleteCommand())
        self.default_verb = 'list'


class ScimListCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> argparse.ArgumentParser | None
        return scim_list_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        table = []
        headers = ['SCIM ID', 'Node Name', 'Node ID', 'Prefix', 'Status', 'Last Synced']
        if params.enterprise and 'scims' in params.enterprise:
            for info in params.enterprise['scims']:
                node_id = info['node_id']
                last_synced = info.get('last_synced')
                if isinstance(last_synced, int):
                    dt = datetime.datetime.fromtimestamp(last_synced / 1000)
                    last_synced = dt.strftime('%c')
                else:
                    last_synced = str(last_synced or '')
                row = [info['scim_id'], self.get_node_path(params, node_id), node_id,
                       info.get('role_prefix') or '', info['status'], last_synced]
                table.append(row)
        dump_report_data(table, headers=headers)


class ScimCreateCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> argparse.ArgumentParser | None
        return scim_create_parser

    def execute(self, params, node=None, **kwargs):
        if not node:
            logging.warning('\"--node\" option is required for \"create\" command')
            return
        nodes = list(self.resolve_nodes(params, node))
        if len(nodes) > 1:
            logging.warning('Node name \'%s\' is not unique. Use Node ID.', node)
            return
        elif len(nodes) == 0:
            logging.warning('Node name \'%s\' is not found', node)
            return

        matched_node = nodes[0]
        if not matched_node.get('parent_id'):
            logging.warning('Root node cannot be used for SCIM endpoint')
            return
        token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        rq = {
            'command': 'scim_add',
            'scim_id': self.get_enterprise_id(params),
            'node_id': matched_node['node_id'],
            'token': token,
        }
        prefix = kwargs.get('prefix')
        if prefix:
            rq['prefix'] = prefix
        if kwargs.get('unique_groups', '') == 'on':
            rq['unique_groups'] = True

        api.communicate(params, rq)
        api.query_enterprise(params)
        logging.info('')
        logging.info('SCIM ID: %d', rq['scim_id'])
        logging.info('SCIM URL: %s', get_scim_url(params, matched_node['node_id']))
        logging.info('Provisioning Token: %s', token)
        logging.info('')
        return token


def find_scim(param, name):   # type: (KeeperParams, any) -> dict
    if not name:
        raise Exception('SCIM ID cannot be empty')
    if 'scims' in param.enterprise:
        try:
            scim_id = int(name)
            for scim in param.enterprise['scims']:
                if scim['scim_id'] == scim_id:
                    return scim
                if scim['node_id'] == scim_id:
                    return scim
        except:
            raise Exception('SCIM ID should be an integer: {0}'.format(name))
    raise Exception('SCIM endpoint with ID \"{0}\" not found'.format(name))


class ScimViewCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> argparse.ArgumentParser | None
        return scim_view_parser

    def execute(self, params, target=None, **kwargs):
        scim = find_scim(params, target)
        fmt = kwargs.get('format')
        node_id = scim['node_id']
        node_name = self.get_node_path(params, node_id)
        last_synced = scim.get('last_synced')
        if isinstance(last_synced, int):
            last_synced = datetime.datetime.fromtimestamp(last_synced / 1000)
        else:
            last_synced = None

        if fmt == 'json':
            j_output = {
                'scim_id': scim['scim_id'],
                'scim_url': get_scim_url(params, node_id),
                'node_id': node_id,
                'node_name': node_name,
                'status': scim['status'],
                'prefix': scim.get('role_prefix') or '',
                'unique_groups': scim.get('unique_groups', False)
            }
            if last_synced:
                j_output['last_synced'] = last_synced.strftime('%c')
            output_file = kwargs.get('output')
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(j_output, f, indent=2)
                logging.info('File name: %s', os.path.abspath(output_file))
            else:
                return json.dumps(j_output, indent=2)
        else:
            table = [
                ['SCIM ID', scim['scim_id']], ['SCIM URL', get_scim_url(params, node_id)], ['Node ID', node_id], ['Node Name', node_name],
                ['Status', scim['status']], ['Prefix', scim.get('role_prefix') or ''], ['Unique Groups', scim.get('unique_groups', False)]
            ]
            if last_synced:
                table.append(['Last Synced', last_synced.strftime('%c')])
            dump_report_data(table, ['key', 'value'], no_header=True, right_align=(0,))


class ScimEditCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> argparse.ArgumentParser | None
        return scim_edit_parser

    def execute(self, params, target=None, **kwargs):
        scim = find_scim(params, target)
        token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
        rq = {
            'command': 'scim_update',
            'scim_id': scim['scim_id'],
            'token': token,
        }
        prefix = kwargs.get('prefix')
        if prefix:
            rq['prefix'] = prefix
        unique_groups = kwargs.get('unique_groups')
        if unique_groups:
            rq['unique_groups'] = unique_groups == 'on'

        api.communicate(params, rq)
        api.query_enterprise(params)
        logging.info('')
        logging.info('SCIM ID: %d', scim['scim_id'])
        logging.info('SCIM URL: %s', get_scim_url(params, scim['node_id']))
        logging.info('Provisioning Token: %s', token)
        logging.info('')
        return token


class ScimDeleteCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> argparse.ArgumentParser | None
        return scim_delete_parser

    def execute(self, params, target=None, **kwargs):
        scim = find_scim(params, target)
        answer = 'y' if kwargs.get('force') else \
            user_choice(bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                        'You are about to delete SCIM endpoint {0}'.format(scim['scim_id']) +
                        '\n\nDo you want to proceed with deletion?', 'yn', 'n')
        if answer.lower() != 'y':
            return

        rq = {
            'command': 'scim_delete',
            'scim_id': scim['scim_id'],
        }
        api.communicate(params, rq)
        api.query_enterprise(params)
        logging.info('SCIM endpoint \"%d\" at node \"%d\" deleted', scim['scim_id'], scim['node_id'])


def get_scim_url(params, node_id):  # type:  (KeeperParams, int) -> any
    p = urlparse(params.rest_context.server_base)
    return urlunparse((p.scheme, p.netloc, '/api/rest/scim/v2/' + str(node_id), None, None, None))
