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
import io
import json
import logging
import os
import requests
from typing import Iterable, Union, Optional, Dict, List
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from .base import user_choice, dump_report_data, report_output_parser, field_to_title, GroupCommand
from .enterprise import TeamApproveCommand, EnterpriseCommand
from .. import api, utils, vault, attachment, vault_extensions
from ..display import bcolors
from ..params import KeeperParams
from ..error import CommandError

scim_list_parser = argparse.ArgumentParser(prog='scim list', parents=[report_output_parser],
                                           description='Display a list of available SCIM endpoints.')

scim_view_parser = argparse.ArgumentParser(prog='scim view', description='Display a SCIM endpoint details.')
scim_view_parser.add_argument('target', help='SCIM ID')
scim_view_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                              help='output format.')
scim_view_parser.add_argument('--output', dest='output', action='store',
                              help='output file name. (ignored for table format)')

scim_create_parser = argparse.ArgumentParser(prog='scim create', description='Create SCIM endpoint.')
scim_create_parser.add_argument('--node', dest='node', required=True, help='Node Name or ID.')
scim_create_parser.add_argument(
    '--prefix', dest='prefix', action='store',
    help='Role Prefix. SCIM groups staring with prefix will be imported to Keeper as Roles.')
scim_create_parser.add_argument(
    '--unique-groups', dest='unique_groups', action='store', choices=['on', 'off'], help='Unique Groups.')

scim_edit_parser = argparse.ArgumentParser(prog='scim edit', description='Edit SCIM endpoint.')
scim_edit_parser.add_argument('target', help='SCIM ID')
scim_edit_parser.add_argument(
    '--prefix', dest='prefix', action='store',
    help='Role Prefix. SCIM groups staring with prefix will be imported to Keeper as Roles.')
scim_edit_parser.add_argument(
    '--unique-groups', dest='unique_groups', action='store', choices=['on', 'off'], help='Unique Groups.')

scim_delete_parser = argparse.ArgumentParser(prog='scim delete', description='Delete SCIM endpoint.')
scim_delete_parser.add_argument('target', help='SCIM ID')
scim_delete_parser.add_argument('--force', '-f', dest='force', action='store_true', help='Delete with no confirmation')

scim_push_parser = argparse.ArgumentParser(prog='scim push', description='Push data to SCIM endpoint.')
scim_push_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                              help='display SCIM requests without posing them')
scim_push_parser.add_argument('--source', dest='source', action='store', choices=['google', 'ad'],
                              default='google', help='Source of SCIM data')
scim_push_parser.add_argument('--record', '-r', dest='record', action='store',
                              help='Record UID with SCIM configuration')
scim_push_parser.add_argument('target', help='SCIM ID')


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
        self.register_command('push', ScimPushCommand())
        self.default_verb = 'list'


class ScimListCommand(EnterpriseCommand):
    def get_parser(self):
        return scim_list_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format') or ''
        headers = ['scim_id', 'node_name', 'node_id', 'prefix', 'status', 'last_synced']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]

        table = []
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
        return dump_report_data(table, headers=headers, fmt=fmt, filename=kwargs.get('output'))


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


def find_scim(param, name):  # type: (KeeperParams, any) -> dict
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
                ['SCIM ID', scim['scim_id']], ['SCIM URL', get_scim_url(params, node_id)], ['Node ID', node_id],
                ['Node Name', node_name],
                ['Status', scim['status']], ['Prefix', scim.get('role_prefix') or ''],
                ['Unique Groups', scim.get('unique_groups', False)]
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


class ScimUser:
    def __init__(self):
        self.id = ''
        self.external_id = ''
        self.email = ''
        self.full_name = ''
        self.first_name = ''
        self.last_name = ''
        self.active = False
        self.groups = []

    def __str__(self):
        scim_user = {
            'id': self.id,
            'external_id': self.external_id,
            'email': self.email,
            'full_name': self.full_name,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'active': self.active,
            'groups': self.groups,
        }
        return 'SCIM USER: ' + json.dumps(scim_user)


class ScimGroup:
    def __init__(self):
        self.id = ''
        self.external_id = ''
        self.name = ''

    def __str__(self):
        scim_group = {
            'id': self.id,
            'external_id': self.external_id,
            'name': self.name,
        }
        return 'SCIM GROUP: ' + json.dumps(scim_group)


class ScimPushCommand(EnterpriseCommand):
    def get_parser(self):
        return scim_push_parser

    def execute(self, params, target=None, **kwargs):
        scim = find_scim(params, target)
        dry_run = kwargs.get('dry_run') is True

        scim_url = get_scim_url(params, scim['node_id'])
        record_uid = kwargs.get('record')
        record = None  # type: Optional[vault.TypedRecord]
        if record_uid:
            if record_uid in params.record_cache:
                r = vault.KeeperRecord.load(params, record_uid)
                if isinstance(r, vault.TypedRecord):
                    record = r
                else:
                    raise CommandError('', f'Record UID "{record_uid}": invalid record type ')
            else:
                raise CommandError('', f'Record UID "{record_uid}": does not exist')
        else:
            for r in vault_extensions.find_records(params, record_version=3):
                if not isinstance(r, vault.TypedRecord):
                    continue
                field = next((x for x in r.fields if x.type == 'url'), None)
                if field:
                    url = field.get_default_value(str)
                    if url and url == scim_url:
                        record = r
                        break
            if not isinstance(record, vault.TypedRecord):
                raise CommandError('', f'Cannot find SCIM record with URL: {scim_url}')

        field = next((x for x in record.fields if x.type == 'password'), None)
        if not field:
            raise CommandError('', f'"Password" field not found on record "{record.title}"')
        token = field.get_default_value(str)
        if not token:
            raise CommandError('', f'"Password" field is empty on record "{record.title}"')

        keeper_users = {}  # type: Dict[str, ScimUser]
        keeper_groups = {}  # type: Dict[str, ScimGroup]
        logging.debug('SCIM Query Keeper')
        for element in ScimPushCommand.scim_keeper(scim_url, token):
            if isinstance(element, ScimUser):
                keeper_users[element.id] = element
                logging.debug(str(element))
            elif isinstance(element, ScimGroup):
                keeper_groups[element.id] = element
                logging.debug(str(element))

        external_func = None
        source = kwargs.get('source')
        if not source:
            raise CommandError('', f'SCIM source {source} cannot be empty')
        if source == 'google':
            external_func = ScimPushCommand.scim_google
        elif source == 'ad':
            external_func = ScimPushCommand.scim_ad
        else:
            raise CommandError('', f'SCIM source {source} is not supported')

        other_users = {}  # type: Dict[str, ScimUser]
        other_groups = {}  # type: Dict[str, ScimGroup]

        logging.debug('SCIM Query External Source')
        for element in external_func(params, record):
            if isinstance(element, ScimUser):
                other_users[element.id] = element
                logging.debug(str(element))
            elif isinstance(element, ScimGroup):
                other_groups[element.id] = element
                logging.debug(str(element))

        self.sync_groups(scim_url, token, keeper_groups, other_groups, dry_run)
        self.sync_users(scim_url, token, keeper_users, other_users, dry_run)
        self.sync_membership(scim_url, token, keeper_groups, keeper_users, other_users, dry_run)
        api.query_enterprise(params)
        team_approve = TeamApproveCommand()
        team_approve.execute(params)
        api.query_enterprise(params)

    @staticmethod
    def sync_groups(scim_url, token,
                    keeper_groups,
                    external_groups,
                    dry_run=False):  # type: (str, str, Dict[str, ScimGroup], Dict[str, ScimGroup], bool) -> None
        keeper_group_copy = keeper_groups.copy()
        external_group_copy = external_groups.copy()
        for match_round in range(3):  # 0 - external ID, 1 - name, 2 - reuse groups
            if len(keeper_group_copy) == 0 or len(external_group_copy) == 0:
                break
            if match_round == 0:
                group_lookup = {x.external_id: x for x in keeper_group_copy.values() if x.external_id}
            elif match_round == 1:
                group_lookup = {x.name.casefold(): x for x in keeper_group_copy.values()}
            elif match_round == 2:
                group_lookup = {key: value for key, value in
                                zip(external_group_copy.keys(), keeper_group_copy.values())}
            else:
                continue

            for group_id in list(external_group_copy.keys()):
                group = external_group_copy[group_id]
                if match_round in (0, 2):
                    key = group.id
                elif match_round == 1:
                    key = group.name.casefold()
                else:
                    continue
                if key in group_lookup:
                    keeper_group = group_lookup[key]
                    op = {
                        'op': 'replace',
                        'value': {}
                    }
                    if keeper_group.external_id != group.id:
                        op['value']['externalId'] = group.id
                    if keeper_group.name != group.name:
                        op['value']['displayName'] = group.name
                    if len(op['value']) > 0:
                        payload = {
                            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                            'Operations': [op]
                        }
                        try:
                            ScimPushCommand.patch_scim_resource(
                                f'{scim_url}/Groups', keeper_group.id, token, payload, dry_run)
                            keeper_group.external_id = group.id
                            keeper_group.name = group.name
                            logging.debug('SCIM updated group "%s"', group.name)
                        except Exception as e:
                            logging.warning('PATCH group "%s" error: %s', group.name, e)

                    del keeper_group_copy[keeper_group.id]
                    del external_group_copy[group.id]

        if len(external_group_copy) > 0:  # add groups
            for group in external_group_copy.values():
                payload = {
                    'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group;'],
                    'displayName': group.name,
                    'externalId': group.id
                }
                try:
                    rs = ScimPushCommand.post_scim_resource(f'{scim_url}/Groups', token, payload, dry_run)
                    group_id = rs.get('id')
                    if group_id:
                        keeper_group = ScimGroup()
                        keeper_group.id = group_id
                        keeper_group.external_id = rs.get('externalId')
                        keeper_group.name = rs.get('displayName')
                        keeper_groups[group_id] = keeper_group
                        logging.debug('SCIM added group "%s"', group.name)
                except Exception as e:
                    logging.warning('POST group "%s" error: %s', group.name, e)
        external_group_copy.clear()

        if len(keeper_group_copy) > 0:  # delete groups
            for keeper_group_id in keeper_group_copy:
                keeper_group = keeper_group_copy[keeper_group_id]
                try:
                    ScimPushCommand.delete_scim_resource(f'{scim_url}/Groups', keeper_group_id, token, dry_run)
                    del keeper_groups[keeper_group_id]
                    logging.debug('SCIM deleted group "%s"', keeper_group.name)
                except Exception as e:
                    logging.warning('DELETE group "%s" error: %s', keeper_group.name, e)
        keeper_group_copy.clear()

    @staticmethod
    def sync_users(scim_url, token,
                   keeper_users,
                   external_users,
                   dry_run=False):  # type: (str, str, Dict[str, ScimUser], Dict[str, ScimUser], bool) -> None
        keeper_user_copy = keeper_users.copy()
        external_user_copy = external_users.copy()
        for match_round in range(1):  # 0 - email
            if len(keeper_user_copy) == 0 or len(external_user_copy) == 0:
                break
            if match_round == 0:
                user_lookup = {x.email.casefold(): x for x in keeper_user_copy.values()}  # type: Dict[str, ScimUser]
            else:
                continue

            for user_id in list(external_user_copy.keys()):
                user = external_user_copy[user_id]
                if match_round == 0:
                    key = user.email.casefold()
                else:
                    continue
                if key in user_lookup:
                    keeper_user = user_lookup[key]
                    op = {
                        'op': 'replace',
                        'value': {}
                    }
                    if keeper_user.external_id != user.id:
                        op['value']['externalId'] = user.id
                    if keeper_user.full_name != user.full_name:
                        op['value']['displayName'] = user.full_name
                    if keeper_user.last_name != user.last_name:
                        op['value']['name.familyName'] = user.last_name
                    if keeper_user.first_name != user.first_name:
                        op['value']['name.givenName'] = user.first_name
                    if keeper_user.active != user.active:
                        op['value']['active'] = user.active

                    if len(op['value']) > 0:
                        payload = {
                            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                            'Operations': [op]
                        }
                        try:
                            ScimPushCommand.patch_scim_resource(
                                f'{scim_url}/Users', keeper_user.id, token, payload, dry_run)
                            keeper_user.external_id = user.id
                            keeper_user.full_name = user.full_name
                            keeper_user.first_name = user.first_name
                            keeper_user.last_name = user.last_name
                            keeper_user.active = user.active
                            logging.debug('SCIM updated user "%s"', user.email)
                        except Exception as e:
                            logging.warning('PATCH user "%s" error: %s', user.email, e)

                    del keeper_user_copy[keeper_user.id]
                    del external_user_copy[user.id]

        if len(external_user_copy) > 0:  # add users
            for user in external_user_copy.values():
                if not user.active:
                    continue

                payload = {
                    'schemas': ["urn:ietf:params:scim:schemas:core:2.0:User",
                                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
                    'userName': user.email,
                    'externalId': user.id,
                    'displayName': user.full_name or '',
                    'name': {
                        "givenName": user.first_name or '',
                        "familyName": user.last_name or ''
                    },
                    'active': user.active
                }
                try:
                    rs = ScimPushCommand.post_scim_resource(f'{scim_url}/Users', token, payload, dry_run)
                    user_id = rs.get('id')
                    if user_id:
                        keeper_user = ScimUser()
                        keeper_user.id = user_id
                        keeper_user.email = user.email
                        keeper_user.active = user.active
                        keeper_user.external_id = user.id
                        keeper_user.first_name = user.first_name
                        keeper_user.last_name = user.last_name
                        keeper_users[user_id] = keeper_user
                        logging.debug('SCIM added user "%s"', user.email)
                except Exception as e:
                    logging.warning('POST email "%s" error: %s', user.email, e)
        external_user_copy.clear()

        if len(keeper_user_copy) > 0:  # delete users
            for keeper_user_id in keeper_user_copy:
                keeper_user = keeper_user_copy[keeper_user_id]
                if not keeper_user.active:
                    continue
                try:
                    ScimPushCommand.delete_scim_resource(f'{scim_url}/Users', keeper_user_id, token, dry_run)
                    del keeper_users[keeper_user_id]
                    logging.debug('SCIM deleted user "%s"', keeper_user.email)
                except Exception as e:
                    logging.warning('DELETE user "%s" error: %s', keeper_user.email, e)
        keeper_user_copy.clear()

    @staticmethod
    def sync_membership(scim_url,  # type: str
                        token,  # type: str
                        keeper_groups,   # type: Dict[str, ScimGroup]
                        keeper_users,    # type: Dict[str, ScimUser]
                        external_users,  # type: Dict[str, ScimUser]
                        dry_run=False    # type: bool
                        ):  # type: (...) -> None
        keeper_user_lookup = {x.email: x for x in keeper_users.values()}   # type: Dict[str, ScimUser]
        keeper_group_map = {x.external_id: x.id for x in keeper_groups.values() if x.external_id}
        for user in external_users.values():
            if user.email not in keeper_user_lookup:
                continue
            keeper_user = keeper_user_lookup[user.email]
            keeper_user_groups = set(keeper_user.groups or [])
            skip_deletion = False
            add_groups = []
            remove_groups = []
            for external_group_id in user.groups:
                if external_group_id in keeper_group_map:
                    keeper_group_id = keeper_group_map[external_group_id]
                    if keeper_group_id in keeper_user_groups:
                        keeper_user_groups.remove(keeper_group_id)
                    else:
                        add_groups.append(keeper_group_id)
                else:
                    skip_deletion = True
            if skip_deletion:
                logging.warning('User "%s" membership: skip deletion')
            elif len(keeper_user_groups) > 0:
                remove_groups.extend(keeper_user_groups)

            if len(add_groups) > 0 or len(remove_groups) > 0:
                payload = {
                    'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
                    'Operations': []
                }
                if len(add_groups) > 0:
                    payload['Operations'].append({
                        'op': 'add',
                        'path': 'groups',
                        'value': [{'value': x} for x in add_groups]
                    })
                if len(remove_groups) > 0:
                    payload['Operations'].append({
                        'op': 'remove',
                        'path': 'groups',
                        'value': [{'value': x} for x in remove_groups]
                    })
                try:
                    ScimPushCommand.patch_scim_resource(
                        f'{scim_url}/Users', keeper_user.id, token, payload, dry_run)
                    logging.debug('SCIM changed user "%s" membership: %d added; %d removed',
                                  keeper_user.email, len(add_groups), len(remove_groups))
                except Exception as e:
                    logging.warning('PATCH user "%s" membership error: %s', keeper_user.email, e)

    @staticmethod
    def post_scim_resource(url, token, payload, dry_run=False):
        if dry_run:
            logging.info(f'POST {url}')
            logging.info(json.dumps(payload, indent=2))
            response = payload.copy()
            response['id'] = utils.generate_uid()
            return response
        else:
            headers = {
                'Authorization': f'Bearer {token}',
            }
            rs = requests.post(url, headers=headers, json=payload)
            if rs.status_code >= 300:
                raise CommandError('', f'POST error: {rs.status_code}')
            if rs.status_code in (200, 201):
                return rs.json()

    @staticmethod
    def patch_scim_resource(url, resource_id, token, payload, dry_run=False):
        patch_url = f'{url}/{resource_id}'
        if dry_run:
            logging.info(f'PATCH {patch_url}')
            logging.info(json.dumps(payload, indent=2))
        else:
            headers = {
                'Authorization': f'Bearer {token}',
            }
            rs = requests.patch(patch_url, headers=headers, json=payload)
            if rs.status_code >= 300:
                raise CommandError('', f'PATCH error: {rs.status_code}')
            if rs.status_code == 200:
                return rs.json()

    @staticmethod
    def delete_scim_resource(url, resource_id, token, dry_run=False):
        patch_url = f'{url}/{resource_id}'
        if dry_run:
            logging.info(f'DELETE {patch_url}')
        else:
            headers = {
                'Authorization': f'Bearer {token}',
            }
            rs = requests.delete(patch_url, headers=headers)
            if rs.status_code >= 300:
                raise CommandError('', f'DELETE error: {rs.status_code}')

    @staticmethod
    def get_scim_resource(url, token):
        resources = []
        start_index = 1
        count = 500
        headers = {
            'Authorization': f'Bearer {token}'
        }
        comps = urlparse(url)

        while True:
            q = parse_qsl(comps.query, keep_blank_values=True)
            q.append(('startIndex', str(start_index)))
            q.append(('count', str(count)))
            query = urlencode(q, doseq=True)
            url_comp = (comps.scheme, comps.netloc, comps.path, None, query, None)
            rq_url = urlunparse(url_comp)
            rs = requests.get(rq_url, headers=headers)
            if rs.status_code != 200:
                raise Exception(f'SCIM GET error code "{rs.status_code}"')
            response = rs.json()
            if 'Resources' in response:
                resources.extend(response['Resources'])
            total_results = response['totalResults']
            items_per_page = response['itemsPerPage']
            start_index = response['startIndex'] + items_per_page
            if start_index >= total_results:
                break
        return resources

    @staticmethod
    def scim_keeper(scim_url, token):  # type: (str, str) -> Iterable[Union[ScimUser, ScimGroup]]
        user_resource = ScimPushCommand.get_scim_resource(f'{scim_url}/Users', token)
        group_resource = ScimPushCommand.get_scim_resource(f'{scim_url}/Groups', token)
        for group in group_resource:
            group_id = group.get('id')
            group_name = group.get('displayName')
            if group_id and group_name:
                g = ScimGroup()
                g.id = group_id
                g.name = group_name
                g.external_id = group.get('externalId')
                yield g
        for user in user_resource:
            user_id = user.get('id')
            email = user.get('userName')
            if user_id and email:
                u = ScimUser()
                u.id = user_id
                u.email = email
                u.active = user.get('active') is True
                u.external_id = user.get('externalId')
                u.full_name = user.get('displayName')
                if 'name' in user:
                    name = user['name']
                    u.first_name = name.get('givenName')
                    u.last_name = name.get('familyName')
                if 'groups' in user:
                    for group in user['groups']:
                        if 'value' in group:
                            group_id = group.get('value')
                            if group_id:
                                u.groups.append(group_id)
                yield u

    @staticmethod
    def scim_ad(params, record):  # type: (KeeperParams, vault.TypedRecord) -> Iterable[Union[ScimUser, ScimGroup]]
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
        except ModuleNotFoundError:
            raise CommandError('', 'LDAP3 client is not installed.\npip install ldap3')

        # SCIM group
        field = next((x for x in record.custom if (x.label or '').lower().strip() == 'scim group'), None)
        if not field:
            raise CommandError('', f'Active Directory SCIM record "{record.title}" does not have "SCIM Group" field.\n'
                            'This field contains a Google group name with users to be imported to Keeper.\n'
                            'Leave this field empty to import all users from Google Workspace.')
        scim_group = field.get_default_value(str)

        # AD URL
        ad_url = ''
        field = next((x for x in record.custom if (x.label or '').lower().strip() == 'ad url'), None)
        if field:
            ad_url = field.get_default_value(str)
        if not ad_url:
            raise CommandError('', f'Active Directory SCIM record "{record.title}" does not have "AD URL" field.\n'
                            'This field contains URL to connect to Active Directory.\n'
                            'Format: ldap(s)://<DOMAIN_CONTROLLER_HOSTNAME_OR_IP_ADDRESS>')

        # AD User
        ad_user = ''
        field = next((x for x in record.custom if (x.label or '').lower().strip() == 'ad user'), None)
        if field:
            ad_user = field.get_default_value(str)
        if not ad_user:
            raise CommandError('', f'Active Directory SCIM record "{record.title}" does not have "AD User" field.\n'
                            'This field contains username to connect to Active Directory.\n'
                            'Username should be either DOMAIN\\USERNAME or user distinguished name')

        # AD Password
        ad_password = ''
        field = next((x for x in record.custom if (x.label or '').lower().strip() == 'ad password'), None)
        if field:
            ad_password = field.get_default_value(str)
        if not ad_password:
            raise CommandError('', f'Active Directory SCIM record "{record.title}" does not have "AD Password" field.\n'
                            'This field contains AD user password.')

        server = ldap3.Server(ad_url)
        with ldap3.Connection(server, user=ad_user, password=ad_password,
                              authentication=ldap3.SIMPLE if server.ssl else ldap3.NTLM) as connection:
            connection.bind()
            if not connection.search('', '(class=*)', search_scope=ldap3.BASE, attributes=["*"]):
                raise CommandError('', 'Active Directory: cannot query Root DSE')
            if len(connection.entries) == 0:
                raise CommandError('', 'Active Directory: cannot query Root DSE')
            root_dn = ''
            entry = connection.entries[0]
            entry_attributes = set(entry.entry_attributes)
            if 'rootDomainNamingContext' in entry_attributes:
                root_dn = entry.rootDomainNamingContext.value
            if not root_dn and 'defaultNamingContext' in entry_attributes:
                root_dn = entry.defaultNamingContext.value
            if not root_dn and 'namingContexts' in entry_attributes:
                attrs = entry.namingContexts.values
                if isinstance(attrs, list) and len(attrs) > 0:
                    root_dn = attrs[0]

            if scim_group.lower().startswith('cn='):
                rs = connection.extend.standard.paged_search(
                    scim_group, f'(objectClass=group)',
                    search_scope=ldap3.BASE, generator=False)
            else:
                rs = connection.extend.standard.paged_search(
                    root_dn, f'(&(objectClass=group)(name={escape_filter_chars(scim_group)}))',
                    search_scope=ldap3.SUBTREE, generator=False)
            group_entry = next((x for x in rs if x.get('type') == 'searchResEntry'), None)
            if not group_entry:
                raise CommandError('', f'Active Directory search error: SCIM Group "{scim_group}" not found')
            group_dn = group_entry['dn']

            scim_users = {}           # type: Dict[str, ScimUser]
            scim_users_groups = {}    # type: Dict[str, List[str]]
            all_users = connection.extend.standard.paged_search(
                root_dn, f'(&(objectClass=user)(memberOf={escape_filter_chars(group_dn)}))',
                search_scope=ldap3.SUBTREE, paged_size=1000, generator=True,
                attributes=['objectGUID', 'mail', 'userPrincipalName', 'givenName', 'accountExpires',
                            'sn', 'cn', 'memberOf'])
            now = datetime.datetime.now().timestamp()
            for u in all_users:
                t = u.get('type')
                if t != 'searchResEntry':
                    continue
                user_dn = u['dn']
                attrs = u['attributes']
                email = ''
                if 'mail' in attrs:
                    email = attrs['mail']
                if not email and 'userPrincipalName' in attrs:
                    email = attrs['userPrincipalName']
                if not email:
                    continue
                if 'objectGUID' in attrs:
                    user_id = attrs['objectGUID']
                else:
                    continue
                su = ScimUser()
                su.id = user_id
                su.email = email
                if 'cn' in attrs:
                    su.full_name = attrs['cn']
                if 'givenName' in attrs:
                    su.first_name = attrs['givenName']
                if 'sn' in attrs:
                    su.last_name = attrs['sn']
                if 'accountExpires' in attrs:
                    ae = attrs['accountExpires']
                    if isinstance(ae, datetime.datetime):
                        su.active = ae.timestamp() > now
                scim_users[user_dn] = su
                if 'memberOf' in attrs:
                    scim_users_groups[user_dn] = attrs['memberOf']

            scim_groups = {}           # type: Dict[str, ScimGroup]
            all_groups = connection.extend.standard.paged_search(
                root_dn, f'(&(objectClass=group)(memberOf={escape_filter_chars(group_dn)}))',
                search_scope=ldap3.SUBTREE, paged_size=1000, generator=True,
                attributes=['objectGUID', 'name'])
            for g in all_groups:
                t = g.get('type')
                if t != 'searchResEntry':
                    continue
                group_dn = g['dn']
                attrs = g['attributes']
                scim_group = ScimGroup()
                scim_group.id = attrs.get('objectGUID')
                scim_group.name = attrs.get('name')
                if scim_group.id and scim_group.name:
                    scim_groups[group_dn] = scim_group

            group_lookup = {dn: g.id for dn, g in scim_groups.items()}
            for user_dn, scim_user in scim_users.items():
                if user_dn not in scim_users_groups:
                    continue
                for group_dn in scim_users_groups[user_dn]:
                    if group_dn in group_lookup:
                        scim_user.groups.append(group_lookup[group_dn])

            for scim_user in scim_users.values():
                yield scim_user
            for scim_group in scim_groups.values():
                yield scim_group

    @staticmethod
    def scim_google(params, record):  # type: (KeeperParams, vault.TypedRecord) -> Iterable[Union[ScimUser, ScimGroup]]
        try:
            from google.oauth2 import service_account
            import googleapiclient.discovery
            logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
        except ModuleNotFoundError:
            raise CommandError('', 'Google Cloud client is not installed.\npip install google-api-python-client')

        # SCIM group
        field = next((x for x in record.custom if (x.label or '').lower().strip() == 'scim group'), None)
        if not field:
            raise CommandError('', f'Google SCIM record "{record.title}" does not have "SCIM Group" field.\n'
                            'This field contains a Google group name with users to be imported to Keeper.\n'
                            'Leave this field empty to import all users from Google Workspace.')
        scim_group = field.get_default_value(str)

        # Admin user
        field = next((x for x in record.fields if x.type == 'login'), None)
        if field is None:
            raise CommandError('', f'Google SCIM record "{record.title}" does not have "login" field.\n'
                            'Please use "login" record type to store Google SCIM configuration.')
        admin_user = field.get_default_value(str)
        if not admin_user:
            raise CommandError('', f'"login" field in Google SCIM record "{record.title}" should be populated with '
                            f'Google Workspace administrator email')

        ad = next(attachment.prepare_attachment_download(
            params, record_uid=record.record_uid, attachment_name='credentials.json'), None)
        if not ad:
            raise CommandError('', 'Google SCIM configuration: Service account credentials are not found')

        with io.BytesIO() as mem:
            ad.download_to_stream(params, mem)
            mem.seek(0, io.SEEK_SET)
            info = json.load(mem)
        scopes = ['https://www.googleapis.com/auth/admin.directory.group.readonly',
                  'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
                  'https://www.googleapis.com/auth/admin.directory.user.readonly']
        cred = service_account.Credentials.from_service_account_info(info, scopes=scopes).with_subject(admin_user)
        directory = googleapiclient.discovery.build('admin', 'directory_v1', credentials=cred, static_discovery=False)

        user_lookup = {}
        users = directory.users().list(customer='my_customer').execute()
        if not isinstance(users, dict):
            raise CommandError('', 'Google Cloud: Invalid users response')
        if 'users' not in users:
            raise CommandError('', 'Google Cloud: Invalid users response')
        for user in users['users']:
            u = ScimUser()
            u.id = user['id']
            u.email = user['primaryEmail']
            u.active = not (user.get('suspended') is True)
            if 'name' in user:
                user_name = user['name']
                if 'givenName' in user_name:
                    u.first_name = user['name']['givenName']
                if 'familyName' in user_name:
                    u.last_name = user['name']['familyName']
            if u.first_name or u.last_name:
                u.full_name = f'{(u.first_name or "")} {(u.last_name or "")}'.strip()
            user_lookup[u.email] = u

        groups = directory.groups().list(customer='my_customer').execute()
        if not isinstance(groups, dict):
            raise CommandError('', 'Google Cloud: Invalid groups response')
        if 'groups' not in groups:
            raise CommandError('', 'Google Cloud: Invalid groups response')
        group_lookup = {x['id']: x['name'] for x in groups['groups']}

        if scim_group:
            group_id = next((g_id for g_id, g_name in group_lookup.items() if g_id == scim_group or g_name == scim_group), None)
            if not group_id:
                raise CommandError('', f'Google Workspace: group "{scim_group}" not found')
            del group_lookup[group_id]
            members = directory.members().list(groupKey=group_id).execute()
            if 'members' in members:
                all_emails = set(user_lookup.keys())
                all_emails.difference_update((x['email'] for x in members['members']))
                for email in all_emails:
                    if email in user_lookup:
                        del user_lookup[email]

        for group_id in group_lookup:
            logging.debug('Google Workspace: membership for group %s', group_lookup[group_id])
            members = directory.members().list(groupKey=group_id).execute()
            if 'members' in members:
                for member in members['members']:
                    email = member.get('email') or ''
                    if email in user_lookup:
                        user = user_lookup[email]
                        if user.groups is None:
                            user.groups = []
                        user.groups.append(group_id)

        # delete groups that are not referenced
        # all_groups = set(group_lookup.keys())
        # for user in user_lookup.values():
        #     if isinstance(user.groups, list):
        #         all_groups.difference_update(user.groups)
        # if len(all_groups) > 0:
        #     for group_id in all_groups:
        #         if group_id in group_lookup:
        #             del group_lookup[group_id]

        for group_id, group_name in group_lookup.items():
            g = ScimGroup()
            g.id = group_id
            g.name = group_name
            yield g

        for u in user_lookup.values():
            yield u
