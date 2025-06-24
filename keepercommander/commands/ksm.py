#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import datetime
import hmac
import json
import logging
import os
import time
import urllib.parse
from itertools import product, groupby

from keeper_secrets_manager_core.utils import bytes_to_base64, url_safe_str_to_bytes

from typing import Sequence, List, Optional

from .base import Command, dump_report_data, user_choice, as_boolean
from . import record
from .. import api, utils, crypto, vault
from ..params import KeeperParams
from ..display import bcolors
from ..proto import APIRequest_pb2, record_pb2, enterprise_pb2
from ..error import KeeperApiError
from ..constants import get_abbrev_by_host
from ..utils import json_to_base64


available_ksm_commands = f"""
{bcolors.BOLD}Keeper Secrets Manager{bcolors.ENDC}
Commands to configure and manage the Keeper Secrets Manager platform.

  Usage:

  {bcolors.BOLD}View Applications:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app list{bcolors.ENDC}

  {bcolors.BOLD}Get Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app get {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.ENDC}

  {bcolors.BOLD}Create Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app create {bcolors.OKBLUE}[NAME]{bcolors.ENDC}

  {bcolors.BOLD}Remove Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app remove {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.ENDC}
    Options: 
      --purge : Remove the application and purge it from the trash
      --force : Do not prompt for confirmation

  {bcolors.BOLD}Grant User Access to Application (Share Application):{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app share {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.OKGREEN} --email {bcolors.OKBLUE}[USERNAME] {bcolors.ENDC}

  {bcolors.BOLD}Revoke User Access to Application (Unshare Application):{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app unshare {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.OKGREEN} --email {bcolors.OKBLUE}[USERNAME]{bcolors.ENDC}

  {bcolors.BOLD}Add Client Device:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager client add --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--unlock-ip{bcolors.ENDC}
    Options: 
      --name [CLIENT NAME] : Name of the client (Default: Random 10 characters string)
      --first-access-expires-in-min [MIN] : First time access expiration (Default 60, Max 1440)
      --access-expire-in-min [MIN] : Client access expiration (Default: no expiration)
      --unlock-ip : Does not lock IP address to first requesting device
      --count [NUM] : Number of tokens to generate (Default: 1)
      --config-init [json, b64 or k8s] : Initialize configuration string from a one-time token

  {bcolors.BOLD}Remove Client Device:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager client remove --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--client {bcolors.OKBLUE}[NAME OR ID]{bcolors.ENDC}
    Options: 
      --force : Do not prompt for confirmation
      --client : Client name or ID. Provide `*` or `all` to delete all clients at once
      
  {bcolors.BOLD}Add Secret to Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share add --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD OR SHARED FOLDER UID]{bcolors.ENDC}
    Options: 
      --editable : Allow secrets to be editable by the client

  {bcolors.BOLD}Remove Secret from Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share remove --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD OR SHARED FOLDER UID]{bcolors.ENDC}

  -----
  Note: If the UID you are using contains a dash (-) in the beginning, the value should be wrapped 
  in quotes and prepended with an equal sign. For example:
  {bcolors.OKGREEN}secrets-manager share add --app={bcolors.OKBLUE}"-fwZjKGbKnZCo1Fh8gsf5w"{bcolors.OKGREEN} --secret={bcolors.OKBLUE}"-FcesCt6YXcJzpHWWRgoDA"{bcolors.ENDC}

  To learn about Keeper Secrets Manager visit:
  {bcolors.WARNING}https://docs.keeper.io/secrets-manager/{bcolors.ENDC}

"""

ksm_parser = argparse.ArgumentParser(prog='secrets-manager', description='Keeper Secrets Management (KSM) Commands',
                                     add_help=False)
ksm_parser.add_argument('command', type=str, action='store', nargs="*",
                    help='One of: "app list", "app get", "app create", "app remove", "app share", "app unshare", ' +
                             '"client add", "client remove", "share add" or "share remove"')
ksm_parser.add_argument('--secret', '-s', type=str, action='append', required=False,
                        help='Record UID')
ksm_parser.add_argument('--app', '-a', type=str, action='store', required=False,
                        help='Application Name or UID')
ksm_parser.add_argument('--client', '-i', type=str, dest='client_names_or_ids', action='append', required=False,
                        help='Client Name or ID')
ksm_parser.add_argument('--first-access-expires-in-min', '-x', type=int, dest='firstAccessExpiresIn', action='store',
                        help='Time for the first request to expire in minutes from the time when this command is '
                             'executed. Maximum 1440 minutes (24 hrs). Default: 60',
                        default=60)
ksm_parser.add_argument('--access-expire-in-min', '-p', type=int, dest='accessExpireInMin', action='store',
                        help='Time interval that this client can access the KSM application. After this time, access '
                             'is denied. Time is entered in minutes starting from the time when command is executed. '
                             'Default: Not expiration')

ksm_parser.add_argument('--count', '-c', type=int, dest='count', action='store',
                        help='Number of tokens to return. Default: 1', default=1)
ksm_parser.add_argument('--help', '-h', dest='helpflag', action="store_true", help='Display help')
ksm_parser.add_argument('--editable', '-e', action='store_true', required=False,
                        help='Is this share going to be editable or not.')
ksm_parser.add_argument('--unlock-ip', '-l', dest='unlockIp', action='store_true', help='Unlock IP Address.')
ksm_parser.add_argument('--return-tokens', dest='returnTokens', action='store_true', help='Return Tokens')
ksm_parser.add_argument('--name', '-n', type=str, dest='name', action='store', help='client name')
ksm_parser.add_argument('--purge', dest='purge', action='store_true',
                        help='remove the record from all folders and purge it from the trash')
ksm_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
ksm_parser.add_argument('--config-init', type=str, dest='config_init', action='store',
                        help='Initialize client config')    # json, b64, file
# Application sharing options
ksm_parser.add_argument('--email', action='store', type=str, dest='email', help='Email of user to grant / remove application access to / from')
# Disable sharing apps w/ admin permissions for now
# ksm_parser.add_argument('--admin', action='store_true', help='Allow share recipient to manage application')
ksm_parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'], default='table',
                        help='Output format (table, json)')



def ms_to_str(ms, frmt='%Y-%m-%d %H:%M:%S'):
    dt = datetime.datetime.fromtimestamp(ms // 1000)
    df_frmt_str = dt.strftime(frmt)

    return df_frmt_str


class KSMCommand(Command):

    CLIENT_SHORT_ID_LENGTH = 8

    def get_parser(self):
        return ksm_parser

    def execute(self, params, **kwargs):

        ksm_command = kwargs.get('command') # type: List[str]
        ksm_helpflag = kwargs.get('helpflag')

        if len(ksm_command) == 0 or ksm_helpflag:
            print(available_ksm_commands)
            return

        ksm_obj = ksm_command[0]
        ksm_action = ksm_command[1] if len(ksm_command) > 1 else None

        if ksm_obj in ['help', 'h']:
            print(available_ksm_commands)
            return

        if ksm_obj == 'apps' or \
                (ksm_obj in ['app', 'apps'] and ksm_action == 'list'):
            format_type = kwargs.get('format', 'table')
            return KSMCommand.print_all_apps_records(params, format_type)

        if ksm_obj == 'clients' or (ksm_obj in ['client', 'clients'] and ksm_action == 'list'):
            print(bcolors.WARNING + "Listing clients is not available" + bcolors.ENDC)
            return

        if ksm_obj in ['app', 'apps'] and ksm_action == 'get':

            if len(ksm_command) != 3:
                print(f"{bcolors.WARNING}Application name is required.\n  " +
                      f"Example: {bcolors.OKGREEN}secrets-manager app get {bcolors.OKBLUE}MyApp{bcolors.ENDC}")
                return

            ksm_app_uid_or_name = ksm_command[2]

            ksm_app = KSMCommand.get_app_record(params, ksm_app_uid_or_name)

            if not ksm_app:
                format_type = kwargs.get('format', 'table')
                if format_type == 'json':
                    return json.dumps({"error": f"Application '{ksm_app_uid_or_name}' not found."})
                else:
                    print((bcolors.WARNING + "Application '%s' not found." + bcolors.ENDC) % ksm_app_uid_or_name)
                return

            format_type = kwargs.get('format', 'table')
            result = KSMCommand.get_and_print_app_info(params, ksm_app.get('record_uid'), format_type)
            if format_type == 'json' and result:
                return result
            return

        if ksm_obj in ['client'] and ksm_action == 'get':
            print(bcolors.WARNING + "Viewing clients is not available" + bcolors.ENDC)
            return

        if ksm_obj in ['app', 'apps'] and ksm_action in ['add', 'create']:
            if len(ksm_command) < 3:
                print(
                    f'''{bcolors.WARNING}Application name is missing.{bcolors.ENDC}\n'''
                    f'''\tEx: {bcolors.OKGREEN}secrets-manager app create {bcolors.OKBLUE}MyApp{bcolors.ENDC}'''
                )
                return

            ksm_app_name = ksm_command[2]

            force_to_add = False    # TODO: externalize this
            format_type = kwargs.get('format', 'table')

            result = KSMCommand.add_new_v5_app(params, ksm_app_name, force_to_add, format_type)
            if format_type == 'json' and result:
                return result
            return

        if ksm_obj in ['app', 'apps'] and ksm_action in ['remove', 'rem', 'rm']:
            app_name_or_uid = ksm_command[2]
            purge = kwargs.get('purge')
            force = kwargs.get('force')

            KSMCommand.remove_v5_app(params=params, app_name_or_uid=app_name_or_uid, purge=purge, force=force)

            return

        if ksm_obj in ['app', 'apps'] and ksm_action in ['share', 'unshare']:
            app_name_or_uid = kwargs.get('app') or ksm_command[2] if len(ksm_command) == 3 else None
            if not app_name_or_uid:
                print(
                    f'''{bcolors.WARNING}Application name is missing.{bcolors.ENDC}\n'''
                    f'''\tEx: {bcolors.OKGREEN}secrets-manager app {ksm_action} {bcolors.OKBLUE}--app=MyApp{bcolors.OKGREEN} --email=myemail@mydomain.com{bcolors.ENDC}'''
                )
                return
            email = kwargs.get('email')
            unshare = 'un' in ksm_action
            is_admin = kwargs.get('admin', False)
            if not email:
                print(
                    f'''{bcolors.WARNING}Email is missing.{bcolors.ENDC}\n'''
                    f'''\tEx: {bcolors.OKGREEN}secrets-manager app {ksm_action} --app=MyApp {bcolors.OKBLUE}--email=myemail@mydomain.com{bcolors.ENDC}'''
                )
                return

            KSMCommand.share_app(params, app_name_or_uid, email, is_admin=is_admin, unshare=unshare)
            return

        if ksm_obj in ['share', 'secret'] and ksm_action is None:
            print("  Add Secret to the App\n\n"
                  + bcolors.OKGREEN + "    secrets-manager share add --app " + bcolors.OKBLUE + "[APP NAME or APP UID]"
                  + bcolors.OKGREEN + " --secret " + bcolors.OKBLUE + "[SECRET UID or SHARED FOLDER UID]"
                  + bcolors.OKGREEN + " --editable" + bcolors.ENDC + "\n")
            return

        if ksm_obj in ['share', 'secret'] and ksm_action in ['add', 'create']:

            app_name_or_uid = kwargs.get('app')
            secret_uid = kwargs.get('secret')   # TODO: Allow multiple secrets
            is_editable = kwargs.get('editable')

            if not secret_uid:
                print(bcolors.WARNING + "\nRecord or Shared Folder UID is required." + bcolors.ENDC)
                print(f"Example to add secret:"
                      + bcolors.OKGREEN + " secrets-manager share add --app " + bcolors.OKBLUE + "[APP NAME or APP UID]"
                      + bcolors.OKGREEN + " --secret " + bcolors.OKBLUE + "[SECRET UID or SHARED FOLDER UID]"
                      + bcolors.OKGREEN + " --editable" + bcolors.ENDC + "\n")
                return

            KSMCommand.add_app_share(params, secret_uid, app_name_or_uid, is_editable)
            return

        if ksm_obj in ['share', 'secret'] and ksm_action in ['remove', 'rem', 'rm']:
            app_name_or_uid = kwargs['app'] if 'app' in kwargs else None
            secret_uids = kwargs.get('secret')

            KSMCommand.remove_share(params, app_name_or_uid, secret_uids)
            return

        if ksm_obj in ['client', 'c']:
            app_name_or_uid = kwargs['app'] if 'app' in kwargs else None

            if not app_name_or_uid:
                print(bcolors.WARNING + "App name is required" + bcolors.ENDC)
                print(f"{bcolors.OKGREEN}  secrets-manager client add "
                      f"{bcolors.OKGREEN}--app {bcolors.OKBLUE}[APP NAME or APP UID] "
                      f"{bcolors.OKGREEN}--secret {bcolors.OKBLUE}[SECRET UID or SHARED FOLDER UID] "
                      f"{bcolors.OKGREEN}--name {bcolors.OKBLUE}[CLIENT NAME] "
                      f"{bcolors.OKGREEN}--config-init [{bcolors.OKBLUE}json{bcolors.OKGREEN}, "
                      f"{bcolors.OKBLUE}b64{bcolors.OKGREEN} or "
                      f"{bcolors.OKBLUE}k8s{bcolors.OKGREEN}]")
                return

            if ksm_action in ['add', 'create']:
                count = kwargs.get('count')
                unlock_ip = kwargs.get('unlockIp')

                client_name = kwargs.get('name')
                config_init = kwargs.get('config_init')

                first_access_expire_on = kwargs.get('firstAccessExpiresIn')
                access_expire_in_min = kwargs.get('accessExpireInMin')

                is_return_tokens = kwargs.get('returnTokens')

                tokens_and_device = KSMCommand.add_client(
                    params, app_name_or_uid, count, unlock_ip, first_access_expire_on, access_expire_in_min,
                    client_name=client_name, config_init=config_init, client_type=enterprise_pb2.GENERAL)

                if config_init:
                    tokens_only = [d['config'] for d in tokens_and_device]
                else:
                    tokens_only = [d['oneTimeToken'] for d in tokens_and_device]

                return ', '.join(tokens_only) if is_return_tokens else None

            if ksm_action in ['remove', 'rem', 'rm']:
                client_names_or_ids = kwargs.get('client_names_or_ids')
                if not client_names_or_ids:
                    return

                force = kwargs.get('force')

                if len(client_names_or_ids) == 1 and client_names_or_ids[0] in ['*', 'all']:
                    KSMCommand.remove_all_clients(params, app_name_or_uid, force)
                else:
                    KSMCommand.remove_client(params, app_name_or_uid, client_names_or_ids)

                return

        print(f"{bcolors.WARNING}Unknown combination of KSM commands. " +
              f"Type 'secrets-manager' for more details'{bcolors.ENDC}")

    @staticmethod
    def share_app(params, app_name_or_uid, email, is_admin=False, unshare=False):
        # type: (KeeperParams, str, List[str], Optional[bool], Optional[bool]) -> None
        app_rec = KSMCommand.get_app_record(params, app_name_or_uid)
        if app_rec is None:
            logging.warning('Application "%s" not found.' % app_name_or_uid)
            return

        # For now, disable sharing app w/ edit + share permissions
        is_admin = False

        app_uid = app_rec.get('record_uid', '')
        sr_action = 'revoke' if unshare else 'grant'
        rec_perms = dict(can_edit=is_admin and not unshare, can_share=is_admin and not unshare)
        users = [email]
        share_rec_args = dict(**rec_perms, action=sr_action, email=users)

        # (Un)Share application record
        from .register import ShareRecordCommand
        share_rec_cmd = ShareRecordCommand()
        share_rec_cmd.execute(params, record=app_uid, **share_rec_args)

        api.sync_down(params)
        KSMCommand.update_secrets_user_permissions(params, app_uid, removed=unshare and email or None)

    @staticmethod
    def update_secrets_user_permissions(params, app_uid, removed=None):   # type: (KeeperParams, str, Optional[str] ) -> None
        # Get app user-permissions
        api.get_record_shares(params, [app_uid])
        app_rec = KSMCommand.get_app_record(params, app_uid)
        if app_rec is None:
            logging.warning('Application "%s" not found.' % app_uid)
            return

        user_perms = app_rec.get('shares', {}).get('user_permissions', [])
        sf_perm_keys = ('manage_users', 'manage_records')
        rec_perm_keys = ('can_edit', 'can_share')

        # Grant app-users access to shares as needed
        app_info = KSMCommand.get_app_info(params, app_uid)
        share_uids = [utils.base64_url_encode(s.secretUid) for ai in app_info for s in (ai.shares or [])]
        shared_recs = [uid for uid in share_uids if uid in params.record_cache]
        shared_folders = [uid for uid in share_uids if uid in params.shared_folder_cache]

        # Exclude un-shareable secrets
        api.get_record_shares(params, shared_recs)
        get_sf_permissions = lambda uid: params.shared_folder_cache.get(uid, {}).get('users', [])
        get_rec_permissions = lambda uid: params.record_cache.get(uid, {}).get('shares', {}).get('user_permissions', {})
        is_sf_admin = lambda uid: params.user in api.get_share_admins_for_shared_folder(params, uid)
        is_rec = lambda uid: uid in shared_recs
        get_perms = lambda uid: get_rec_permissions(uid) if is_rec(uid) else get_sf_permissions(uid)
        get_share_user_perms = lambda user, uid: next((x for x in get_perms(uid) if x.get('username') == user), {})
        get_perm = lambda uid, name: get_share_user_perms(params.user, uid).get(name, False)
        is_shareable = lambda uid: (get_perm(uid, 'shareable') or get_perm(uid, 'share_admin')
                                    or  get_perm(uid, 'manage_users') or is_sf_admin(uid))
        shared_recs = [uid for uid in shared_recs if is_shareable(uid)]
        shared_folders = [uid for uid in shared_folders if is_shareable(uid)]

        def share_needs_update(user, share_uid, elevated):
            if is_removed:
                # Allow user to retain access to app secrets after removal from app
                return False
            else:
                # Share secret w/ user only if they lack access
                return not get_share_user_perms(user, share_uid)

        admins = [up.get('username') for up in user_perms if up.get('editable')]
        admins = [x for x in admins if x != params.user]    # Exclude current user
        viewers = [up.get('username') for up in user_perms if not up.get('editable')]
        removed = [removed] if removed is not None else []
        app_users_map = dict(admins=admins,viewers=viewers, removed=removed)

        from .register import ShareRecordCommand, ShareFolderCommand

        get_sf = lambda uid: params.shared_folder_cache.get(uid, {})
        user_needs_update = lambda u, adm: any(share_needs_update(u, uid, adm) for uid in share_uids)

        def group_by_app_share(products):
            first_element = lambda x: x[0]
            products = sorted(products, key=first_element)
            products = groupby(products, key=first_element)
            return {uid: [user for _, user in pair] for uid, pair in products}

        sf_requests = []
        rec_requests = []
        for group, users in app_users_map.items():
            is_admin, is_removed = group == 'admins', group == 'removed'
            users = [u for u in users if user_needs_update(u, is_admin)]
            sf_action = 'remove' if is_removed else 'grant'
            rec_action = 'revoke' if is_removed else 'grant'

            # Grant app-users access (using folder's default permissions) to folder shares if needed
            get_sf_perms = lambda sf: {perm: 'on' if sf.get(f'default_{perm}', False) else 'off' for perm in sf_perm_keys}
            get_sf_args = lambda u, uid: dict(action=sf_action, user=u, **get_sf_perms(get_sf(uid)))
            prep_sf_rq = lambda u, uid: ShareFolderCommand.prepare_request(params, get_sf_args(u, uid), get_sf(uid), u, [], [])
            sf_updates = {(sf, user) for sf, user in product(shared_folders, users) if share_needs_update(user, sf, is_admin)}
            sf_updates = group_by_app_share(sf_updates)
            sf_requests.append([prep_sf_rq(users, uid) for uid, users in sf_updates.items() if users])

            # Grant app-users read-only access to record shares if not already shared
            get_rec_perms = lambda uid: {perm: False for perm in rec_perm_keys}
            get_rec_args = lambda user, uid: dict(action=rec_action, email=user, record=uid, **get_rec_perms(uid))
            prep_rec_rq = lambda user, uid: ShareRecordCommand.prep_request(params, get_rec_args(user, uid))
            rec_updates = {(rec, user) for rec, user in product(shared_recs, users) if share_needs_update(user, rec, is_admin)}
            rec_updates = group_by_app_share(rec_updates)
            rec_requests.extend([prep_rec_rq(users, rec) for rec, users in rec_updates.items() if users])
            rec_requests = [rq for rq in rec_requests if rq]

        ShareFolderCommand.send_requests(params, sf_requests)
        ShareRecordCommand.send_requests(params, rec_requests)


    @staticmethod
    def add_app_share(params, secret_uids, app_name_or_uid, is_editable):

        rec_cache_val = KSMCommand.get_app_record(params, app_name_or_uid)
        if rec_cache_val is None:
            logging.warning('Application "%s" not found.' % app_name_or_uid)
            return

        app_record_uid = rec_cache_val.get('record_uid')
        master_key = rec_cache_val.get('record_key_unencrypted')

        KSMCommand.share_secret(
            params=params,
            app_uid=app_record_uid,
            master_key=master_key,
            secret_uids=secret_uids,
            is_editable=is_editable
        )

        # Update user-permissions for new app share
        api.sync_down(params)
        KSMCommand.update_secrets_user_permissions(params, app_record_uid)

    @staticmethod
    def record_data_as_dict(record_dict):
        data_json_str = record_dict.get('data_unencrypted').decode("utf-8")
        data_dict = json.loads(data_json_str)
        return data_dict

    @staticmethod
    def print_all_apps_records(params, format_type='table'):

        if format_type == 'table':
            print(f"\n{bcolors.BOLD}List all Secrets Manager Applications{bcolors.ENDC}\n")
        
        rs = api.communicate_rest(params, None, 'vault/get_applications_summary',
                                  rs_type=APIRequest_pb2.GetApplicationsSummaryResponse)

        app_summary = {utils.base64_url_encode(x.appRecordUid): {
            'last_access': x.lastAccess,
            'record_shares': x.recordShares,
            'folder_shares': x.folderShares,
            'folder_records': x.folderRecords,
            'client_count': x.clientCount,
        } for x in rs.applicationSummary}

        if format_type == 'json':
            apps_table_fields = ['app_name', 'app_uid', 'records', 'folders', 'devices', 'last_access']
        else:
            apps_table_fields = [f'{bcolors.OKGREEN}App Name{bcolors.ENDC}', f'{bcolors.OKBLUE}App UID{bcolors.ENDC}',
                                 'Records', 'Folders', 'Devices', 'Last Access']
        
        apps_table = []
        for app_uid in app_summary:
            app = app_summary[app_uid]
            app_record = vault.KeeperRecord.load(params, app_uid)
            if isinstance(app_record, vault.ApplicationRecord):
                la = app['last_access']
                if la > 0:
                    last_access = datetime.datetime.fromtimestamp(la // 1000)
                    last_access_str = last_access.strftime('%Y-%m-%d %H:%M:%S') if format_type == 'json' else last_access
                else:
                    last_access_str = None
                
                if format_type == 'json':
                    row = [app_record.title, app_uid, app['folder_records'], app['folder_shares'], 
                           app['client_count'], last_access_str]
                else:
                    row = [f'{bcolors.OKGREEN}{app_record.title}{bcolors.ENDC}', f'{bcolors.OKBLUE}{app_uid}{bcolors.ENDC}',
                           app['folder_records'], app['folder_shares'], app['client_count'], last_access_str]
                apps_table.append(row)

        apps_table.sort(key=lambda x: x[0].lower() if format_type == 'json' else x[0].replace('\x1b[92m', '').replace('\x1b[0m', '').lower())

        if len(apps_table) == 0:
            if format_type == 'json':
                print(json.dumps({"applications": [], "message": "No Applications to list."}))
            else:
                print(f'{bcolors.WARNING}No Applications to list.{bcolors.ENDC}\n\n'
                      f'To create new application, use command {bcolors.OKGREEN}secrets-manager app '
                      f'create {bcolors.OKBLUE}[NAME]{bcolors.ENDC}')
        else:
            return dump_report_data(apps_table, apps_table_fields, fmt=format_type)

        if format_type == 'table':
            print("")

    @staticmethod
    def get_app_info(params, app_uid):   # type: (KeeperParams, str) -> Sequence[APIRequest_pb2.AppInfo]
        rq = APIRequest_pb2.GetAppInfoRequest()
        rq.appRecordUid.append(utils.base64_url_decode(app_uid))
        rs = api.communicate_rest(params, rq, 'vault/get_app_info', rs_type=APIRequest_pb2.GetAppInfoResponse)
        return rs.appInfo

    @staticmethod
    def get_sm_app_record_by_uid(params, uid):
        rec = params.record_cache.get(uid)

        if rec.get('version') != 5:
            raise Exception(f'Record {uid} is not a Secrets Manager application')

        data_json_str = rec.get('data_unencrypted').decode("utf-8")
        data_dict = json.loads(data_json_str)

        return data_dict

    @staticmethod
    def get_and_print_app_info(params, uid, format_type='table'):

        app_info = KSMCommand.get_app_info(params, uid)

        def shorten_client_id(all_clients, original_id, number_of_characters):

            new_id = original_id[0:number_of_characters]

            res = list(filter(lambda x: utils.base64_url_encode(x.clientId).startswith(new_id), all_clients))
            if len(res) == 1 or new_id == original_id:
                return new_id
            else:
                return shorten_client_id(all_clients, original_id, number_of_characters+1)

        if len(app_info) == 0:
            if format_type == 'json':
                return json.dumps({"error": "No Secrets Manager Applications returned."})
            else:
                print(bcolors.WARNING + 'No Secrets Manager Applications returned.' + bcolors.ENDC)
            return
        else:
            result_data = []
            for ai in app_info:

                app_uid_str = utils.base64_url_encode(ai.appRecordUid)

                app = KSMCommand.get_sm_app_record_by_uid(params, app_uid_str)
                
                app_data = {
                    "app_name": app.get("title"),
                    "app_uid": app_uid_str,
                    "client_devices": [],
                    "shares": []
                }
                
                if format_type == 'table':
                    print(f'\nSecrets Manager Application\n'
                        f'App Name: {app.get("title")}\n'
                        f'App UID: {app_uid_str}')

                client_devices = [x for x in ai.clients if x.appClientType == enterprise_pb2.GENERAL]
                if len(client_devices) > 0:
                    client_count = 1
                    for c in client_devices:
                        client_id = utils.base64_url_encode(c.clientId)
                        current_milli_time = round(time.time() * 1000)
                        
                        created_on_ts = ms_to_str(c.createdOn)
                        first_access_ts = None if c.firstAccess == 0 else ms_to_str(c.firstAccess)
                        last_access_ts = None if c.lastAccess == 0 else ms_to_str(c.lastAccess)
                        
                        if c.accessExpireOn == 0:
                            expire_access_ts = None
                            expire_status = "never"
                        elif c.accessExpireOn <= current_milli_time:
                            expire_access_ts = ms_to_str(c.accessExpireOn)
                            expire_status = "expired"
                        else:
                            expire_access_ts = ms_to_str(c.accessExpireOn)
                            expire_status = "active"
                        
                        short_client_id = shorten_client_id(ai.clients, client_id, KSMCommand.CLIENT_SHORT_ID_LENGTH)
                        
                        client_device_data = {
                            "device_name": c.id,
                            "short_id": short_client_id,
                            "client_id": client_id,
                            "created_on": created_on_ts,
                            "expires_on": expire_access_ts,
                            "expire_status": expire_status,
                            "first_access": first_access_ts,
                            "last_access": last_access_ts,
                            "ip_lock_enabled": c.lockIp,
                            "ip_address": c.ipAddress if c.ipAddress else None
                        }
                        app_data["client_devices"].append(client_device_data)
                        
                        if format_type == 'table':
                            created_on = f'{bcolors.OKGREEN}{created_on_ts}{bcolors.ENDC}'
                            first_access = f'{bcolors.WARNING}Never{bcolors.ENDC}' if c.firstAccess == 0 else f'{bcolors.OKGREEN}{first_access_ts}{bcolors.ENDC}'
                            last_access = f'{bcolors.WARNING}Never{bcolors.ENDC}' if c.lastAccess == 0 else f'{bcolors.OKGREEN}{last_access_ts}{bcolors.ENDC}'
                            lock_ip = f'{bcolors.OKGREEN}Enabled{bcolors.ENDC}' if c.lockIp else f'{bcolors.WARNING}Disabled{bcolors.ENDC}'
                            
                            if expire_status == "never":
                                expire_access = f'{bcolors.OKGREEN}Never{bcolors.ENDC}'
                            elif expire_status == "expired":
                                expire_access = f'{bcolors.FAIL}{expire_access_ts}{bcolors.ENDC}'
                            else:
                                expire_access = f'{bcolors.WARNING}{expire_access_ts}{bcolors.ENDC}'

                            client_devices_str = f"\n{bcolors.BOLD}Client Device {client_count}{bcolors.ENDC}\n" \
                                                f"=============================\n" \
                                                f'  Device Name: {bcolors.OKGREEN}{c.id}{bcolors.ENDC}\n' \
                                                f'  Short ID: {bcolors.OKGREEN}{short_client_id}{bcolors.ENDC}\n' \
                                                f'  Created On: {created_on}\n' \
                                                f'  Expires On: {expire_access}\n' \
                                                f'  First Access: {first_access}\n' \
                                                f'  Last Access: {last_access}\n' \
                                                f'  IP Lock: {lock_ip}\n' \
                                                f'  IP Address: {client_device_data["ip_address"] or "--"}'

                            print(client_devices_str)
                        client_count += 1

                else:
                    if format_type == 'table':
                        print(f'\n\t{bcolors.WARNING}No client devices registered for this Application{bcolors.ENDC}')

                if format_type == 'table':
                    print(bcolors.BOLD + "\nApplication Access\n" + bcolors.ENDC)

                if ai.shares:
                    recs = params.record_cache

                    for s in ai.shares:
                        uid_str = utils.base64_url_encode(s.secretUid)
                        sht = APIRequest_pb2.ApplicationShareType.Name(s.shareType)
                        
                        share_data = {
                            "share_type": sht,
                            "uid": uid_str,
                            "editable": s.editable
                        }

                        if sht == 'SHARE_TYPE_RECORD':
                            rec = recs.get(uid_str)
                            if rec:
                                record_data_dict = KSMCommand.record_data_as_dict(rec)
                                share_data["title"] = record_data_dict.get('title')
                                share_data["type"] = "RECORD"
                        elif sht == 'SHARE_TYPE_FOLDER':
                            if uid_str in params.shared_folder_cache:
                                cached_sf = params.shared_folder_cache[uid_str]
                                share_data["title"] = cached_sf.get('name_unencrypted')
                                share_data["type"] = "FOLDER"
                            else:
                                continue
                        else:
                            logging.warning("Unknown Share Type %s" % sht)
                            continue

                        app_data["shares"].append(share_data)
                    
                    if format_type == 'table' and ai.shares:
                        shares_table_fields = ['Share Type', 'UID', 'Title', 'Permissions']
                        shares_table = []
                        
                        for share in app_data["shares"]:
                            uid_str_c = bcolors.OKBLUE + share["uid"] + bcolors.ENDC
                            editable_status_color = bcolors.OKGREEN if share["editable"] else bcolors.WARNING
                            editable_status = editable_status_color + ("Editable" if share["editable"] else "Read-Only") + bcolors.ENDC
                            
                            row = [
                                share["type"],
                                uid_str_c,
                                share.get("title", ""),
                                editable_status]
                            shares_table.append(row)

                        shares_table.sort(key=lambda x: x[2].lower())
                        dump_report_data(shares_table, shares_table_fields, fmt='table')
                        print()
                else:
                    if format_type == 'table':
                        print('\tThere are no shared secrets to this application')
                
                result_data.append(app_data)
            
        if format_type == 'json':
            if len(result_data) == 1:
                return json.dumps(result_data[0], indent=2)
            else:
                return json.dumps({"applications": result_data}, indent=2)

    @staticmethod
    def share_secret(params, app_uid, master_key, secret_uids, is_editable=False):

        app_shares = []

        added_secret_uids_type_pairs = []

        for uid in secret_uids:
            is_record = uid in params.record_cache
            is_shared_folder = api.is_shared_folder(params, uid)

            if is_record:
                rec = params.record_cache[uid]
                share_key_decrypted = rec['record_key_unencrypted']
                share_type = 'SHARE_TYPE_RECORD'
            elif is_shared_folder:
                cached_sf = params.shared_folder_cache[uid]
                shared_folder_key_unencrypted = cached_sf.get('shared_folder_key_unencrypted')
                share_key_decrypted = shared_folder_key_unencrypted
                share_type = 'SHARE_TYPE_FOLDER'
            else:
                print(f"""{bcolors.WARNING}\tUID="{uid}" is not a Record nor Shared Folder. Only individual records or 
                Shared Folders can be added to the application.{bcolors.ENDC} Make sure your local cache is up to date by
                running 'sync-down' command and trying again.""")

                continue

            added_secret_uids_type_pairs.append((uid, share_type))

            encrypted_secret_key = crypto.encrypt_aes_v2(share_key_decrypted, master_key)

            app_share = APIRequest_pb2.AppShareAdd()
            app_share.secretUid = utils.base64_url_decode(uid)
            app_share.shareType = APIRequest_pb2.ApplicationShareType.Value(share_type)
            app_share.encryptedSecretKey = encrypted_secret_key
            app_share.editable = is_editable

            app_shares.append(app_share)

        if len(added_secret_uids_type_pairs) == 0:
            return

        app_share_add_rq = APIRequest_pb2.AddAppSharesRequest()
        app_share_add_rq.appRecordUid = utils.base64_url_decode(app_uid)
        app_share_add_rq.shares.extend(app_shares)

        try:
            api.communicate_rest(params, app_share_add_rq, 'vault/app_share_add')
            print(bcolors.OKGREEN + f'\nSuccessfully added secrets to app uid={app_uid}, '
                                    f'editable=' + bcolors.BOLD + f'{is_editable}:' + bcolors.ENDC)
            print('\n'.join(map(lambda x: ('\t' + str(x[0])) + ' ' + ('Record' if ('RECORD' in str(x[1])) else 'Shared Folder'), added_secret_uids_type_pairs)))
            print('\n')
            return True
        except KeeperApiError as kae:
            if kae.message == 'Duplicate share, already added':
                logging.error("One of the secret UIDs is already shared to this application. "
                              "Please remove already shared UIDs from your command and try again.")
            else:
                raise kae
        return False

    @staticmethod
    def get_app_record(params, app_name_or_uid):

        for rec_cache_val in params.record_cache.values():

            if rec_cache_val.get('version') == 5:
                r_uid = rec_cache_val.get('record_uid')
                r_unencr_json_data = rec_cache_val.get('data_unencrypted').decode('utf-8')
                r_unencr_dict = json.loads(r_unencr_json_data)

                if r_unencr_dict.get('title') == app_name_or_uid or r_uid == app_name_or_uid:
                    return rec_cache_val

        return None

    @staticmethod
    def search_app_records(params, search_str):

        search_results_rec_data = []

        for record_uid in params.record_cache:
            rec = params.record_cache[record_uid]

            if rec.get('version') == 5:
                data = json.loads(rec.get('data_unencrypted'))
                rec_uid = rec.get('record_uid')
                rec_title = data.get('title')

                if rec_uid == search_str.strip() or rec_title.lower() == search_str.strip().lower():
                    search_results_rec_data.append(
                        {
                            'uid': rec_uid,
                            'data': data
                        })

        return search_results_rec_data

    @staticmethod
    def remove_v5_app(params, app_name_or_uid, purge, force):

        app = KSMCommand.get_app_record(params, app_name_or_uid)

        if not app:
            logging.warning('Application "%s" not found.' % app_name_or_uid)
            return
        app_uid = app.get('record_uid')

        app_info = KSMCommand.get_app_info(params, app_uid)

        clients_count = len(app_info[0].clients)
        shared_folders_count = sum(map(lambda s: s.shareType == 1, app_info[0].shares))
        shared_records_count = sum(map(lambda s: s.shareType == 0, app_info[0].shares))

        if not force:
            print("This Application (uid: %s) has %d client(s), %d shared folder(s), and %d record(s)."
                  % (app_uid, clients_count, shared_folders_count, shared_records_count))
            uc = user_choice('\tAre you sure you want to delete this application?', 'yn', default='n')
            if uc.lower() != 'y':
                return

        logging.info("Removed Application uid: %s" % app_uid)

        cmd = record.RecordRemoveCommand()
        cmd.execute(params, purge=purge, force=True, record=app_uid)

    @staticmethod
    def add_new_v5_app(params, app_name, force_to_add=False, format_type='table'):

        logging.debug("Creating new KSM Application named '%s'" % app_name)

        found_app = KSMCommand.get_app_record(params, app_name)
        if (found_app is not None) and (found_app is not force_to_add):
            if format_type == 'json':
                return json.dumps({"error": f'Application with the same name "{app_name}" already exists.'})
            else:
                logging.warning('Application with the same name "%s" already exists.' % app_name)
            return

        app_record_data = {
            'title': app_name,
            'type': 'app'
        }

        data_json = json.dumps(app_record_data)
        record_key_unencrypted = utils.generate_aes_key()
        record_key_encrypted = crypto.encrypt_aes_v2(record_key_unencrypted, params.data_key)

        app_record_uid_str = api.generate_record_uid()
        app_record_uid = utils.base64_url_decode(app_record_uid_str)

        data = data_json.decode('utf-8') if isinstance(data_json, bytes) else data_json
        data = api.pad_aes_gcm(data)

        rdata = bytes(data, 'utf-8')
        rdata = crypto.encrypt_aes_v2(rdata, record_key_unencrypted)

        client_modif_time = api.current_milli_time()

        ra = record_pb2.ApplicationAddRequest()
        ra.app_uid = app_record_uid
        ra.record_key = record_key_encrypted
        ra.client_modified_time = client_modif_time
        ra.data = rdata

        api.communicate_rest(params, ra, 'vault/application_add')
        app_uid_str = utils.base64_url_encode(ra.app_uid)
        
        if format_type == 'json':
            result = {
                "app_name": app_name,
                "app_uid": app_uid_str,
                "message": "Application was successfully added",
                "created_at": datetime.datetime.fromtimestamp(client_modif_time / 1000).strftime('%Y-%m-%d %H:%M:%S')
            }
            params.sync_data = True
            return json.dumps(result, indent=2)
        else:
            print(bcolors.OKGREEN + f"Application was successfully added (UID: {app_uid_str})" + bcolors.ENDC)

        params.sync_data = True

    @staticmethod
    def remove_share(params, app_name_or_uid, secret_uids):
        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        app_uid = app.get('record_uid')

        rq = APIRequest_pb2.RemoveAppSharesRequest()

        rq.appRecordUid = utils.base64_url_decode(app_uid)
        rq.shares.extend((utils.base64_url_decode(x) for x in secret_uids))
        api.communicate_rest(params, rq, 'vault/app_share_remove')
        print(bcolors.OKGREEN + "Secret share was successfully removed from the application\n" + bcolors.ENDC)

    @staticmethod
    def remove_all_clients(params, app_name_or_uid, force):
        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        app_uid = app.get('record_uid')

        app_info = KSMCommand.get_app_info(params, app_uid)

        clients_count = len(app_info[0].clients)

        if clients_count == 0:
            print(bcolors.WARNING + "No client devices registered for this Application\n" + bcolors.ENDC)
            return

        if not force:

            print(f"This app has {clients_count} client(s) connections.")
            uc = user_choice('\tAre you sure you want to delete all clients from this application?', 'yn', default='n')
            if uc.lower() != 'y':
                return

        client_ids_to_rem = [utils.base64_url_encode(c.clientId) for ai in app_info
                             for c in ai.clients if c.appClientType == enterprise_pb2.GENERAL]
        if len(client_ids_to_rem) > 0:
            KSMCommand.remove_client(params, app_name_or_uid, client_ids_to_rem)

    @staticmethod
    def remove_client(params, app_name_or_uid, client_names_and_hashes):

        def convert_ids_and_hashes_to_hashes(cnahs, app_uid):

            client_id_hashes_bytes = []

            app_info = KSMCommand.get_app_info(params, app_uid)

            for ai in app_info:

                if len(ai.clients) > 0:
                    for c in ai.clients:
                        name = c.id
                        client_id = utils.base64_url_encode(c.clientId)

                        for cnah in cnahs:
                            if name == cnah:
                                client_id_hashes_bytes.append(c.clientId)
                            else:
                                if len(cnah) >= KSMCommand.CLIENT_SHORT_ID_LENGTH and client_id.startswith(cnah):
                                    client_id_hashes_bytes.append(c.clientId)

            return client_id_hashes_bytes

        if not app_name_or_uid:
            raise Exception("No app provided")

        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        app_uid = app.get('record_uid')

        client_hashes = convert_ids_and_hashes_to_hashes(client_names_and_hashes, app_uid)

        found_clients_count = len(client_hashes)
        if found_clients_count == 0:
            print(bcolors.WARNING + "No Client Devices found with given name or ID\n" + bcolors.ENDC)
            return
        else:
            uc = user_choice(f'\tAre you sure you want to delete {found_clients_count} matching clients from this application?',
                             'yn', default='n')
            if uc.lower() != 'y':
                return

        rq = APIRequest_pb2.RemoveAppClientsRequest()

        rq.appRecordUid = utils.base64_url_decode(app_uid)
        rq.clients.extend(client_hashes)
        api.communicate_rest(params, rq, 'vault/app_client_remove')
        print(bcolors.OKGREEN + "\nClient removal was successful\n" + bcolors.ENDC)

    @staticmethod
    def add_client(params, app_name_or_uid, count, unlock_ip, first_access_expire_on, access_expire_in_min,
                   client_name=None, config_init=None, silent=False, client_type=enterprise_pb2.GENERAL):

        is_ip_unlocked = as_boolean(unlock_ip, False)
        curr_ms = int(time.time() * 1000)

        first_access_expire_on_ms = curr_ms + (int(first_access_expire_on) * 60 * 1000)

        if access_expire_in_min:
            access_expire_on_ms = curr_ms + (int(access_expire_in_min) * 60 * 1000)
        else:
            access_expire_on_ms = curr_ms

        if not app_name_or_uid:
            raise Exception("No app provided")

        rec_cache_val = KSMCommand.get_app_record(params, app_name_or_uid)

        if not rec_cache_val:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        logging.debug("App uid=%s, unlock_ip=%s" % (rec_cache_val.get('record_uid'), unlock_ip))

        master_key = rec_cache_val.get('record_key_unencrypted')

        keys_str = ""
        otat_str = ""

        tokens = []

        for i in range(count):
            secret_bytes = os.urandom(32)
            counter_bytes = b'KEEPER_SECRETS_MANAGER_CLIENT_ID'
            digest = 'sha512'

            try:
                mac = hmac.new(secret_bytes, counter_bytes, digest).digest()
            except Exception as e:
                logging.error(e.args[0])
                return

            encrypted_master_key = crypto.encrypt_aes_v2(master_key, secret_bytes)

            rq = APIRequest_pb2.AddAppClientRequest()
            rq.appRecordUid = utils.base64_url_decode(rec_cache_val.get('record_uid'))
            rq.encryptedAppKey = encrypted_master_key
            rq.lockIp = not is_ip_unlocked
            rq.firstAccessExpireOn = first_access_expire_on_ms
            rq.appClientType = client_type

            if access_expire_in_min:
                rq.accessExpireOn = access_expire_on_ms

            rq.clientId = mac

            if client_name:
                if count == 1:
                    rq.id = client_name
                else:
                    rq.id = client_name + " " + str((i+1))

            # api_request_payload = ApiRequestPayload()
            # api_request_payload.payload = rq.SerializeToString()
            # api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')

            # rs = execute_rest(params.rest_context, 'vault/app_client_add', api_request_payload)

            device = api.communicate_rest(params, rq, 'vault/app_client_add', rs_type=APIRequest_pb2.Device)

            encrypted_device_token = bytes_to_base64(device.encryptedDeviceToken)

            if encrypted_device_token:

                if keys_str:
                    keys_str += '\n'

                if not is_ip_unlocked:
                    lock_ip_stat = bcolors.OKGREEN + "Enabled" + bcolors.ENDC
                else:
                    lock_ip_stat = bcolors.HIGHINTENSITYRED + "Disabled" + bcolors.ENDC
                exp_date_str = bcolors.BOLD + datetime.datetime.fromtimestamp(
                    first_access_expire_on_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') + bcolors.ENDC

                if access_expire_in_min:
                    app_expire_on_str = bcolors.BOLD + datetime.datetime.fromtimestamp(
                        access_expire_on_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') + bcolors.ENDC
                else:
                    app_expire_on_str = bcolors.WARNING + "Never" + bcolors.ENDC

                token = utils.base64_url_encode(secret_bytes)

                if not config_init:
                    abbrev = get_abbrev_by_host(params.server.lower())

                    if abbrev:
                        token_w_prefix = f'{abbrev}:{token}'
                    else:
                        if not params.server.startswith('http'):
                            tmp_server = "https://" + params.server
                        else:
                            tmp_server = params.server

                        token_w_prefix = f'{urllib.parse.urlparse(tmp_server).netloc.lower()}:{token}'

                    otat_str += f'\nOne-Time Access Token: {bcolors.OKGREEN}{token_w_prefix}{bcolors.ENDC}\n'

                    tokens.append({
                        'oneTimeToken': token_w_prefix,
                        'deviceToken': encrypted_device_token
                    })

                else:
                    config_str = KSMCommand.init_ksm_config(params,
                                                            one_time_token=token,
                                                            config_init=config_init)
                    otat_str += f'\nInitialized Config: {bcolors.OKGREEN}{config_str}{bcolors.ENDC}\n'
                    tokens.append({
                        'config': config_str,
                        'deviceToken': encrypted_device_token
                    })

                if client_name:
                    otat_str += f'Name: {client_name}\n'

                otat_str += f'IP Lock: {lock_ip_stat}\n' \
                            f'Token Expires On: {exp_date_str}\n' \
                            f'App Access Expires on: {app_expire_on_str}\n'

        if not silent:
            print(f'\nSuccessfully generated Client Device\n'
                  f'====================================\n'
                  f'{otat_str}')

        if config_init and not unlock_ip and not silent:
            print(bcolors.WARNING + "\tWarning: Configuration is now locked to your current IP. To keep in unlock you "
                                    "can add flag `--unlock-ip` or use the One-time token to generate configuration on "
                                    "the host that has the IP that needs to be locked." + bcolors.ENDC)

            logging.warning('')

        return tokens

    @staticmethod
    def init_ksm_config(params, one_time_token, config_init, include_config_dict=False):

        try:
            from keeper_secrets_manager_core import SecretsManager
            from keeper_secrets_manager_core.configkeys import ConfigKeys
            from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
        except Exception:
            raise Exception("Keeper Secrets Manager is not installed.\n"
                            "Install it using pip `pip3 install keeper-secrets-manager-core`")

        ksm_conf_storage = InMemoryKeyValueStorage()

        secrets_manager = SecretsManager(
            hostname=params.config.get('server'),
            token=one_time_token,
            # verify_ssl_certs=False,
            config=ksm_conf_storage
        )

        secrets_manager.get_secrets("NON-EXISTING-RECORD-UID")

        config_dict = {
            ConfigKeys.KEY_HOSTNAME.value:             ksm_conf_storage.config.get(ConfigKeys.KEY_HOSTNAME),
            ConfigKeys.KEY_CLIENT_ID.value:            ksm_conf_storage.config.get(ConfigKeys.KEY_CLIENT_ID),
            ConfigKeys.KEY_PRIVATE_KEY.value:          ksm_conf_storage.config.get(ConfigKeys.KEY_PRIVATE_KEY),
            ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID.value: ksm_conf_storage.config.get(ConfigKeys.KEY_SERVER_PUBLIC_KEY_ID),
            ConfigKeys.KEY_APP_KEY.value:              ksm_conf_storage.config.get(ConfigKeys.KEY_APP_KEY),
        }

        # if the SDK version is below 16.2.0 then this key won't be present
        if 'KEY_OWNER_PUBLIC_KEY' in ConfigKeys.__members__ and ksm_conf_storage.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY):
            config_dict[ConfigKeys.KEY_OWNER_PUBLIC_KEY.value] = ksm_conf_storage.config.get(ConfigKeys.KEY_OWNER_PUBLIC_KEY)

        converted_config = KSMCommand.convert_config_dict(config_dict, config_init)

        if include_config_dict:
            return {
                'config_str': converted_config,
                'config_dict': config_dict
            }
        else:
            return converted_config

    @staticmethod
    def convert_config_dict(config_dict, conversion_type='json'):

        config = json.dumps(config_dict)

        if conversion_type in ['b64', 'k8s']:
            config = json_to_base64(config)

        if conversion_type == 'k8s':
            config = "\n" \
                     + "apiVersion: v1\n" \
                     + "data:\n" \
                     + "  config: " + config + "\n" \
                     + "kind: Secret\n" \
                     + "metadata:\n" \
                     + "  name: ksm-config\n" \
                     + "  namespace: default\n" \
                     + "type: Opaque"

        if conversion_type == 'dict':
            config = config_dict

        return config

    @staticmethod
    def get_hash_of_one_time_token(one_time_token):
        """ KSM: Get client ID from one time token, which is equal to a Hash of one time token"""

        ott_parts = one_time_token.split(":")

        if len(ott_parts) == 2:
            ott = ott_parts[1]
        else:
            ott = ott_parts[0]

        existing_secret_key_bytes = url_safe_str_to_bytes(ott)
        digest = 'sha512'
        one_time_token_hash = bytes_to_base64(hmac.new(existing_secret_key_bytes,
                                                       b'KEEPER_SECRETS_MANAGER_CLIENT_ID',
                                                       digest).digest())
        return one_time_token_hash


