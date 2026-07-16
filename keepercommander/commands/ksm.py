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
import base64
import calendar
import datetime
import hmac
import json
import logging
import os
import shlex
import time
import urllib.parse
from itertools import product, groupby

from keeper_secrets_manager_core.utils import bytes_to_base64, url_safe_str_to_bytes

from typing import Sequence, List, Optional

from .base import (
    Command, dump_report_data, user_choice, as_boolean, report_output_parser,
    suppress_exit, raise_parse_exception, expand_cmd_args, normalize_output_param, ParseError)
from . import record
from ..nested_share_folder.common import get_folder_key, get_record_key
from .nested_share_folder.helpers import (
    is_nested_share_folder, is_nested_share_record, load_record_metadata, resolve_folder_uid)
from ..nested_share_folder.removal_api import (
    resolve_nested_share_folder_uid, resolve_nested_share_record_uid)
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

  {bcolors.BOLD}Update Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager app update {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.OKGREEN} --name {bcolors.OKBLUE}[NEW NAME]{bcolors.ENDC}

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

  {bcolors.BOLD}Revoke Client Device (search all applications):{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager client revoke --client {bcolors.OKBLUE}[CLIENT ID]{bcolors.ENDC}
    Searches all applications for the given client ID and revokes it.
    Useful for quickly revoking a leaked device without knowing the application.
    The client ID can be found in the device's configuration file as "clientId".
    Options:
      --force : Do not prompt for confirmation

  {bcolors.BOLD}Add Secret to Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share add --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD, SHARED FOLDER, OR NSF UID/PATH] {bcolors.ENDC}
    Options: 
      --editable : Allow secrets to be editable by the client

  {bcolors.BOLD}Update Secret Permissions:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share update --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD, SHARED FOLDER, OR NSF UID/PATH] {bcolors.OKGREEN}--editable{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share update --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD, SHARED FOLDER, OR NSF UID/PATH] {bcolors.OKGREEN}--readonly{bcolors.ENDC}

  {bcolors.BOLD}Remove Secret from Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager share remove --app {bcolors.OKBLUE}[APP NAME OR UID] {bcolors.OKGREEN}--secret {bcolors.OKBLUE}[RECORD, SHARED FOLDER, OR NSF UID/PATH] {bcolors.ENDC}

  {bcolors.BOLD}Add Token to Application:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager token add {bcolors.OKBLUE}[APP NAME OR UID]{bcolors.ENDC}
    Options:
      --count [NUM] : Number of tokens to generate (Default: 1)
      --unlock-ip : Does not lock IP address to first requesting device
      --first-access-expires-in-min [MIN] : First time access expiration (Default 60, Max 1440)
      --access-expire-in-min [MIN] : Client access expiration (Default: no expiration)
      --name [CLIENT NAME] : Name of the client
      --config-init [json, b64 or k8s] : Initialize configuration string from a one-time token
      --return-tokens : Return generated tokens as a comma-separated string
    Adds one or more one-time access tokens to an existing KSM application.
    Equivalent to: secrets-manager client add --app [APP NAME OR UID]

  {bcolors.BOLD}Usage Report:{bcolors.ENDC}
  {bcolors.OKGREEN}secrets-manager usage{bcolors.ENDC}
    Modes:
      (default)            : Top Application Usage - owner (email), count
      --detail             : Full User Usage - owner (name+email), device, API usage
      --by-device          : Top Usage by Device - device, count (+ Exist with --exists)
      --detail --by-device : Full Device Usage - device, app UID, owner, API usage
      --summary            : Total API usage, applications, devices, avg calls/user
      --timeline           : Event timeline over all KSM event types
        --range [24h|7d|30d] : Timeline window (default 30d)
        --all                : Export All rows (Date / Event / Number of Events)
    Options:
      --created [RANGE]    : Override usage/summary date window (default: KSM billing cycle)
      --limit [N]          : Max rows to fetch (paginated; -1 for all)
      --sort [count|name]  : Sort by usage count (default) or name/title (groups related rows)
      --exists             : Add an Exist column to --by-device (Y=live, T=in Trash, N=purged,
                             ?=unknown) resolved from enterprise compliance data.
                             {bcolors.WARNING}*** VERY SLOW: runs a FULL enterprise compliance sync (can take
                             minutes on large tenants). ***{bcolors.ENDC} Only applies to --by-device; it is the
                             only way to detect deleted KSM apps, since the local Trash API cannot
                             list v5 records.
      --format [table|csv|json] --output [FILE] : Output format / file
    Note: usage covers only applications with recorded activity and may include ones since deleted.
    To list all live applications you have access to, run: {bcolors.OKGREEN}secrets-manager app list{bcolors.ENDC}

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
                    help='One of: "app list", "app get", "app create", "app update", "app remove", "app share", ' +
                             '"app unshare", "client add", "client remove", "share add", "share update", "share remove" or "token add"')
ksm_parser.add_argument('--secret', '-s', type=str, action='append', required=False,
                        help='Record, shared folder, or Nested Share Folder (NSF) UID or path')
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
ksm_parser.add_argument('--readonly', '-r', action='store_true', required=False,
                        help='Set this share to read-only (used with share update).')
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


# KSM audit event types, mirrors Admin Console `ksmEventTypes` (const.ts). Only `app_client_access`
# drives the usage-metrics report; the full list is used for the event timeline / Export All.
KSM_EVENT_TYPES = [
    'app_record_shared', 'app_folder_shared', 'app_record_removed', 'app_folder_removed',
    'app_record_share_changed', 'app_folder_share_changed', 'app_client_added', 'app_client_removed',
    'app_client_connected', 'app_client_access', 'app_client_record_update', 'app_client_access_denied',
    'record_rotation_on_demand_fail', 'record_rotation_on_demand_ok',
    'record_rotation_scheduled_fail', 'record_rotation_scheduled_ok',
]
KSM_USAGE_EVENT_TYPE = 'app_client_access'
# Shown after every usage table.
USAGE_APPS_TAIL = ('Usage covers only applications with recorded activity and may include ones since '
                   'deleted. Run "secrets-manager app list" to see all live applications you can access.')
# Legend for the Exist column, shown only with --exists (on --by-device). Existence is resolved from
# enterprise compliance data - deleted KSM apps (v5) cannot be listed via the local Trash API (the
# backend excludes version >= 4), so this tenant-wide check is the only way to detect them. N (purged)
# and T (in trash) are best-effort: only as complete/current as the compliance dataset.
USAGE_EXIST_LEGEND = (
    'Exist: Y=live, T=in Trash (restorable), N=purged, ?=unknown (compliance data unavailable). '
    'Resolved from enterprise compliance data (best-effort).')
# Composite-key separator, mirrors Admin Console (`getSecretsManagerMetrics`).
_USAGE_KEY_SEP = '~|~'
# Timeline presets -> (audit report_type, console preset). Mirrors reportsDatePresets + auditTimeline.js.
KSM_TIMELINE_RANGES = {
    '24h': ('hour', 'last_24_hours', 1),
    '7d': ('day', 'last_7_days', 7),
    '30d': ('day', 'last_30_days', 30),
}

ksm_usage_parser = argparse.ArgumentParser(
    prog='secrets-manager usage', parents=[report_output_parser], add_help=False,
    description='Keeper Secrets Manager usage report')
ksm_usage_parser.add_argument('--detail', dest='detail', action='store_true',
                              help='Full detail table (per owner+device, or per device with --by-device)')
ksm_usage_parser.add_argument('--by-device', dest='by_device', action='store_true',
                              help='Aggregate by device instead of by application owner')
ksm_usage_parser.add_argument('--summary', dest='summary', action='store_true',
                              help='Usage metrics summary (total API usage, apps, devices, avg calls/user)')
ksm_usage_parser.add_argument('--timeline', dest='timeline', action='store_true',
                              help='Secrets Manager event timeline (all KSM event types)')
ksm_usage_parser.add_argument('--range', dest='range', action='store', choices=list(KSM_TIMELINE_RANGES.keys()),
                              help='Timeline window: 24h, 7d or 30d (default 30d). Timeline only')
ksm_usage_parser.add_argument('--all', dest='export_all', action='store_true',
                              help='Timeline only: Export All rows (Date / Event / Number of Events)')
ksm_usage_parser.add_argument('--created', dest='created', action='store',
                              help='Override usage/summary date window (same syntax as audit-report --created). '
                                   'Default: current KSM billing cycle')
ksm_usage_parser.add_argument('--limit', dest='limit', type=int, action='store',
                              help='Max rows to fetch (paginated). Default: all. Use -1 for all')
ksm_usage_parser.add_argument('--exists', dest='exists', action='store_true',
                              help='Add an Exist column to --by-device showing whether each app is '
                                   'live / in Trash / purged, resolved from enterprise compliance data. '
                                   '*** VERY SLOW *** - runs a FULL enterprise compliance sync (can take '
                                   'minutes on large tenants). Only applies to --by-device; ignored on '
                                   'other views (deleted KSM apps cannot be detected any other way)')
ksm_usage_parser.add_argument('--sort', dest='sort', action='store', choices=['count', 'name'],
                              default='count',
                              help='Sort rows by usage count (default, descending) or by name/title '
                                   '(ascending) - use "name" to group related rows, e.g. all "Playground" devices')
ksm_usage_parser.add_argument('--help', '-h', dest='helpflag', action='store_true', help='Display help')
ksm_usage_parser.error = raise_parse_exception
ksm_usage_parser.exit = suppress_exit


def ms_to_str(ms, frmt='%Y-%m-%d %H:%M:%S'):
    dt = datetime.datetime.fromtimestamp(ms // 1000)
    df_frmt_str = dt.strftime(frmt)

    return df_frmt_str


class KSMCommand(Command):

    CLIENT_SHORT_ID_LENGTH = 8

    def get_parser(self):
        return ksm_parser

    def execute_args(self, params, args, **kwargs):
        # Route the `usage` verb to its own parser so its many flags stay out of the shared ksm_parser.
        try:
            tokens = shlex.split(args) if args else []
        except ValueError:
            tokens = []
        if tokens and tokens[0].lower() == 'usage':
            raw = normalize_output_param(expand_cmd_args(args, params.environment_variables))
            try:
                opts = ksm_usage_parser.parse_args(shlex.split(raw)[1:])
            except ParseError as e:
                logging.error(e)
                return
            d = {}
            d.update(kwargs)
            d.update(opts.__dict__)
            return KSMCommand.execute_usage(params, **d)
        return super(KSMCommand, self).execute_args(params, args, **kwargs)

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

        if ksm_obj in ['app', 'apps'] and ksm_action in ['update', 'rename']:
            if len(ksm_command) < 3:
                print(
                    f'''{bcolors.WARNING}Application name or UID is missing.{bcolors.ENDC}\n'''
                    f'''\tEx: {bcolors.OKGREEN}secrets-manager app update {bcolors.OKBLUE}MyApp'''
                    f'''{bcolors.OKGREEN} --name {bcolors.OKBLUE}NewAppName{bcolors.ENDC}'''
                )
                return

            app_name_or_uid = ksm_command[2]
            new_name = kwargs.get('name')

            if not new_name:
                print(
                    f'''{bcolors.WARNING}New application name is required.{bcolors.ENDC}\n'''
                    f'''\tEx: {bcolors.OKGREEN}secrets-manager app update {bcolors.OKBLUE}{app_name_or_uid}'''
                    f'''{bcolors.OKGREEN} --name {bcolors.OKBLUE}NewAppName{bcolors.ENDC}'''
                )
                return

            format_type = kwargs.get('format', 'table')
            result = KSMCommand.update_app(params, app_name_or_uid, new_name, format_type)
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

        if ksm_obj in ['share', 'secret'] and ksm_action in ['update', 'edit']:

            app_name_or_uid = kwargs.get('app')
            secret_uids = kwargs.get('secret')
            is_editable = kwargs.get('editable')
            is_readonly = kwargs.get('readonly')

            if not app_name_or_uid:
                print(bcolors.WARNING + "\nApplication name or UID is required." + bcolors.ENDC)
                print(f"Example:"
                      + bcolors.OKGREEN + " secrets-manager share update --app " + bcolors.OKBLUE + "[APP NAME or APP UID]"
                      + bcolors.OKGREEN + " --secret " + bcolors.OKBLUE + "[SECRET UID]"
                      + bcolors.OKGREEN + " --editable" + bcolors.ENDC)
                return

            if not secret_uids:
                print(bcolors.WARNING + "\nRecord or Shared Folder UID is required." + bcolors.ENDC)
                print(f"Example:"
                      + bcolors.OKGREEN + " secrets-manager share update --app " + bcolors.OKBLUE + "[APP NAME or APP UID]"
                      + bcolors.OKGREEN + " --secret " + bcolors.OKBLUE + "[SECRET UID]"
                      + bcolors.OKGREEN + " --editable" + bcolors.ENDC)
                return

            if not is_editable and not is_readonly:
                print(bcolors.WARNING + "\nPlease specify either --editable or --readonly." + bcolors.ENDC)
                print(f"Example:"
                      + bcolors.OKGREEN + " secrets-manager share update --app " + bcolors.OKBLUE + "[APP NAME or APP UID]"
                      + bcolors.OKGREEN + " --secret " + bcolors.OKBLUE + "[SECRET UID]"
                      + bcolors.OKGREEN + " --editable" + bcolors.ENDC)
                return

            if is_editable and is_readonly:
                print(bcolors.WARNING + "\nCannot specify both --editable and --readonly." + bcolors.ENDC)
                return

            KSMCommand.update_app_share(params, secret_uids, app_name_or_uid, is_editable)
            return

        if ksm_obj in ['share', 'secret'] and ksm_action in ['remove', 'rem', 'rm']:
            app_name_or_uid = kwargs['app'] if 'app' in kwargs else None
            secret_uids = kwargs.get('secret')

            KSMCommand.remove_share(params, app_name_or_uid, secret_uids)
            return

        if ksm_obj in ['client', 'c'] and ksm_action == 'revoke':
            client_names_or_ids = kwargs.get('client_names_or_ids')
            if not client_names_or_ids:
                print(f"{bcolors.WARNING}Client ID is required.{bcolors.ENDC}\n"
                      f"  Usage: {bcolors.OKGREEN}secrets-manager client revoke --client {bcolors.OKBLUE}[CLIENT ID]{bcolors.ENDC}\n"
                      f"  The client ID can be found in the device configuration file as \"clientId\".")
                return
            force = kwargs.get('force')
            KSMCommand.revoke_client(params, client_names_or_ids, force)
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
                    KSMCommand.remove_client(params, app_name_or_uid, client_names_or_ids, force)

                return

        elif ksm_obj in ('token', 'tokens') and ksm_action in ('add', 'create'):
            if len(ksm_command) < 3:
                print(
                    f'{bcolors.WARNING}App UID or name is required.{bcolors.ENDC}\n'
                    f'\tEx: {bcolors.OKGREEN}secrets-manager token add {bcolors.OKBLUE}MyApp{bcolors.ENDC}'
                )
                return
            app_name_or_uid = ksm_command[2]
            count = kwargs.get('count', 1)
            unlock_ip = kwargs.get('unlockIp', False)
            first_access_expire_on = kwargs.get('firstAccessExpiresIn')
            access_expire_in_min = kwargs.get('accessExpireInMin')
            client_name = kwargs.get('name')
            config_init = kwargs.get('config_init')
            is_return_tokens = kwargs.get('returnTokens', False)
            tokens_and_device = KSMCommand.add_client(
                params, app_name_or_uid, count, unlock_ip,
                first_access_expire_on, access_expire_in_min,
                client_name=client_name, config_init=config_init,
                client_type=enterprise_pb2.GENERAL,
            )
            if is_return_tokens and tokens_and_device:
                tokens_only = [x.get('oneTimeToken', '') for x in tokens_and_device if x.get('oneTimeToken')]
                return ', '.join(tokens_only) if tokens_only else None
            return

        print(f"{bcolors.WARNING}Unknown combination of KSM commands. " +
              f"Type 'secrets-manager' for more details'{bcolors.ENDC}")

    # ------------------------------------------------------------------ #
    # secrets-manager usage                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _ts_to_ms(value):
        """Normalize an epoch timestamp to milliseconds (Console stores add-on/billing dates in ms,
        but Commander protos may deliver seconds). Values below 1e11 are treated as seconds."""
        try:
            value = int(value)
        except (TypeError, ValueError):
            return 0
        if value <= 0:
            return 0
        return value if value >= 100_000_000_000 else value * 1000

    @staticmethod
    def _ksm_pick_license(params):
        licenses = params.enterprise.get('licenses', []) if params.enterprise else []
        if not licenses:
            return None
        # Prefer a license carrying the secrets_manager add-on, else the first (Console uses licenses[0]).
        for lic in licenses:
            if any(a.get('name') == 'secrets_manager' for a in lic.get('add_ons', [])):
                return lic
        return licenses[0]

    @staticmethod
    def _set_month(dt, month0, year):
        """Mirror Console checkDateChangeRisk: set month (0-based) + year, clamping day to month length."""
        month = month0 + 1
        last_day = calendar.monthrange(year, month)[1]
        return dt.replace(year=year, month=month, day=min(dt.day, last_day))

    @staticmethod
    def _ksm_billing_cycle(params, run_on_ms=None):
        """Port of Admin Console getKSMBillingCycle (yearly/enterprise path).
        Returns (min_epoch_sec, max_epoch_sec) for the current billing cycle, or None if unavailable."""
        lic = KSMCommand._ksm_pick_license(params)
        if not lic:
            return None
        nb_ms = KSMCommand._ts_to_ms(lic.get('next_billing_date'))
        if not nb_ms:
            return None

        nb = datetime.datetime.fromtimestamp(nb_ms / 1000)
        nb_day = nb.day
        run = datetime.datetime.fromtimestamp(run_on_ms / 1000) if run_on_ms else datetime.datetime.now()
        run_month0 = run.month - 1
        run_year = run.year

        def case_current_to_next():
            start = KSMCommand._set_month(nb, run_month0, run_year)
            end_month0 = 0 if run_month0 + 1 > 11 else run_month0 + 1
            end_year = run_year + 1 if run_month0 + 1 > 11 else run_year
            end = KSMCommand._set_month(nb, end_month0, end_year)
            return start, end

        def case_prev_to_current():
            start_month0 = run_month0 - 1 if run_month0 else 11
            start_year = run_year if run_month0 else run_year - 1
            start = KSMCommand._set_month(nb, start_month0, start_year)
            end = KSMCommand._set_month(nb, run_month0, run_year)
            return start, end

        if run.day > nb_day:
            start, end = case_current_to_next()
        elif run.day < nb_day:
            start, end = case_prev_to_current()
        else:
            run_tod = (run.hour * 3600 + run.minute * 60 + run.second) * 1000 + run.microsecond // 1000
            nb_tod = (nb.hour * 3600 + nb.minute * 60 + nb.second) * 1000 + nb.microsecond // 1000
            start, end = case_prev_to_current() if run_tod < nb_tod else case_current_to_next()

        # Never report before KSM was actually created (Console clamps to max(created, activationTime);
        # Commander add-ons expose only `created`).
        ksm_created_ms = 0
        for a in lic.get('add_ons', []):
            if a.get('name') == 'secrets_manager':
                ksm_created_ms = KSMCommand._ts_to_ms(a.get('created'))
                break
        if ksm_created_ms and ksm_created_ms > int(start.timestamp() * 1000):
            start = datetime.datetime.fromtimestamp(ksm_created_ms / 1000)

        return int(start.timestamp()), int(end.timestamp())

    @staticmethod
    def _user_fullname_map(params):
        result = {}
        for u in (params.enterprise.get('users', []) if params.enterprise else []):
            data = u.get('data') or {}
            name = data.get('displayname')
            if u.get('username'):
                result[u['username']] = name or ''
        return result

    @staticmethod
    def _compliance_app_status(params):
        """Tenant-wide record existence via compliance/SOX data. Returns (live_uids, trash_uids) or
        None if compliance reporting is unavailable. VERY SLOW: performs a FULL enterprise compliance
        sync (can take minutes on large tenants) - callers must gate this behind the opt-in --exists
        flag. This is the ONLY way to detect deleted KSM apps - the local Trash API (get_deleted_records)
        excludes version >= 4 in the backend, so deleted v5 app records are never returned to the client.
        `in_trash` is point-in-time (last sync); a record restored after the sync may read stale, and
        absence from the dataset is treated as 'purged' only as best effort."""
        try:
            from .. import sox
            if not sox.is_compliance_reporting_enabled(params):
                logging.warning('secrets-manager usage --exists: compliance reporting is not enabled for '
                                'this account; the Exist column will be reported as unknown (?)')
                return None
            nodes = params.enterprise.get('nodes') or []
            enterprise_id = next(((n['node_id'] >> 32) for n in nodes), 0)
            root_node_id = nodes[0]['node_id'] if nodes else 0
            sd = sox.get_compliance_data(params, root_node_id, enterprise_id, rebuild=False, min_updated=0)
            live, trash = set(), set()
            for rec in sd.get_records().values():
                (trash if rec.in_trash else live).add(rec.record_uid)
            return live, trash
        except Exception as e:
            logging.warning('secrets-manager usage --exists: could not load compliance data (%s); '
                            'the Exist column will be reported as unknown (?)', e)
            return None

    @staticmethod
    def _resolve_usage_window(params, kwargs):
        """Return (min_sec, max_sec) for the usage/summary path. --created overrides billing cycle."""
        from .aram import AuditReportCommand
        created = kwargs.get('created')
        if created:
            if created in ('today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date',
                           'last_month', 'year_to_date', 'last_year'):
                # Named ranges are resolved server-side; return the token for the filter.
                return created
            flt = AuditReportCommand.get_filter(created, AuditReportCommand.convert_date)
            return flt
        cycle = KSMCommand._ksm_billing_cycle(params)
        if cycle:
            return {'min': cycle[0], 'max': cycle[1], 'exclude_max': True}
        # No billing-cycle anchor available (license has no next_billing_date); fall back to a 30-day window.
        logging.warning('KSM billing cycle unavailable; defaulting to the last 30 days')
        return 'last_30_days'

    @staticmethod
    def execute_usage(params, **kwargs):
        if kwargs.get('helpflag'):
            ksm_usage_parser.print_help()
            return
        if not params.enterprise:
            print(f'{bcolors.WARNING}secrets-manager usage requires an enterprise account.{bcolors.ENDC}')
            return

        detail = kwargs.get('detail', False)
        by_device = kwargs.get('by_device', False)
        summary = kwargs.get('summary', False)
        timeline = kwargs.get('timeline', False)
        export_all = kwargs.get('export_all', False)
        time_range = kwargs.get('range')

        # Validate mutually-exclusive families.
        if timeline and (detail or by_device or summary):
            print(f'{bcolors.WARNING}--timeline cannot be combined with --detail/--by-device/--summary.{bcolors.ENDC}')
            return
        if summary and (detail or by_device):
            print(f'{bcolors.WARNING}--summary is its own report; do not combine with --detail/--by-device.{bcolors.ENDC}')
            return
        if not timeline and (export_all or time_range):
            print(f'{bcolors.WARNING}--all and --range apply only to --timeline.{bcolors.ENDC}')
            return

        if timeline:
            return KSMCommand._usage_timeline(params, **kwargs)
        return KSMCommand._usage_metrics(params, **kwargs)

    @staticmethod
    def _usage_metrics(params, **kwargs):
        from .aram import fetch_audit_events
        detail = kwargs.get('detail', False)
        by_device = kwargs.get('by_device', False)
        summary = kwargs.get('summary', False)
        fmt = kwargs.get('format') or 'table'
        output = kwargs.get('output')
        limit = kwargs.get('limit')

        created_filter = KSMCommand._resolve_usage_window(params, kwargs)
        audit_filter = {'audit_event_type': [KSM_USAGE_EVENT_TYPE], 'created': created_filter}
        rows = fetch_audit_events(
            params, audit_filter, columns=['app_uid', 'device_name', 'username'],
            aggregate=['occurrences'], report_type='span', limit=limit)

        # Aggregation maps mirror Console getSecretsManagerMetrics. The *_apps maps track which
        # application UID(s) contributed to each row so we can flag rows whose app has been deleted
        # (audit events outlive the app, so usage can reference apps no longer in the vault inventory).
        users = {}            # username -> occurrences
        devices = {}          # device_name -> occurrences
        applications = set()  # distinct app_uid
        by_owner = {}         # username~|~device_name -> occurrences
        by_dev = {}           # device_name~|~app_uid~|~username -> occurrences
        users_apps = {}       # username -> {app_uid}  (for the aggregate Exist column)
        devices_apps = {}     # device_name -> {app_uid}
        # (device_name, app_uid) -> occurrences. Device names are NOT unique - the same name can
        # belong to different apps (e.g. several "Playground Gateway" from repeated sample-data
        # imports). Aggregating by name alone would merge distinct apps into one row with a blurred
        # Exist; keying by (name, app_uid) keeps them separate so each row maps to exactly one app.
        dev_app = {}
        # username~|~device_name -> {app_uid}. Not consumed today (detail views omit the Exist column),
        # but kept so a per-owner+device existence flag can be re-added without touching aggregation.
        by_owner_apps = {}
        for r in rows:
            username = r.get('username') or ''
            device_name = r.get('device_name') or ''
            app_uid = r.get('app_uid') or ''
            occ = int(r.get('occurrences') or 0)
            users[username] = users.get(username, 0) + occ
            devices[device_name] = devices.get(device_name, 0) + occ
            dev_app[(device_name, app_uid)] = dev_app.get((device_name, app_uid), 0) + occ
            if app_uid:
                applications.add(app_uid)
                users_apps.setdefault(username, set()).add(app_uid)
                devices_apps.setdefault(device_name, set()).add(app_uid)
                by_owner_apps.setdefault(_USAGE_KEY_SEP.join((username, device_name)), set()).add(app_uid)
            by_owner[_USAGE_KEY_SEP.join((username, device_name))] = \
                by_owner.get(_USAGE_KEY_SEP.join((username, device_name)), 0) + occ
            by_dev[_USAGE_KEY_SEP.join((device_name, app_uid, username))] = \
                by_dev.get(_USAGE_KEY_SEP.join((device_name, app_uid, username)), 0) + occ

        name_map = KSMCommand._user_fullname_map(params)

        # Exist column: shown only with --exists, and only on --by-device (each row is a single app).
        # Existence comes solely from enterprise compliance data - deleted KSM apps (v5) cannot be
        # listed via any local API (get_deleted_records excludes version >= 4 in the backend), so the
        # compliance sync is the only source. That sync is VERY SLOW (full tenant scan) - hence opt-in
        # behind --exists. Unknown ('?') when compliance data is unavailable.
        show_exist = by_device and not detail and bool(kwargs.get('exists'))
        sox_live, sox_trash, sox_loaded = set(), set(), False
        if show_exist:
            logging.warning(f'{bcolors.WARNING}secrets-manager usage --exists is VERY SLOW: it runs a '
                            f'FULL enterprise compliance sync (can take minutes on large tenants). '
                            f'Resolving app existence...{bcolors.ENDC}')
            status = KSMCommand._compliance_app_status(params)
            if status is not None:
                sox_live, sox_trash = status
                sox_loaded = True

        def app_status(a):  # -> 'Y' (live) | 'T' (in trash) | 'N' (purged) | '?' (unknown)
            if not a or not sox_loaded:
                return '?'
            if a in sox_live:
                return 'Y'
            if a in sox_trash:
                return 'T'
            return 'N'  # absent from compliance data -> purged (best effort)

        if summary:
            total = sum(users.values())
            users_count = len(users)
            avg = (total / users_count) if users_count else 0
            table = [
                ['Total API Usage This Cycle', total],
                ['Applications', len(applications)],
                ['Devices', len(devices)],
                ['Average API Calls Per User', round(avg, 2)],
            ]
            headers = ['Metric', 'Value']
        elif detail and by_device:
            # Full Device Usage: device, app_uid, owner (name+email), usage
            table = []
            for key, occ in sorted(by_dev.items(), key=lambda kv: kv[1], reverse=True):
                device_name, app_uid, username = key.split(_USAGE_KEY_SEP)
                full = name_map.get(username, '')
                table.append([device_name, app_uid, full, username, occ])
            headers = ['Device', 'Application UID', 'Owner', 'Email', 'API Usage per Month']
        elif detail:
            # Full User Usage: owner (name+email), device, usage
            table = []
            for key, occ in sorted(by_owner.items(), key=lambda kv: kv[1], reverse=True):
                username, device_name = key.split(_USAGE_KEY_SEP)
                full = name_map.get(username, '')
                table.append([full, username, device_name, occ])
            headers = ['Owner', 'Email', 'Device', 'API Usage per Month']
        elif by_device:
            # Top Usage by Device: one row per (device, app). Suffix the name with the app UID only
            # when that device name is shared by more than one app, so each row is unambiguous. The
            # Exist column is appended only with --exists (compliance-based; see above).
            name_counts = {}
            for (dev, _app) in dev_app:
                name_counts[dev] = name_counts.get(dev, 0) + 1
            table = []
            for (dev, app), occ in sorted(dev_app.items(), key=lambda kv: kv[1], reverse=True):
                label = dev if name_counts.get(dev, 0) <= 1 else f'{dev} ({app or "no-app-uid"})'
                row = [label, occ]
                if show_exist:
                    row.append(app_status(app))
                table.append(row)
            headers = ['Device', 'Count', 'Exist'] if show_exist else ['Device', 'Count']
        else:
            # Default: Top Application Usage (by owner/user): email, count. No Exist column - a single
            # owner aggregates many apps, so a combined existence verdict would be misleading.
            table = [[user, occ]
                     for user, occ in sorted(users.items(), key=lambda kv: kv[1], reverse=True)]
            headers = ['Application Owner', 'Count']

        # --sort name: re-sort by the first (name/title) column so related rows group together
        # (e.g. all "Playground*" devices). Default 'count' keeps the per-view descending-count order.
        # Skipped for --summary, whose rows are fixed metric labels.
        if kwargs.get('sort') == 'name' and not summary:
            table.sort(key=lambda r: str(r[0]).casefold())

        result = dump_report_data(table, headers=headers, fmt=fmt, filename=output)
        # Table mode: always print the app-list pointer; add the Exist legend only when the Exist
        # column is shown (--by-device --exists).
        if fmt == 'table':
            if show_exist:
                print(f'\n{bcolors.OKBLUE}{USAGE_EXIST_LEGEND} {USAGE_APPS_TAIL}{bcolors.ENDC}')
            else:
                print(f'\n{bcolors.OKBLUE}{USAGE_APPS_TAIL}{bcolors.ENDC}')
        return result

    @staticmethod
    def _usage_timeline(params, **kwargs):
        from .aram import fetch_audit_events
        from ..constants import AUDIT_EVENT_STATE_MAPPING
        fmt = kwargs.get('format') or 'table'
        output = kwargs.get('output')
        limit = kwargs.get('limit')
        export_all = kwargs.get('export_all', False)
        time_range = kwargs.get('range') or '30d'
        report_type, _preset, _days = KSM_TIMELINE_RANGES[time_range]

        # Window: mirror Console reportsDatePresets / auditTimeline.js.
        now = datetime.datetime.now()
        if time_range == '24h':
            to_dt = now.replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=1)
            from_dt = to_dt - datetime.timedelta(hours=24)
        else:
            to_dt = now.replace(hour=0, minute=0, second=0, microsecond=0) + datetime.timedelta(days=1)
            from_dt = to_dt - datetime.timedelta(days=_days + 1)
        created_filter = {'min': int(from_dt.timestamp()), 'max': int(to_dt.timestamp())}

        audit_filter = {'audit_event_type': KSM_EVENT_TYPES, 'created': created_filter}
        rows = fetch_audit_events(
            params, audit_filter, columns=['audit_event_type'], aggregate=['occurrences'],
            report_type=report_type, limit=limit, order='descending')

        def label(evt):
            return AUDIT_EVENT_STATE_MAPPING.get(evt, evt)

        def fmt_time(created):
            dt = datetime.datetime.fromtimestamp(int(created))
            return dt.strftime('%Y-%m-%d %H:%M') if report_type == 'hour' else dt.strftime('%Y-%m-%d')

        if export_all:
            # Export All: one row per (time bucket x event), columns Date / Event / Number of Events.
            table = []
            for r in sorted(rows, key=lambda x: int(x.get('created') or 0)):
                evt = r.get('audit_event_type') or ''
                table.append([fmt_time(r.get('created')), label(evt), int(r.get('occurrences') or 0)])
            headers = ['Date', 'Event', 'Number of Events']
            return dump_report_data(table, headers=headers, fmt=fmt, filename=output)

        # Default timeline: event totals over the range, with % of total.
        totals = {}
        for r in rows:
            evt = r.get('audit_event_type') or ''
            totals[evt] = totals.get(evt, 0) + int(r.get('occurrences') or 0)
        grand = sum(totals.values())
        table = []
        for evt, cnt in sorted(totals.items(), key=lambda kv: kv[1], reverse=True):
            pct = round(cnt * 100.0 / grand, 1) if grand else 0
            table.append([label(evt), cnt, f'{pct}%'])
        return dump_report_data(table, headers=['Event', 'Count', '% of Total'], fmt=fmt, filename=output)

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

        resolved_uids = KSMCommand.resolve_secret_uids(params, secret_uids)
        if not resolved_uids:
            return

        KSMCommand.share_secret(
            params=params,
            app_uid=app_record_uid,
            master_key=master_key,
            secret_uids=resolved_uids,
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
                    "users": [],
                    "client_devices": [],
                    "shares": []
                }

                # Fetch user permissions for this application record
                app_rec = params.record_cache.get(app_uid_str)
                if app_rec:
                    # Clear cached shares to force a fresh fetch
                    app_rec.pop('shares', None)
                    api.get_record_shares(params, [app_uid_str])
                    app_rec = params.record_cache.get(app_uid_str)
                    user_perms = (app_rec or {}).get('shares', {}).get('user_permissions', [])
                    for up in user_perms:
                        role = 'owner' if up.get('owner') else 'member'
                        user_data = {
                            "username": up.get('username'),
                            "role": role,
                            "share_admin": up.get('share_admin', False),
                            "shareable": up.get('shareable', False),
                            "editable": up.get('editable', False),
                        }
                        if up.get('awaiting_approval'):
                            user_data["awaiting_approval"] = True
                        if up.get('expiration') and up['expiration'] > 0:
                            user_data["expiration"] = up['expiration']
                        app_data["users"].append(user_data)
                
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
                    if app_data["users"]:
                        print(bcolors.BOLD + "\nApplication Users\n" + bcolors.ENDC)
                        users_table_fields = ['Username', 'Role', 'Editable', 'Shareable']
                        users_table = []
                        for u in app_data["users"]:
                            role_color = bcolors.OKGREEN if u["role"] == "owner" else bcolors.OKBLUE
                            role_str = role_color + u["role"].capitalize() + bcolors.ENDC
                            editable_str = (bcolors.OKGREEN + "Yes" + bcolors.ENDC) if u["editable"] else (bcolors.WARNING + "No" + bcolors.ENDC)
                            shareable_str = (bcolors.OKGREEN + "Yes" + bcolors.ENDC) if u["shareable"] else (bcolors.WARNING + "No" + bcolors.ENDC)
                            users_table.append([u["username"], role_str, editable_str, shareable_str])
                        users_table.sort(key=lambda x: (0 if 'Owner' in x[1] else 1, x[0].lower()))
                        dump_report_data(users_table, users_table_fields, fmt='table')

                    print(bcolors.BOLD + "\nApplication Access\n" + bcolors.ENDC)

                if ai.shares:
                    for s in ai.shares:
                        uid_str = utils.base64_url_encode(s.secretUid)
                        sht = APIRequest_pb2.ApplicationShareType.Name(s.shareType)
                        
                        share_data = {
                            "share_type": sht,
                            "uid": uid_str,
                            "editable": s.editable
                        }

                        if sht == 'SHARE_TYPE_RECORD':
                            share_data["title"] = KSMCommand.get_secret_title(params, uid_str, sht)
                            share_data["type"] = "RECORD"
                            #ToDo: check if type nsf record is valid here
                            if is_nested_share_record(params, uid_str):
                                share_data["type"] = "NSF RECORD"
                        elif sht == 'SHARE_TYPE_FOLDER':
                            share_data["title"] = KSMCommand.get_secret_title(params, uid_str, sht)
                            share_data["type"] = "FOLDER"
                            #ToDo: check if type nsf folder is valid here
                            if is_nested_share_folder(params, uid_str):
                                share_data["type"] = "NSF FOLDER"
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
    def _secret_in_cache(params, uid):
        if uid in getattr(params, 'record_cache', {}):
            return True
        if uid in getattr(params, 'nested_share_records', {}):
            return True
        if api.is_shared_folder(params, uid):
            return True
        if is_nested_share_folder(params, uid):
            return True
        return False

    @staticmethod
    def resolve_secret_uid(params, identifier):
        if not identifier:
            return None
        identifier = str(identifier).strip()
        if identifier.startswith('[') and identifier.endswith(']') and len(identifier) > 2:
            identifier = identifier[1:-1].strip()
        if KSMCommand._secret_in_cache(params, identifier):
            return identifier
        record_uid = resolve_nested_share_record_uid(params, identifier)
        if record_uid:
            return record_uid
        folder_uid = resolve_folder_uid(params, identifier)
        if folder_uid and (api.is_shared_folder(params, folder_uid)
                           or is_nested_share_folder(params, folder_uid)):
            return folder_uid
        folder_uid = resolve_nested_share_folder_uid(params, identifier)
        if folder_uid and is_nested_share_folder(params, folder_uid):
            return folder_uid
        return None

    @staticmethod
    def resolve_secret_uids(params, identifiers):
        if not identifiers:
            return []
        if isinstance(identifiers, str):
            identifiers = [identifiers]
        resolved = []
        for ident in identifiers:
            uid = KSMCommand.resolve_secret_uid(params, ident)
            if uid:
                resolved.append(uid)
            else:
                logging.warning('Could not resolve secret "%s". Run sync-down and try again.', ident)
        return resolved

    @staticmethod
    def classify_secret(params, uid):
        share_key = None
        share_type = None

        if uid in getattr(params, 'record_cache', {}) or is_nested_share_record(params, uid):
            share_type = 'SHARE_TYPE_RECORD'
            if uid in params.record_cache:
                share_key = params.record_cache[uid].get('record_key_unencrypted')
            if not share_key:
                share_key = get_record_key(params, uid, raise_on_missing=False)
        elif api.is_shared_folder(params, uid) or is_nested_share_folder(params, uid):
            share_type = 'SHARE_TYPE_FOLDER'
            cached_sf = getattr(params, 'shared_folder_cache', {}).get(uid, {})
            share_key = cached_sf.get('shared_folder_key_unencrypted')
            if not share_key:
                share_key = get_folder_key(params, uid, raise_on_missing=False)

        if share_type and share_key:
            return {'uid': uid, 'share_type': share_type, 'share_key': share_key}
        return None

    @staticmethod
    def get_secret_title(params, uid, share_type):
        if share_type == 'SHARE_TYPE_RECORD':
            rec = getattr(params, 'record_cache', {}).get(uid)
            if rec and rec.get('data_unencrypted'):
                try:
                    return KSMCommand.record_data_as_dict(rec).get('title', uid)
                except Exception:
                    pass
            if is_nested_share_record(params, uid):
                return load_record_metadata(params, uid).get('title', uid)
        elif share_type == 'SHARE_TYPE_FOLDER':
            cached_sf = getattr(params, 'shared_folder_cache', {}).get(uid, {})
            if cached_sf.get('name_unencrypted'):
                return cached_sf.get('name_unencrypted')
            nsf = getattr(params, 'nested_share_folders', {}).get(uid, {})
            if nsf.get('name'):
                return nsf.get('name')
            folder = getattr(params, 'folder_cache', {}).get(uid)
            if folder and getattr(folder, 'name', None):
                return folder.name
        return uid

    @staticmethod
    def _share_nsf_secret(params, app_uid, master_key, secret, is_editable=False):
        """Share an NSF folder/record with an application using v3 access APIs."""
        from ..nested_share_folder.folder_api import grant_folder_access_to_application_v3
        from ..nested_share_folder.record_api import share_record_to_application_v3

        uid = secret['uid']
        if secret['share_type'] == 'SHARE_TYPE_FOLDER' and is_nested_share_folder(params, uid):
            result = grant_folder_access_to_application_v3(
                params, uid, app_uid, master_key, is_editable=is_editable)
            if not result.get('success'):
                raise KeeperApiError(
                    result.get('status') or 'access_denied',
                    result.get('message') or 'Failed to share Nested Share Folder with application')
            return True

        if secret['share_type'] == 'SHARE_TYPE_RECORD' and is_nested_share_record(params, uid):
            result = share_record_to_application_v3(
                params, uid, app_uid, master_key, is_editable=is_editable)
            if not result.get('success'):
                message = '; '.join(
                    r.get('message') or r.get('status') or 'share failed'
                    for r in result.get('results', [])) or 'Failed to share Nested Share Record with application'
                raise KeeperApiError('share_failed', message)
            return True

        return False

    @staticmethod
    def share_secret(params, app_uid, master_key, secret_uids, is_editable=False):

        app_shares = []
        added_secret_uids_type_pairs = []

        for uid in secret_uids:
            secret = KSMCommand.classify_secret(params, uid)
            if not secret:
                print(f"""{bcolors.WARNING}\tUID="{uid}" is not a Record, Shared Folder, or Nested Share Folder record.
                Only individual records or folders can be added to the application.{bcolors.ENDC} Make sure your local cache is up to date by
                running 'sync-down' command and trying again.""")
                continue

            share_type = secret['share_type']
            uid = secret['uid']

            # NSF folders/records must use v3 access_update / records share APIs.
            if ((share_type == 'SHARE_TYPE_FOLDER' and is_nested_share_folder(params, uid))
                    or (share_type == 'SHARE_TYPE_RECORD' and is_nested_share_record(params, uid))):
                try:
                    KSMCommand._share_nsf_secret(
                        params, app_uid, master_key, secret, is_editable=is_editable)
                    added_secret_uids_type_pairs.append((uid, share_type))
                except KeeperApiError as kae:
                    if 'already' in (kae.message or '').lower():
                        logging.error("One of the secret UIDs is already shared to this application. "
                                      "Please remove already shared UIDs from your command and try again.")
                    else:
                        raise kae
                continue

            share_key_decrypted = secret['share_key']
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

        try:
            if app_shares:
                app_share_add_rq = APIRequest_pb2.AddAppSharesRequest()
                app_share_add_rq.appRecordUid = utils.base64_url_decode(app_uid)
                app_share_add_rq.shares.extend(app_shares)
                api.communicate_rest(params, app_share_add_rq, 'vault/app_share_add')

            print(bcolors.OKGREEN + f'\nSuccessfully added secrets to app uid={app_uid}, '
                                    f'editable=' + bcolors.BOLD + f'{is_editable}:' + bcolors.ENDC)
            print('\n'.join(map(lambda x: ('\t' + str(x[0])) + ' ' + (
                'Nested Share Folder' if is_nested_share_folder(params, x[0]) else
                'Nested Share Record' if is_nested_share_record(params, x[0]) else
                'Record' if 'RECORD' in str(x[1]) else 'Shared Folder'),
                added_secret_uids_type_pairs)))
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
    def _is_ksm_app_data(data_dict):
        return isinstance(data_dict, dict) and data_dict.get('type') == 'app'

    @staticmethod
    def _app_record_from_cache_entry(rec_cache_val):
        if not rec_cache_val or rec_cache_val.get('version') != 5:
            return None
        data_unencrypted = rec_cache_val.get('data_unencrypted')
        if not data_unencrypted:
            return None
        try:
            data_dict = json.loads(data_unencrypted.decode('utf-8'))
        except Exception:
            return None
        if KSMCommand._is_ksm_app_data(data_dict):
            return rec_cache_val
        return None

    @staticmethod
    def _normalize_nsf_app_record(params, record_uid):
        nsf_rec = getattr(params, 'nested_share_records', {}).get(record_uid)
        if not nsf_rec:
            return None

        nsf_data = getattr(params, 'nested_share_record_data', {}).get(record_uid, {})
        data_json = nsf_data.get('data_json', {})
        if not KSMCommand._is_ksm_app_data(data_json):
            return None

        record_key = nsf_rec.get('record_key_unencrypted')
        if not record_key:
            record_key = get_record_key(params, record_uid, raise_on_missing=False)
        if not record_key:
            return None

        return {
            'record_uid': record_uid,
            'version': nsf_rec.get('version', 5),
            'revision': nsf_rec.get('revision', 0),
            'record_key_unencrypted': record_key,
            'data_unencrypted': json.dumps(data_json).encode('utf-8'),
            'source': 'nested_share_folder',
        }

    @staticmethod
    def get_app_record(params, app_name_or_uid):
        if not app_name_or_uid:
            return None

        if app_name_or_uid in getattr(params, 'record_cache', {}):
            rec = KSMCommand._app_record_from_cache_entry(params.record_cache[app_name_or_uid])
            if rec:
                return rec

        nsf_rec = KSMCommand._normalize_nsf_app_record(params, app_name_or_uid)
        if nsf_rec:
            return nsf_rec

        for rec_cache_val in params.record_cache.values():
            rec = KSMCommand._app_record_from_cache_entry(rec_cache_val)
            if not rec:
                continue
            r_uid = rec.get('record_uid')
            try:
                r_unencr_dict = json.loads(rec.get('data_unencrypted').decode('utf-8'))
            except Exception:
                continue
            if r_unencr_dict.get('title') == app_name_or_uid or r_uid == app_name_or_uid:
                return rec

        resolved_uid = resolve_nested_share_record_uid(params, app_name_or_uid)
        if resolved_uid:
            if resolved_uid in getattr(params, 'record_cache', {}):
                rec = KSMCommand._app_record_from_cache_entry(params.record_cache[resolved_uid])
                if rec:
                    return rec
            nsf_rec = KSMCommand._normalize_nsf_app_record(params, resolved_uid)
            if nsf_rec:
                return nsf_rec

        return None

    @staticmethod
    def get_app_title(params, app_uid):
        rec = KSMCommand.get_app_record(params, app_uid)
        if rec and rec.get('data_unencrypted'):
            try:
                return json.loads(rec.get('data_unencrypted').decode('utf-8')).get('title', app_uid)
            except Exception:
                pass

        if is_nested_share_record(params, app_uid):
            meta = load_record_metadata(params, app_uid)
            if meta.get('type') == 'app':
                return meta.get('title', app_uid)

        nsf_data = getattr(params, 'nested_share_record_data', {}).get(app_uid, {})
        data_json = nsf_data.get('data_json', {})
        if isinstance(data_json, dict) and data_json.get('type') == 'app':
            return data_json.get('title', app_uid)
        return None

    @staticmethod
    def get_ksm_app_display_info(params, app_uid_str):
        ksm_app = KSMCommand.get_app_record(params, app_uid_str)
        if ksm_app:
            try:
                title = json.loads(ksm_app.get('data_unencrypted').decode('utf-8')).get('title', app_uid_str)
            except Exception:
                title = app_uid_str
            return title, True, f'{title} ({app_uid_str})'

        title = KSMCommand.get_app_title(params, app_uid_str)
        if title:
            return title, False, f'{title} ({app_uid_str})'

        return None, False, f'[APP NOT ACCESSIBLE OR DELETED] ({app_uid_str})'

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
    def update_app(params, app_name_or_uid, new_name, format_type='table'):
        """Rename an existing KSM application."""
        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            if format_type == 'json':
                return json.dumps({"error": f"Application '{app_name_or_uid}' not found."})
            else:
                logging.warning('Application "%s" not found.' % app_name_or_uid)
            return

        existing_app = KSMCommand.get_app_record(params, new_name)
        if existing_app and existing_app.get('record_uid') != app.get('record_uid'):
            if format_type == 'json':
                return json.dumps({"error": f'Application with the name "{new_name}" already exists.'})
            else:
                logging.warning('Application with the name "%s" already exists.' % new_name)
            return

        app_uid = app.get('record_uid')
        record_key = app.get('record_key_unencrypted')
        revision = app.get('revision')

        data_dict = KSMCommand.record_data_as_dict(app)
        old_name = data_dict.get('title')
        data_dict['title'] = new_name

        data_json = json.dumps(data_dict)
        data_padded = api.pad_aes_gcm(data_json)
        rdata = bytes(data_padded, 'utf-8') if isinstance(data_padded, str) else data_padded
        rdata = crypto.encrypt_aes_v2(rdata, record_key)

        ru = record_pb2.RecordUpdate()
        ru.record_uid = utils.base64_url_decode(app_uid)
        ru.client_modified_time = api.current_milli_time()
        ru.revision = revision
        ru.data = rdata

        rq = api.get_records_update_request(params)
        rq.records.append(ru)

        try:
            rs = api.communicate_rest(params, rq, 'vault/records_update',
                                      rs_type=record_pb2.RecordsModifyResponse)
            record_uid_bytes = utils.base64_url_decode(app_uid)
            rs_status = next((x for x in rs.records if record_uid_bytes == x.record_uid), None)
            if rs_status and rs_status.status != record_pb2.RS_SUCCESS:
                raise KeeperApiError(record_pb2.RecordModifyResult.keys()[rs_status.status], rs_status.message)

            params.sync_data = True
            if format_type == 'json':
                return json.dumps({
                    "app_uid": app_uid,
                    "old_name": old_name,
                    "new_name": new_name,
                    "message": "Application was successfully renamed"
                }, indent=2)
            else:
                print(bcolors.OKGREEN +
                      f'Application "{old_name}" was successfully renamed to "{new_name}" (UID: {app_uid})' +
                      bcolors.ENDC)
        except KeeperApiError as kae:
            logging.error('Failed to update application: %s' % kae.message)
        except Exception as e:
            logging.error('Failed to update application: %s' % str(e))

    @staticmethod
    def update_app_share(params, secret_uids, app_name_or_uid, is_editable):
        """Update the editable permission on secrets already shared with an application.

        Performs a remove + re-add (matching the web vault behaviour) so that
        the encrypted secret key is re-supplied with the new editable flag.
        """
        rec_cache_val = KSMCommand.get_app_record(params, app_name_or_uid)
        if rec_cache_val is None:
            logging.warning('Application "%s" not found.' % app_name_or_uid)
            return

        app_record_uid = rec_cache_val.get('record_uid')
        master_key = rec_cache_val.get('record_key_unencrypted')

        resolved_secret_uids = KSMCommand.resolve_secret_uids(params, secret_uids)
        if not resolved_secret_uids:
            return

        app_info = KSMCommand.get_app_info(params, app_record_uid)
        existing_shares = {
            utils.base64_url_encode(s.secretUid): s
            for ai in app_info for s in (ai.shares or [])
        }

        uids_to_update = []
        nsf_uids_to_update = []
        for uid in resolved_secret_uids:
            secret = KSMCommand.classify_secret(params, uid)
            is_nsf = bool(
                secret and (
                    (secret['share_type'] == 'SHARE_TYPE_FOLDER'
                     and is_nested_share_folder(params, secret['uid']))
                    or (secret['share_type'] == 'SHARE_TYPE_RECORD'
                        and is_nested_share_record(params, secret['uid']))))
            if is_nsf:
                nsf_uids_to_update.append(secret['uid'])
                continue
            if uid not in existing_shares:
                logging.warning('Secret "%s" is not currently shared with this application. '
                                'Use "share add" to add it first.' % uid)
                continue
            current_share = existing_shares[uid]
            if current_share.editable == is_editable:
                perm = "editable" if is_editable else "read-only"
                logging.info('Secret "%s" is already %s. No change needed.' % (uid, perm))
                continue
            uids_to_update.append(uid)

        if not uids_to_update and not nsf_uids_to_update:
            print(bcolors.WARNING + "No share permissions to update." + bcolors.ENDC)
            return

        from ..nested_share_folder.folder_api import update_folder_access_to_application_v3
        from ..nested_share_folder.record_api import update_record_share_to_application_v3

        updated = []
        for uid in nsf_uids_to_update:
            secret = KSMCommand.classify_secret(params, uid)
            if not secret:
                logging.warning('UID "%s" not found in local cache. Run sync-down and try again.' % uid)
                continue
            if secret['share_type'] == 'SHARE_TYPE_FOLDER':
                result = update_folder_access_to_application_v3(
                    params, uid, app_record_uid, is_editable=is_editable)
            else:
                result = update_record_share_to_application_v3(
                    params, uid, app_record_uid, master_key, is_editable=is_editable)
            if not result.get('success'):
                logging.error('Failed to update NSF share "%s": %s',
                              uid, result.get('message') or result)
                continue
            updated.append(uid)

        if uids_to_update:
            rq_remove = APIRequest_pb2.RemoveAppSharesRequest()
            rq_remove.appRecordUid = utils.base64_url_decode(app_record_uid)
            rq_remove.shares.extend(utils.base64_url_decode(uid) for uid in uids_to_update)

            try:
                api.communicate_rest(params, rq_remove, 'vault/app_share_remove')
            except KeeperApiError as kae:
                logging.error('Failed to remove shares for update: %s' % kae.message)
                return

            app_shares = []
            for uid in uids_to_update:
                secret = KSMCommand.classify_secret(params, uid)
                if not secret:
                    logging.warning('UID "%s" not found in local cache. Run sync-down and try again.' % uid)
                    continue

                share_key = secret['share_key']
                share_type = secret['share_type']
                uid = secret['uid']

                encrypted_secret_key = crypto.encrypt_aes_v2(share_key, master_key)

                app_share = APIRequest_pb2.AppShareAdd()
                app_share.secretUid = utils.base64_url_decode(uid)
                app_share.shareType = APIRequest_pb2.ApplicationShareType.Value(share_type)
                app_share.encryptedSecretKey = encrypted_secret_key
                app_share.editable = is_editable

                app_shares.append(app_share)

            if not app_shares and not updated:
                return

            if app_shares:
                rq_add = APIRequest_pb2.AddAppSharesRequest()
                rq_add.appRecordUid = utils.base64_url_decode(app_record_uid)
                rq_add.shares.extend(app_shares)

                try:
                    api.communicate_rest(params, rq_add, 'vault/app_share_add')
                    updated.extend(uids_to_update)
                except KeeperApiError as kae:
                    logging.error('Failed to re-add shares with updated permissions: %s' % kae.message)
                    return

        if updated:
            perm = "editable" if is_editable else "read-only"
            print(bcolors.OKGREEN +
                  f'\nSuccessfully updated share permissions to {perm} for app uid={app_record_uid}:' +
                  bcolors.ENDC)
            for uid in updated:
                print(f'\t{uid}')
            print()

    @staticmethod
    def remove_share(params, app_name_or_uid, secret_uids):
        app = KSMCommand.get_app_record(params, app_name_or_uid)
        if not app:
            raise Exception("KMS App with name or uid '%s' not found" % app_name_or_uid)

        app_uid = app.get('record_uid')

        resolved_uids = KSMCommand.resolve_secret_uids(params, secret_uids)
        if not resolved_uids:
            raise Exception("No valid record or folder secrets were found for removal")

        from ..nested_share_folder.folder_api import revoke_folder_access_from_application_v3
        from ..nested_share_folder.record_api import unshare_record_from_application_v3

        classic_uids = []
        for uid in resolved_uids:
            secret = KSMCommand.classify_secret(params, uid)
            if secret and secret['share_type'] == 'SHARE_TYPE_FOLDER' and is_nested_share_folder(params, uid):
                result = revoke_folder_access_from_application_v3(params, uid, app_uid)
                if not result.get('success'):
                    raise KeeperApiError(
                        result.get('status') or 'access_denied',
                        result.get('message') or f'Failed to remove NSF folder share {uid}')
                continue
            if secret and secret['share_type'] == 'SHARE_TYPE_RECORD' and is_nested_share_record(params, uid):
                result = unshare_record_from_application_v3(params, uid, app_uid)
                if not result.get('success'):
                    message = '; '.join(
                        r.get('message') or r.get('status') or 'revoke failed'
                        for r in result.get('results', [])) or f'Failed to remove NSF record share {uid}'
                    raise KeeperApiError('share_failed', message)
                continue
            classic_uids.append(uid)

        if classic_uids:
            rq = APIRequest_pb2.RemoveAppSharesRequest()
            rq.appRecordUid = utils.base64_url_decode(app_uid)
            rq.shares.extend((utils.base64_url_decode(x) for x in classic_uids))
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
            KSMCommand.remove_client(params, app_name_or_uid, client_ids_to_rem, force=True)

    @staticmethod
    def remove_client(params, app_name_or_uid, client_names_and_hashes, force=False):

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
        
        if not force:
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
    def revoke_client(params, client_ids, force=False):
        """Search all SM applications for matching client IDs and revoke them.

        Accepts clientId values from device config files (standard or URL-safe base64).
        """
        # Normalize input client IDs to URL-safe base64 for comparison
        normalized_inputs = []
        for cid in client_ids:
            # Config files may use standard base64 (+, /, =) or URL-safe base64 (-, _)
            normalized = cid.replace('+', '-').replace('/', '_').rstrip('=')
            normalized_inputs.append(normalized)

        # Collect all SM app UIDs from the vault cache
        app_uids = []
        app_titles = {}
        for rec_cache_val in params.record_cache.values():
            if rec_cache_val.get('version') == 5:
                r_uid = rec_cache_val.get('record_uid')
                try:
                    r_data = json.loads(rec_cache_val.get('data_unencrypted').decode('utf-8'))
                    app_titles[r_uid] = r_data.get('title', r_uid)
                except Exception:
                    app_titles[r_uid] = r_uid
                app_uids.append(r_uid)

        if not app_uids:
            print(bcolors.WARNING + "No Secrets Manager applications found in the vault." + bcolors.ENDC)
            return

        # Fetch app info for all apps in a single API call
        rq = APIRequest_pb2.GetAppInfoRequest()
        for app_uid in app_uids:
            rq.appRecordUid.append(utils.base64_url_decode(app_uid))
        rs = api.communicate_rest(params, rq, 'vault/get_app_info', rs_type=APIRequest_pb2.GetAppInfoResponse)

        # Search for matching clients across all apps
        matches = []  # list of (app_uid, app_title, client_name, client_id_b64, client_id_bytes)
        for ai in rs.appInfo:
            app_uid_str = utils.base64_url_encode(ai.appRecordUid)
            app_title = app_titles.get(app_uid_str, app_uid_str)
            for c in ai.clients:
                client_id_b64 = utils.base64_url_encode(c.clientId)
                for norm_input in normalized_inputs:
                    if client_id_b64 == norm_input or \
                       (len(norm_input) >= KSMCommand.CLIENT_SHORT_ID_LENGTH and client_id_b64.startswith(norm_input)):
                        matches.append((app_uid_str, app_title, c.id, client_id_b64, c.clientId))
                        break

        if not matches:
            print(bcolors.WARNING + "No matching client devices found across any application." + bcolors.ENDC)
            return

        # Display matches and confirm
        print(f"\n{bcolors.BOLD}Found {len(matches)} matching client device(s):{bcolors.ENDC}\n")
        for app_uid_str, app_title, device_name, client_id_b64, _ in matches:
            print(f"  Application: {bcolors.OKGREEN}{app_title}{bcolors.ENDC} ({app_uid_str})")
            print(f"  Device Name: {device_name}")
            print(f"  Client ID:   {client_id_b64[:20]}...")
            print()

        if not force:
            uc = user_choice(f'\tAre you sure you want to revoke {len(matches)} client device(s)?', 'yn', default='n')
            if uc.lower() != 'y':
                return

        # Group matches by app and remove
        sorted_matches = sorted(matches, key=lambda m: m[0])
        for app_uid_str, group in groupby(sorted_matches, key=lambda m: m[0]):
            group_list = list(group)
            app_title = group_list[0][1]
            client_hashes = [m[4] for m in group_list]

            rm_rq = APIRequest_pb2.RemoveAppClientsRequest()
            rm_rq.appRecordUid = utils.base64_url_decode(app_uid_str)
            rm_rq.clients.extend(client_hashes)
            api.communicate_rest(params, rm_rq, 'vault/app_client_remove')
            print(bcolors.OKGREEN + f"Revoked {len(client_hashes)} client(s) from application \"{app_title}\"" + bcolors.ENDC)

        print(bcolors.OKGREEN + "\nClient revocation complete.\n" + bcolors.ENDC)

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

        KSMCommand.validate_ksm_config_dict(config_dict)

        converted_config = KSMCommand.convert_config_dict(config_dict, config_init)

        if include_config_dict:
            return {
                'config_str': converted_config,
                'config_dict': config_dict
            }
        else:
            return converted_config

    @staticmethod
    def validate_ksm_config_dict(config_dict):
        """Verify a freshly generated KSM device config is intact.

        The config is handed out as an opaque base64 blob (gateway install,
        k8s secret) and a corrupted clientId/privateKey only surfaces much
        later as an unusable device, so fail loudly at the source instead.

        Note: if this validation passes but the consumer still receives a
        malformed token, the base64 was most likely mangled by the console -
        lines overwritten/lost during print (wrapped rows, redraws) or a bad
        copy/paste. For comparison capture it losslessly with a redirect:
        pam project import ... > out.json
        """
        required_keys = ('hostname', 'clientId', 'privateKey', 'serverPublicKeyId', 'appKey')
        for key in required_keys:
            value = config_dict.get(key)
            if not value or not isinstance(value, str):
                raise Exception(f'Generated KSM config is invalid: "{key}" is missing or empty. '
                                'Please remove the client device and try again.')
        for key in ('clientId', 'privateKey', 'appKey'):
            try:
                decoded = base64.b64decode(config_dict[key], validate=True)
            except Exception:
                raise Exception(f'Generated KSM config is invalid: "{key}" is not valid base64. '
                                'Please remove the client device and try again.')
            if key == 'clientId' and len(decoded) != 64:  # HMAC-SHA512 digest
                raise Exception(f'Generated KSM config is invalid: "clientId" decodes to '
                                f'{len(decoded)} bytes, expected 64. '
                                'Please remove the client device and try again.')

    @staticmethod
    def convert_config_dict(config_dict, conversion_type='json'):

        config = json.dumps(config_dict)

        if conversion_type in ['b64', 'k8s']:
            encoded = json_to_base64(config)
            # the encoded blob must round-trip to the exact JSON it was built
            # from - catches any corruption before the config is handed out
            if base64.b64decode(encoded).decode('utf-8') != config:
                raise Exception('KSM config base64 encoding failed the integrity check')
            config = encoded

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


