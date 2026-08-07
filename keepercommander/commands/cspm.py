#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import concurrent.futures
import datetime
import json
import logging

from . import base, enterprise_common
from .. import api

# Maximum enterprise_user_ids per dm/device_admin_list call
_DEVICE_BATCH_SIZE = 100


cspm_report_parser = argparse.ArgumentParser(
    prog='cspm-report',
    description='Generate a CSPM/SSPM/GRC posture snapshot of enterprise users.',
    parents=[base.report_output_parser],
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''
Examples:
  # Basic user snapshot (page 1, 1000 users)
  cspm-report --format json

  # Second page of results
  cspm-report --format json --page 2 --page-size 1000

  # Full snapshot including devices, last-login, records, and security scores
  cspm-report --format json --include-devices --include-last-login --include-has-records --include-security-audit

  # Save to file
  cspm-report --format json --include-devices --include-last-login --output cspm_snapshot.json
    ''',
)
cspm_report_parser.add_argument(
    '--page', dest='page', type=int, default=1,
    help='Page number (1-based). Default: 1',
)
cspm_report_parser.add_argument(
    '--page-size', dest='page_size', type=int, default=1000,
    help='Users per page (max 5000). Default: 1000',
)
cspm_report_parser.add_argument(
    '--include-last-login', dest='include_last_login', action='store_true',
    help='Add last_login per user (extra audit-log API call)',
)
cspm_report_parser.add_argument(
    '--include-has-records', dest='include_has_records', action='store_true',
    help='Add has_records and last_logged_in per user (extra RMD API call)',
)
cspm_report_parser.add_argument(
    '--include-security-audit', dest='include_security_audit', action='store_true',
    help='Add security_score per user (extra security-report API call)',
)
cspm_report_parser.add_argument(
    '--include-devices', dest='include_devices', action='store_true',
    help='Add devices list per user — active devices via dm/device_admin_list plus '
         'pending-approval devices already in enterprise data (extra API calls)',
)


def register_commands(commands):
    commands['cspm-report'] = CspmReportCommand()


def register_command_info(aliases, command_info):
    aliases['cspm'] = 'cspm-report'
    command_info['cspm-report'] = 'Generate a CSPM/SSPM/GRC posture snapshot of enterprise users'


def _map_status(user):
    if user.get('status') == 'invited':
        return 'invited'
    lock = user.get('lock', 0)
    if lock == 1:
        return 'locked'
    if lock == 2:
        return 'locked_by_idp'
    return 'active'


def _map_auth_method(user):
    if user.get('status') == 'invited':
        return 'pending'
    key_type = user.get('key_type') or ''
    kt = key_type.lower()
    if kt.startswith('encrypted_by_data_key'):
        return 'master_password'
    if kt.startswith('encrypted_by_public_key'):
        return 'sso'
    return 'pending'


def _ts_to_iso(ts_ms):
    """Convert a millisecond epoch timestamp to an ISO-8601 string, or None."""
    if not ts_ms:
        return None
    try:
        divisor = 1000 if ts_ms > 10_000_000_000 else 1
        return datetime.datetime.fromtimestamp(ts_ms / divisor).isoformat()
    except Exception:
        return str(ts_ms)


def _build_subscription(ent):
    licenses = ent.get('licenses', [])
    if not licenses:
        return {}
    lic = licenses[0]

    add_ons = []
    for ao in lic.get('add_ons', []):
        add_ons.append({
            'name': ao.get('name'),
            'enabled': ao.get('enabled'),
            'seats': ao.get('seats'),
            'expiration': _ts_to_iso(ao.get('expiration')),
        })

    return {
        'seats_purchased': lic.get('number_of_seats'),
        'seats_allocated': lic.get('seats_allocated'),
        'seats_pending': lic.get('seats_pending'),
        'expiration': _ts_to_iso(lic.get('expiration')),
        'add_ons': add_ons,
    }


def _rmd_last_login_from_stats(rmd_map, users):
    """Derive {email_lower: str|None} from an already-fetched RMD stats map.

    Uses last_logged_in from RMD as the authoritative last-login source.
    The audit-log approach (get_audit_event_reports) misses Commander CLI
    and some vault session types, making it unreliable for CSPM staleness checks.
    """
    result = {}
    for u in users:
        key = (u.get('username') or '').lower()
        if u.get('status') == 'invited':
            result[key] = 'N/A'
            continue
        rmd = rmd_map.get(key, {})
        ll = rmd.get('last_logged_in')
        result[key] = ll  # datetime string or None
    return result


def _fetch_rmd_stats(params):
    """Return {email_lower: {has_records, last_logged_in}} from RMD API."""
    from .risk_management import RiskManagementEnterpriseStatDetailsCommand
    cmd = RiskManagementEnterpriseStatDetailsCommand()
    result = {}
    try:
        output = cmd.execute(params, format='json')
        if not output:
            return result
        rows = json.loads(output)
        for row in rows:
            if not isinstance(row, dict) or 'username' not in row:
                continue
            result[(row['username'] or '').lower()] = {
                'has_records': row.get('has_records'),
                'last_logged_in': row.get('last_logged_in'),
            }
    except Exception as e:
        logging.warning('cspm-report: RMD fetch failed: %s', e)
    return result


def _fetch_security_scores(params):
    """Return {email_lower: score} from enterprise security report."""
    from .security_audit import SecurityAuditReportCommand
    cmd = SecurityAuditReportCommand()
    result = {}
    try:
        output = cmd.execute(params, format='json')
        if not output:
            return result
        rows = json.loads(output)
        for row in rows:
            if not isinstance(row, dict) or 'email' not in row:
                continue
            result[(row['email'] or '').lower()] = row.get('securityScore')
    except Exception as e:
        logging.warning('cspm-report: security-audit fetch failed: %s', e)
    return result


def _fetch_devices(params, user_ids=None):
    """Return {enterprise_user_id: [device_dict, ...]} for the given user IDs.

    Active devices come from dm/device_admin_list (batches fired concurrently).
    Pending-approval devices come from params.enterprise with no extra API call.
    Pass user_ids to scope the fetch to a specific set (e.g. the current page).
    """
    from ..proto import DeviceManagement_pb2
    from .device_management import StatusMapper, UICategory

    if user_ids is None:
        user_ids = [u['enterprise_user_id'] for u in params.enterprise.get('users', [])]

    uid_set = set(user_ids)
    devices_by_uid = {}  # enterprise_user_id -> [device_dict]

    # --- Active / approved devices via dm/device_admin_list (concurrent batches) ---
    batches = [user_ids[i:i + _DEVICE_BATCH_SIZE] for i in range(0, len(user_ids), _DEVICE_BATCH_SIZE)]

    def _fetch_batch(batch):
        rq = DeviceManagement_pb2.DeviceAdminRequest()
        rq.enterpriseUserIds.extend(batch)
        return api.communicate_rest(
            params, rq, 'dm/device_admin_list',
            rs_type=DeviceManagement_pb2.DeviceAdminResponse,
        )

    if batches:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(batches), 10)) as pool:
            future_to_batch = {pool.submit(_fetch_batch, b): b for b in batches}
            for future in concurrent.futures.as_completed(future_to_batch):
                try:
                    rs = future.result()
                except Exception as e:
                    logging.warning('cspm-report: dm/device_admin_list failed: %s', e)
                    continue
                for device_user in rs.deviceUserList:
                    uid = device_user.enterpriseUserId
                    for device_group in device_user.deviceGroups:
                        for device in device_group.devices:
                            devices_by_uid.setdefault(uid, []).append({
                                'device_name': device.deviceName or None,
                                'client_version': device.clientVersion or None,
                                'device_platform': device.devicePlatform or None,
                                'device_category': UICategory.get_ui_category(device),
                                'device_status': StatusMapper.get_device_status_display(device.deviceStatus),
                                'login_state': StatusMapper.get_login_status_display(device.loginState),
                                'last_modified': _ts_to_iso(device.lastModifiedTime),
                                'ip_address': None,
                                'location': None,
                            })

    # --- Pending-approval devices already in params.enterprise (no extra API call) ---
    for pending in params.enterprise.get('devices_request_for_admin_approval', []):
        uid = pending.get('enterprise_user_id')
        if uid is None or uid not in uid_set:
            continue
        ts_ms = pending.get('date')
        devices_by_uid.setdefault(uid, []).append({
            'device_name': pending.get('device_name'),
            'client_version': pending.get('client_version'),
            'device_platform': None,
            'device_category': pending.get('device_type'),
            'device_status': 'NEEDS_APPROVAL',
            'login_state': None,
            'last_modified': _ts_to_iso(ts_ms),
            'ip_address': pending.get('ip_address'),
            'location': pending.get('location'),
        })

    return devices_by_uid


class CspmReportCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return cspm_report_parser

    def execute(self, params, **kwargs):
        ent = params.enterprise

        # Build lookup indexes from enterprise data (no extra API calls)
        role_map = {
            r['role_id']: (r.get('data') or {}).get('displayname') or str(r['role_id'])
            for r in ent.get('roles', [])
        }
        team_map = {
            t['team_uid']: t.get('name') or t['team_uid']
            for t in ent.get('teams', [])
        }

        user_role_map = {}   # enterprise_user_id -> {role_id}
        for ru in ent.get('role_users', []):
            user_role_map.setdefault(ru['enterprise_user_id'], set()).add(ru['role_id'])

        user_team_map = {}   # enterprise_user_id -> {team_uid}
        for tu in ent.get('team_users', []):
            user_team_map.setdefault(tu['enterprise_user_id'], set()).add(tu['team_uid'])

        admin_role_ids = {mn['role_id'] for mn in ent.get('managed_nodes', [])}

        role_privileges_map = {}   # role_id -> [privilege]
        for rp in ent.get('role_privileges', []):
            role_privileges_map.setdefault(rp['role_id'], []).append(rp['privilege'])

        role_enforcements_map = {
            re['role_id']: re.get('enforcements', {})
            for re in ent.get('role_enforcements', [])
        }

        subscription = _build_subscription(ent)

        users = ent.get('users', [])
        total = len(users)

        page = max(1, kwargs.get('page', 1))
        page_size = max(1, min(kwargs.get('page_size', 1000), 5000))
        start = (page - 1) * page_size
        end = start + page_size
        page_users = users[start:end]
        page_user_ids = [u['enterprise_user_id'] for u in page_users]

        need_rmd = kwargs.get('include_last_login') or kwargs.get('include_has_records')
        need_security = kwargs.get('include_security_audit')
        need_devices = kwargs.get('include_devices')

        rmd_map = {}
        security_score_map = {}
        devices_map = {}

        # Fire all optional supplemental calls concurrently — they hit independent endpoints.
        # Devices are scoped to page_user_ids to avoid fetching the entire enterprise on every page.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            pending = {}
            if need_rmd:
                pending['rmd'] = pool.submit(_fetch_rmd_stats, params)
            if need_security:
                pending['security'] = pool.submit(_fetch_security_scores, params)
            if need_devices:
                pending['devices'] = pool.submit(_fetch_devices, params, page_user_ids)

            for key, fut in pending.items():
                try:
                    result = fut.result()
                    if key == 'rmd':
                        rmd_map = result
                    elif key == 'security':
                        security_score_map = result
                    elif key == 'devices':
                        devices_map = result
                except Exception as e:
                    logging.warning('cspm-report: %s fetch failed: %s', key, e)

        last_login_map = {}
        if kwargs.get('include_last_login'):
            last_login_map = _rmd_last_login_from_stats(rmd_map, users)

        user_records = []
        for user in page_users:
            uid = user['enterprise_user_id']
            user_role_ids = user_role_map.get(uid, set())
            user_team_uids = user_team_map.get(uid, set())

            is_admin = bool(user_role_ids & admin_role_ids)

            admin_permissions = []
            if is_admin:
                seen = set()
                for rid in (user_role_ids & admin_role_ids):
                    for priv in role_privileges_map.get(rid, []):
                        if priv not in seen:
                            seen.add(priv)
                            admin_permissions.append(priv)

            enforcements = {}
            for rid in user_role_ids:
                enforcements.update(role_enforcements_map.get(rid, {}))

            record = {
                'email': user.get('username'),
                'user_id': uid,
                'status': _map_status(user),
                'is_admin': is_admin,
                'auth_method': _map_auth_method(user),
                'tfa_enabled': bool(user.get('tfa_enabled', False)),
                'roles': sorted(role_map.get(rid, str(rid)) for rid in user_role_ids),
                'teams': sorted(team_map.get(tuid, str(tuid)) for tuid in user_team_uids),
                'admin_permissions': admin_permissions,
                'role_enforcements': enforcements,
            }

            if kwargs.get('include_last_login'):
                email_key = (user.get('username') or '').lower()
                record['last_login'] = last_login_map.get(email_key)

            if kwargs.get('include_has_records'):
                rmd = rmd_map.get((user.get('username') or '').lower(), {})
                record['has_records'] = rmd.get('has_records')
                last_logged_in = rmd.get('last_logged_in')
                record['last_logged_in'] = (
                    last_logged_in.isoformat()
                    if isinstance(last_logged_in, datetime.datetime)
                    else last_logged_in
                )

            if kwargs.get('include_security_audit'):
                email_key = (user.get('username') or '').lower()
                record['security_score'] = security_score_map.get(email_key)

            if kwargs.get('include_devices'):
                record['devices'] = devices_map.get(uid, [])

            user_records.append(record)

        fmt = kwargs.get('format') or 'json'
        output_file = kwargs.get('output')

        if fmt == 'json':
            payload = {
                'total': total,
                'page': page,
                'page_size': page_size,
                'has_more': end < total,
                'subscription': subscription,
                'users': user_records,
            }
            json_str = json.dumps(payload, indent=2, default=str)
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(json_str)
            return json_str

        # Table / CSV fallback: one row per user, flat columns (devices omitted in table mode)
        headers = [
            'email', 'user_id', 'status', 'is_admin', 'auth_method',
            'tfa_enabled', 'roles', 'teams',
        ]
        if kwargs.get('include_last_login'):
            headers.append('last_login')
        if kwargs.get('include_has_records'):
            headers.extend(['has_records', 'last_logged_in'])
        if kwargs.get('include_security_audit'):
            headers.append('security_score')
        if kwargs.get('include_devices'):
            headers.append('device_count')
            for r in user_records:
                r['device_count'] = len(r.get('devices', []))

        rows = [[r.get(h) for h in headers] for r in user_records]
        return base.dump_report_data(
            rows,
            headers=[base.field_to_title(h) for h in headers],
            fmt=fmt,
            filename=output_file,
        )
