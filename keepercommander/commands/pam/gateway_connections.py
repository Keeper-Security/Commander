"""List active connections reported by the enterprise-scoped router.

The data comes from the router's ``/api/user/get_controllers`` call (the same
call used by ``pam gateway list``). The router scopes it to the enterprise;
the router worker host and stopping a connection are not exposed by the user
API.
"""

import argparse
import datetime
import json
import logging
import os
import sys
import time

import requests

from ... import utils, vault
from ...display import bcolors
from ...error import CommandError
from ...proto import pam_pb2
from ..base import Command, dump_report_data, report_output_parser, user_choice
from . import gateway_helper, router_helper
from .pam_dto import GatewayAction, GatewayActionWebRTCSession


_COMMAND = 'pam gateway connections'
_DEFAULT_FIELDS = (
    'gateway_name', 'gateway_uid', 'connection_type', 'user', 'record_title',
    'record_uid', 'started_on', 'duration_seconds', 'connection_uid',
)
_VERBOSE_FIELDS = ('gateway_instance_ip', 'configuration_uid', 'gateway_version')
_TABLE_COLUMNS = ('gateway_name', 'short_id', 'connection_type', 'user', 'record', 'started_on', 'duration_seconds')
_TABLE_VERBOSE_COLUMNS = (
    'gateway_uid', 'record_uid', 'connection_uid', 'gateway_instance_ip', 'configuration_uid', 'gateway_version',
)
_TABLE_HEADERS = {
    'short_id': 'ID',
    'gateway_name': 'Gateway',
    'connection_type': 'Type',
    'user': 'User',
    'record': 'Record',
    'started_on': 'Started',
    'duration_seconds': 'Duration',
    'gateway_uid': 'Gateway UID',
    'record_uid': 'Record UID',
    'connection_uid': 'Connection UID',
    'gateway_instance_ip': 'Gateway Instance IP',
    'configuration_uid': 'PAM Configuration UID',
    'gateway_version': 'Gateway Version',
}
_MIN_ID_LENGTH = 4
# Columns shortened, in this order, when the table is wider than the terminal.
_SHRINKABLE_COLUMNS = ('record', 'gateway_name', 'user')


def _now_ms():
    # type: () -> int
    return int(time.time() * 1000)


def _enum_names():
    # type: () -> set
    enum_descriptor = pam_pb2.DESCRIPTOR.enum_types_by_name['WebRtcConnectionType']
    return {value.name.lower(): value.number for value in enum_descriptor.values}


def _connection_type(value):
    # type: (int) -> str
    try:
        return pam_pb2.WebRtcConnectionType.Name(value).lower()
    except ValueError:
        return 'unknown'


def _record_title(params, record_uid):
    # type: (object, str) -> str | None
    try:
        record = vault.KeeperRecord.load(params, record_uid)
        return record.title if record else None
    except Exception as exc:  # noqa: BLE001 - vault lookup is best effort
        logging.debug('Unable to resolve record title for %s: %s', record_uid, exc)
        return None


def _iso_time(epoch_ms):
    # type: (int) -> str | None
    if not epoch_ms:
        return None
    return datetime.datetime.fromtimestamp(epoch_ms / 1000, datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%SZ')


def _duration_seconds(epoch_ms):
    # type: (int) -> int | None
    if not epoch_ms:
        return None
    return max(0, int((_now_ms() - epoch_ms) / 1000))


def _gateway_lookup(gateways):
    # type: (list) -> dict
    return {gateway.controllerUid: gateway for gateway in gateways}


def build_connection_rows(online_controllers, gateways, params, user=None, connection_type=None):
    # type: (object, list, object, str | None, str | None) -> tuple
    """Build sorted, deduplicated connection dictionaries from protobuf data."""
    gateway_by_uid = _gateway_lookup(gateways)
    rows = []
    seen = set()
    duplicate_count = 0
    wanted_user = user.strip().casefold() if user else None
    for controller in online_controllers or []:
        gateway_uid = utils.base64_url_encode(controller.controllerUid)
        gateway = gateway_by_uid.get(controller.controllerUid)
        gateway_name = gateway.controllerName if gateway else gateway_uid
        for connection in controller.connections:
            key = (gateway_uid, utils.base64_url_encode(connection.connectionUid))
            if key in seen:
                duplicate_count += 1
                continue
            seen.add(key)
            name = _connection_type(connection.type)
            if connection_type and name != connection_type:
                continue
            if wanted_user and connection.userName.strip().casefold() != wanted_user:
                continue
            record_uid = utils.base64_url_encode(connection.recordUid)
            rows.append({
                'gateway_name': gateway_name,
                'gateway_uid': gateway_uid,
                'connection_type': name,
                'user': connection.userName,
                'record_title': _record_title(params, record_uid),
                'record_uid': record_uid,
                'started_on': _iso_time(connection.startedOn),
                'duration_seconds': _duration_seconds(connection.startedOn),
                'connection_uid': utils.base64_url_encode(connection.connectionUid),
                'gateway_instance_ip': controller.ipAddress,
                'configuration_uid': utils.base64_url_encode(connection.configurationUid),
                'gateway_version': controller.version,
                '_started_ms': connection.startedOn,
            })
    if duplicate_count:
        logging.debug('%d duplicate connection entries from router were hidden', duplicate_count)
    return rows, duplicate_count


def _human_duration(seconds):
    # type: (int | None) -> str
    if seconds is None:
        return ''
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    if days:
        return f'{days}d {hours:02d}h'
    if hours:
        return f'{hours}h {minutes:02d}m'
    if minutes:
        return f'{minutes}m {secs:02d}s'
    return f'{secs}s'


def _fields(is_verbose):
    # type: (bool) -> list
    fields = list(_DEFAULT_FIELDS)
    if is_verbose:
        fields.extend(_VERBOSE_FIELDS)
    return fields


def _table_columns(is_verbose):
    # type: (bool) -> list
    # The default table keeps to columns a person reads; UIDs are for -v, json and csv.
    columns = list(_TABLE_COLUMNS)
    if is_verbose:
        columns.extend(_TABLE_VERBOSE_COLUMNS)
    return columns


def _started_label(started_ms, today):
    # type: (int, datetime.date) -> str
    if not started_ms:
        return ''
    started = datetime.datetime.fromtimestamp(started_ms / 1000)
    return started.strftime('%H:%M:%S' if started.date() == today else '%Y-%m-%d %H:%M')


_DIM = '\033[2m'
_CYAN = '\033[36m'
_TYPE_COLORS = {
    'ssh': bcolors.OKGREEN, 'telnet': bcolors.OKGREEN,
    'rdp': bcolors.OKBLUE, 'vnc': bcolors.OKBLUE,
    'http': bcolors.HEADER,
    'tunnel': bcolors.WARNING,
    'mysql': _CYAN, 'sql_server': _CYAN, 'postgresql': _CYAN, 'kubernetes': _CYAN,
}
_LONG_SESSION_SECONDS = 8 * 3600


def _use_color():
    # type: () -> bool
    return sys.stdout.isatty() and not os.environ.get('NO_COLOR')


def _paint(value, color, use_color):
    # type: (str, str | None, bool) -> str
    return f'{color}{value}{bcolors.ENDC}' if use_color and color and value else value


def _duration_color(seconds):
    # type: (int | None) -> str | None
    # Long-running sessions are what an admin scanning this list usually looks for.
    if seconds is None:
        return None
    if seconds >= _LONG_SESSION_SECONDS:
        return bcolors.FAIL
    if seconds >= 3600:
        return bcolors.WARNING
    return bcolors.OKGREEN


def _short_ids(rows):
    # type: (list) -> dict
    """Shortest prefix, at least _MIN_ID_LENGTH long, that tells each listed connection UID apart."""
    uids = sorted({row['connection_uid'] for row in rows})
    short = {}
    for index, uid in enumerate(uids):
        neighbours = uids[max(index - 1, 0):index] + uids[index + 1:index + 2]
        length = _MIN_ID_LENGTH
        for other in neighbours:
            common = len(os.path.commonprefix([uid, other]))
            length = max(length, common + 1)
        short[uid] = uid[:length]
    return short


def _table_value(row, column, today, use_color):
    # type: (dict, str, datetime.date, bool) -> str
    if column == 'short_id':
        return _paint(row['short_id'], bcolors.OKBLUE, use_color)
    if column == 'gateway_name':
        return _paint(row['gateway_name'], bcolors.BOLD, use_color)
    if column == 'connection_type':
        return _paint(row['connection_type'], _TYPE_COLORS.get(row['connection_type']), use_color)
    if column == 'record':
        if row['record_title']:
            return row['record_title']
        return _paint(row['record_uid'], _DIM, use_color)
    if column == 'started_on':
        return _paint(_started_label(row['_started_ms'], today), _DIM, use_color)
    if column == 'duration_seconds':
        seconds = row['duration_seconds']
        return _paint(_human_duration(seconds), _duration_color(seconds), use_color)
    value = row[column]
    return '' if value is None else str(value)


def _print_table(rows, is_verbose):
    # type: (list, bool) -> bool
    use_color = _use_color()
    columns = _table_columns(is_verbose)
    headers = [_TABLE_HEADERS[column] for column in columns]
    today = datetime.date.today()
    short = _short_ids(rows)
    rows = [dict(row, short_id=short[row['connection_uid']]) for row in rows]
    data = [[_table_value(row, column, today, use_color) for column in columns] for row in rows]
    # -v is the full detail view, so it is never truncated
    shrink = None if is_verbose else [columns.index(column) for column in _SHRINKABLE_COLUMNS]
    dump_report_data(data, headers, fmt='table', row_number=False, group_by=columns.index('gateway_name'),
                     right_align=columns.index('duration_seconds'), shrink_columns=shrink)
    return use_color


def _dump_json(rows, fields, filename):
    # type: (list, list, str | None) -> str | None
    # Built directly rather than via dump_report_data, which drops null values;
    # keys stay stable and in column order so the output is safe to script against.
    report = json.dumps([{field: row[field] for field in fields} for row in rows], indent=2)
    if not filename:
        return report
    if not os.path.splitext(filename)[1]:
        filename += '.json'
    logging.info('Report path: %s', os.path.abspath(filename))
    with open(filename, 'w') as fd:
        fd.write(report)
    return None


class PAMGatewayConnectionsCommand(Command):
    parser = argparse.ArgumentParser(
        prog=_COMMAND,
        parents=[report_output_parser],
        description='List active connections (sessions and tunnels) on PAM Gateways',
    )
    parser.add_argument('gateway', nargs='?', help='Gateway UID or name')
    parser.add_argument('--user', '-u', dest='user', help='Exact Keeper user email')
    parser.add_argument('--type', '-t', dest='connection_type', help='Connection type')
    parser.add_argument('--verbose', '-v', dest='is_verbose', action='store_true',
                        help='Include gateway instance details')

    def get_parser(self):
        return self.parser

    def _resolve_gateway(self, gateways, selector):
        # type: (list, str | None) -> tuple
        if not selector:
            return None
        uid_matches = [g for g in gateways if utils.base64_url_encode(g.controllerUid) == selector]
        if uid_matches:
            return uid_matches[0]
        name_matches = [g for g in gateways if g.controllerName == selector]
        if not name_matches:
            raise CommandError(_COMMAND, f'Gateway "{selector}" not found')
        if len(name_matches) > 1:
            uids = ', '.join(utils.base64_url_encode(g.controllerUid) for g in name_matches)
            raise CommandError(_COMMAND, f'Gateway name "{selector}" is ambiguous; use a UID ({uids})')
        return name_matches[0]

    def execute(self, params, **kwargs):
        # type: (object, **object) -> str | None
        format_type = kwargs.get('format', 'table')
        is_verbose = kwargs.get('is_verbose', False)
        selector = kwargs.get('gateway')
        try:
            online = router_helper.router_get_connected_gateways(params)
        except requests.exceptions.ConnectionError:
            url = router_helper.get_router_url(params)
            raise CommandError(_COMMAND, f'Unable to reach Keeper Router at {url}')
        gateways = list(gateway_helper.get_all_gateways(params) or [])
        selected = self._resolve_gateway(gateways, selector)
        online_controllers = list(online.controllers) if online else []
        if selected:
            selected_instances = [c for c in online_controllers if c.controllerUid == selected.controllerUid]
            if not selected_instances:
                logging.warning(f'Gateway "{selected.controllerName}" ({utils.base64_url_encode(selected.controllerUid)}) is offline')
            online_controllers = selected_instances
        normalized_type = kwargs.get('connection_type')
        if normalized_type:
            normalized_type = normalized_type.strip().lower().replace('-', '_')
            valid_types = set(_enum_names()) | {'unknown'}
            if normalized_type not in valid_types:
                valid = ', '.join(sorted(valid_types))
                raise CommandError(_COMMAND, f'Invalid connection type "{normalized_type}". Valid values: {valid}')
        rows, duplicate_count = build_connection_rows(
            online_controllers, gateways, params, kwargs.get('user'), normalized_type)
        if is_verbose and duplicate_count:
            logging.info(f'{duplicate_count} duplicate connection entries from router were hidden')
        rows.sort(key=lambda row: (row['gateway_name'].casefold(), row['_started_ms'] is None,
                                   row['_started_ms'] or 0))
        fields = _fields(is_verbose)
        if not rows:
            if format_type == 'table':
                message = 'No active connections.'
                if selected:
                    message = f'{message[:-1]} on gateway "{selected.controllerName}".'
                print(message)
                return None
            if format_type == 'json':
                return _dump_json([], fields, kwargs.get('output'))
            return dump_report_data([], fields, fmt=format_type, filename=kwargs.get('output'), row_number=False)
        if format_type == 'table':
            use_color = _print_table(rows, is_verbose)
            gateway_count = len({row['gateway_uid'] for row in rows})
            summary = (f"{len(rows)} active connection{'s' if len(rows) != 1 else ''} on "
                       f"{gateway_count} gateway{'s' if gateway_count != 1 else ''}")
            print(_paint(summary, _DIM, use_color))
            return None
        if format_type == 'json':
            return _dump_json(rows, fields, kwargs.get('output'))
        data = [[row[field] for field in fields] for row in rows]
        return dump_report_data(data, fields, fmt=format_type, filename=kwargs.get('output'), row_number=False)


# Close reason the gateway records for a session stopped by an administrator.
_ADMIN_CLOSED_REASON = 12
_DISCONNECT_COMMAND = 'pam gateway disconnect'
_DISCONNECT_CHECK_SECONDS = 10


def _find_connections(online, selector):
    # type: (object, str) -> list
    """Return [(controller, connection)] whose UID equals selector or, failing that, starts with it.
    The router can list one connection more than once, so matches are unique by connection UID."""
    matches = {}
    for controller in (online.controllers if online else []):
        for connection in controller.connections:
            uid = utils.base64_url_encode(connection.connectionUid)
            if uid.startswith(selector):
                matches.setdefault(uid, (controller, connection))
    if selector in matches:
        return [matches[selector]]
    return list(matches.values())


def _is_connection_active(params, connection_uid):
    # type: (object, str) -> bool
    online = router_helper.router_get_connected_gateways(params)
    return any(utils.base64_url_encode(c.connectionUid) == connection_uid
               for controller in (online.controllers if online else []) for c in controller.connections)


class PAMGatewayDisconnectCommand(Command):
    parser = argparse.ArgumentParser(
        prog=_DISCONNECT_COMMAND,
        description='Stop an active connection (session or tunnel) on a PAM Gateway. '
                    'Use the ID column of "pam gateway connections", or any unique prefix of the connection UID.',
    )
    parser.add_argument('connection_uid', help='Connection UID, or a unique prefix of it (the ID column)')
    parser.add_argument('--force', '-f', dest='force', action='store_true', help='Do not ask for confirmation')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        connection_uid = (kwargs.get('connection_uid') or '').strip()
        try:
            online = router_helper.router_get_connected_gateways(params)
        except requests.exceptions.ConnectionError:
            url = router_helper.get_router_url(params)
            raise CommandError(_DISCONNECT_COMMAND, f'Unable to reach Keeper Router at {url}')
        if len(connection_uid) < _MIN_ID_LENGTH:
            raise CommandError(_DISCONNECT_COMMAND,
                               f'Give at least {_MIN_ID_LENGTH} characters of the connection UID')
        matches = _find_connections(online, connection_uid)
        if not matches:
            raise CommandError(_DISCONNECT_COMMAND, f'No active connection matches "{connection_uid}"')
        if len(matches) > 1:
            listed = '; '.join(f'{utils.base64_url_encode(c.connectionUid)} ({_connection_type(c.type)}, {c.userName})'
                               for _, c in matches)
            raise CommandError(_DISCONNECT_COMMAND, f'"{connection_uid}" matches {len(matches)} connections: '
                                                    f'{listed}. Type more characters of the connection UID.')
        controller, connection = matches[0]
        connection_uid = utils.base64_url_encode(connection.connectionUid)

        gateway_uid = utils.base64_url_encode(controller.controllerUid)
        gateway = next((g for g in (gateway_helper.get_all_gateways(params) or [])
                        if g.controllerUid == controller.controllerUid), None)
        record_uid = utils.base64_url_encode(connection.recordUid)
        record = _record_title(params, record_uid) or record_uid
        print(f'Connection: {connection_uid}')
        print(f'Gateway:  {gateway.controllerName if gateway else gateway_uid}')
        print(f'Type:     {_connection_type(connection.type)}')
        print(f'User:     {connection.userName}')
        print(f'Record:   {record}')
        print(f'Started:  {_iso_time(connection.startedOn) or ""} ({_human_duration(_duration_seconds(connection.startedOn))} ago)')
        if not kwargs.get('force'):
            answer = user_choice('Disconnect this connection?', 'yn', default='n')
            if answer.lower() != 'y':
                print('Cancelled.')
                return

        # The gateway knows the session by its conversation ID, which is the connection UID. The router
        # parses every webrtc-session message as a connect request, so recordUid and conversationType are
        # required even for a disconnect.
        action = GatewayActionWebRTCSession(
            conversation_id=connection_uid,
            message_id=GatewayAction.conversation_id_to_message_id(connection_uid),
            inputs={
                'kind': 'disconnect',
                'recordUid': record_uid,
                'conversationType': _connection_type(connection.type).replace('_', '-'),
                'closeConnectionReason': _ADMIN_CLOSED_REASON,
            },
        )
        try:
            router_helper.router_send_action_to_gateway(
                params=params, gateway_action=action, message_type=pam_pb2.CMT_CONNECT, is_streaming=False,
                destination_gateway_uid_str=gateway_uid)
        except Exception as exc:  # noqa: BLE001 - router errors arrive as plain Exceptions
            raise CommandError(_DISCONNECT_COMMAND, f'Gateway did not accept the disconnect: {exc}')

        # The gateway acknowledges before the session is torn down, and in a gateway pool the router
        # may deliver the request to an instance that does not hold the session. Confirm it is gone.
        deadline = time.time() + _DISCONNECT_CHECK_SECONDS
        while time.time() < deadline:
            time.sleep(1)
            if not _is_connection_active(params, connection_uid):
                print(f'{bcolors.OKGREEN}Connection {connection_uid} disconnected.{bcolors.ENDC}')
                return
        print(f'{bcolors.WARNING}The gateway accepted the request, but connection {connection_uid} is still listed '
              f'as active after {_DISCONNECT_CHECK_SECONDS} seconds. Run "pam gateway connections" to check again.'
              f'{bcolors.ENDC}')
