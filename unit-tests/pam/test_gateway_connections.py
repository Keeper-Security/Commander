#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_||_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com

import io
import itertools
import json
import os
import re
import unittest
from unittest.mock import MagicMock, patch

import requests

from keepercommander.commands.base import _truncate_visible, dump_report_data
from keepercommander.commands.discoveryrotation import PAMGatewayCommand
from keepercommander.commands.pam.gateway_connections import (
    PAMGatewayConnectionsCommand, PAMGatewayDisconnectCommand, build_connection_rows)
from keepercommander.error import CommandError
from keepercommander.proto import pam_pb2


def _gateway(uid, name):
    return pam_pb2.PAMController(controllerUid=uid, controllerName=name)


def _online(uid, connection_uid, started, connection_type, user='user@example.com', record_uid=b'record'):
    controller = pam_pb2.PAMOnlineController(
        controllerUid=uid, ipAddress='10.0.0.1', version='1;linux;release;machine;osver')
    controller.connections.add(
        connectionUid=connection_uid, type=connection_type, recordUid=record_uid,
        userName=user, startedOn=started, configurationUid=b'config')
    return controller


class TestPAMGatewayConnectionsCommand(unittest.TestCase):
    def setUp(self):
        self.params = MagicMock()
        self.command = PAMGatewayConnectionsCommand()
        self.gateways = [_gateway(b'gw-a', 'Alpha'), _gateway(b'gw-b', 'Beta')]
        self.online = pam_pb2.PAMOnlineControllers()
        self.online.controllers.extend([
            _online(b'gw-b', b'conn-b', 2000, pam_pb2.RDP),
            _online(b'gw-a', b'conn-a', 1000, pam_pb2.SSH),
        ])

    def _execute(self, **kwargs):
        with patch('keepercommander.commands.pam.gateway_connections.router_helper.router_get_connected_gateways',
                   return_value=self.online), patch(
                       'keepercommander.commands.pam.gateway_connections.gateway_helper.get_all_gateways',
                       return_value=self.gateways), patch(
                           'keepercommander.commands.pam.gateway_connections._now_ms', return_value=6000), patch(
                               'keepercommander.commands.pam.gateway_connections.vault.KeeperRecord.load',
                               side_effect=KeyError('missing')):
            return self.command.execute(self.params, format='json', **kwargs)

    def test_lists_sorted_connections_and_json_shape(self):
        result = json.loads(self._execute())
        self.assertEqual([row['gateway_name'] for row in result], ['Alpha', 'Beta'])
        self.assertEqual(result[0]['connection_type'], 'ssh')
        self.assertEqual(result[0]['record_uid'], 'cmVjb3Jk')
        self.assertTrue(result[0]['started_on'].endswith('Z'))
        self.assertEqual(result[0]['duration_seconds'], 5)
        self.assertIsNone(result[0]['record_title'])
        self.assertEqual(set(result[0]), {
            'gateway_name', 'gateway_uid', 'connection_type', 'user', 'record_title',
            'record_uid', 'started_on', 'duration_seconds', 'connection_uid',
        })

    def test_filters_type_and_user(self):
        result = json.loads(self._execute(connection_type='sql-server', user=' USER@EXAMPLE.COM '))
        self.assertEqual(result, [])
        self.online.controllers[0].connections[0].type = pam_pb2.SQL_SERVER
        result = json.loads(self._execute(connection_type='sql-server', user=' USER@EXAMPLE.COM '))
        self.assertEqual(len(result), 1)

    def test_invalid_type_and_unknown_enum(self):
        self.online.controllers[0].connections[0].type = -1
        result = json.loads(self._execute(connection_type='unknown'))
        self.assertEqual(result[0]['connection_type'], 'unknown')
        with self.assertRaisesRegex(CommandError, 'Valid values'):
            self._execute(connection_type='not-a-type')

    def test_duplicate_connections_are_hidden(self):
        self.online.controllers.append(self.online.controllers[0])
        with self.assertLogs(level='DEBUG') as logs:
            result = json.loads(self._execute())
        self.assertEqual(len(result), 2)
        self.assertTrue(any('duplicate connection entries' in line for line in logs.output))

    def test_pool_instances_keep_distinct_connections_and_verbose_ip(self):
        pool = _online(b'gw-a', b'conn-c', 3000, pam_pb2.HTTP)
        pool.ipAddress = '10.0.0.2'
        self.online.controllers.append(pool)
        result = json.loads(self._execute(is_verbose=True))
        self.assertEqual({row['gateway_instance_ip'] for row in result}, {'10.0.0.1', '10.0.0.2'})

    def test_gateway_selectors_and_errors(self):
        self.assertEqual(len(json.loads(self._execute(gateway='Alpha'))), 1)
        self.assertEqual(len(json.loads(self._execute(gateway='Z3ctYQ'))), 1)
        with self.assertRaises(CommandError):
            self._execute(gateway='missing')

    def test_ambiguous_gateway_name(self):
        self.gateways.append(_gateway(b'gw-c', 'Alpha'))
        with self.assertRaises(CommandError):
            self._execute(gateway='Alpha')

    def test_online_gateway_missing_from_keeper_api_is_kept(self):
        self.online.controllers[0].controllerUid = b'not-in-ka'
        result = json.loads(self._execute())
        self.assertIn('bm90LWluLWth', [row['gateway_name'] for row in result])

    def test_offline_gateway_is_empty(self):
        del self.online.controllers[:]
        with self.assertLogs(level='WARNING'):
            result = self._execute(gateway='Alpha')
        self.assertEqual(result, '[]')

    def test_router_down_is_command_error(self):
        with patch('keepercommander.commands.pam.gateway_connections.router_helper.router_get_connected_gateways',
                   side_effect=requests.exceptions.ConnectionError), patch(
                       'keepercommander.commands.pam.gateway_connections.router_helper.get_router_url',
                       return_value='https://router.example'):
            with self.assertRaisesRegex(CommandError, 'Unable to reach Keeper Router'):
                self.command.execute(self.params, format='json')

    def test_record_title_is_looked_up_by_string_uid(self):
        # KeeperRecord.load only resolves str UIDs from the record cache; raw bytes return None.
        def load(_params, uid):
            return MagicMock(title='Linux bastion') if uid == 'cmVjb3Jk' else None
        with patch('keepercommander.commands.pam.gateway_connections.vault.KeeperRecord.load', side_effect=load):
            rows, _ = build_connection_rows(self.online.controllers, self.gateways, MagicMock())
        self.assertEqual({row['record_title'] for row in rows}, {'Linux bastion'})

    def _table_lines(self, columns, **kwargs):
        output = io.StringIO()
        with patch('keepercommander.commands.pam.gateway_connections.router_helper.router_get_connected_gateways',
                   return_value=self.online), patch(
                       'keepercommander.commands.pam.gateway_connections.gateway_helper.get_all_gateways',
                       return_value=self.gateways), patch(
                           'keepercommander.commands.pam.gateway_connections._record_title',
                           return_value='Production SSH Machine with Password Access (AI:On)'), patch(
                               'keepercommander.commands.base.shutil.get_terminal_size',
                               return_value=os.terminal_size((columns, 24))), patch('sys.stdout', output):
            PAMGatewayConnectionsCommand().execute(MagicMock(), **kwargs)
        return output.getvalue().splitlines()

    def test_table_fits_terminal_width_and_hides_uids(self):
        lines = self._table_lines(90)
        self.assertLessEqual(max(len(line) for line in lines), 89)
        self.assertNotIn('Connection UID', lines[0])
        self.assertIn('...', '\n'.join(lines))

    def test_wide_terminal_and_verbose_are_not_truncated(self):
        self.assertNotIn('...', '\n'.join(self._table_lines(300)))
        verbose = self._table_lines(60, is_verbose=True)
        self.assertIn('Connection UID', verbose[0])
        self.assertIn('(AI:On)', '\n'.join(verbose))

    def test_dump_report_data_shrink_columns_is_opt_in(self):
        data = [['gw', 'x' * 200]]
        for shrink, fits in ((None, False), ([1], True)):
            output = io.StringIO()
            with patch('keepercommander.commands.base.shutil.get_terminal_size',
                       return_value=os.terminal_size((80, 24))), patch('sys.stdout', output):
                dump_report_data([list(row) for row in data], ['Gateway', 'Record'], fmt='table',
                                 shrink_columns=shrink)
            widest = max(len(line) for line in output.getvalue().splitlines())
            self.assertEqual(widest <= 79, fits)

    def test_colors_only_on_a_terminal(self):
        self.assertNotIn('\x1b[', '\n'.join(self._table_lines(300)))
        with patch('keepercommander.commands.pam.gateway_connections._use_color', return_value=True):
            colored = self._table_lines(90)
        self.assertIn('\x1b[', '\n'.join(colored))
        visible = [re.sub(r'\x1b\[[0-9;]*m', '', line) for line in colored]
        self.assertLessEqual(max(len(line) for line in visible), 89)

    def test_truncate_keeps_color_and_ignores_codes_in_width(self):
        colored = '\x1b[92m' + 'x' * 40 + '\x1b[0m'
        self.assertEqual(_truncate_visible(colored, 50), colored)
        self.assertEqual(_truncate_visible(colored, 10), '\x1b[92m' + 'x' * 7 + '...\x1b[0m')

    def test_registration_and_alias(self):
        command = PAMGatewayCommand()
        self.assertIn('connections', command._commands)
        self.assertEqual(command._aliases['conn'], 'connections')

    def test_table_empty_message(self):
        del self.online.controllers[:]
        output = io.StringIO()
        with patch('keepercommander.commands.pam.gateway_connections.router_helper.router_get_connected_gateways',
                   return_value=self.online), patch(
                       'keepercommander.commands.pam.gateway_connections.gateway_helper.get_all_gateways',
                       return_value=self.gateways), patch('sys.stdout', output):
            self.command.execute(self.params, format='table')
        self.assertIn('No active connections.', output.getvalue())


if __name__ == '__main__':
    unittest.main()


class TestPAMGatewayDisconnectCommand(unittest.TestCase):
    MODULE = 'keepercommander.commands.pam.gateway_connections'

    def setUp(self):
        self.gateway_uid = b'G' * 16
        self.connection_uid = b'C' * 16
        self.connection_uid_str = 'Q0NDQ0NDQ0NDQ0NDQ0NDQw'
        self.active = pam_pb2.PAMOnlineControllers()
        controller = self.active.controllers.add(controllerUid=self.gateway_uid, ipAddress='10.0.0.1')
        controller.connections.add(connectionUid=self.connection_uid, type=pam_pb2.SSH, recordUid=b'R' * 16,
                                   userName='user@example.com', startedOn=1000)
        self.gone = pam_pb2.PAMOnlineControllers()
        self.gone.controllers.add(controllerUid=self.gateway_uid, ipAddress='10.0.0.1')

    def _run(self, router_states, answer='y', selector=None, **kwargs):
        send = MagicMock(return_value={'response': {}})
        output = io.StringIO()
        with patch(f'{self.MODULE}.router_helper.router_get_connected_gateways', side_effect=router_states), \
                patch(f'{self.MODULE}.router_helper.router_send_action_to_gateway', send), \
                patch(f'{self.MODULE}.gateway_helper.get_all_gateways',
                      return_value=[_gateway(self.gateway_uid, 'gw')]), \
                patch(f'{self.MODULE}._record_title', return_value='My Server'), \
                patch(f'{self.MODULE}.user_choice', return_value=answer) as choice, \
                patch(f'{self.MODULE}.time.sleep'), \
                patch(f'{self.MODULE}.time.time', side_effect=itertools.count(1000)), patch('sys.stdout', output):
            PAMGatewayDisconnectCommand().execute(MagicMock(), connection_uid=selector or self.connection_uid_str,
                                                  **kwargs)
        return send, choice, output.getvalue()

    def test_sends_admin_disconnect_to_the_owning_gateway(self):
        send, choice, output = self._run([self.active, self.gone])
        choice.assert_called_once()
        kwargs = send.call_args.kwargs
        self.assertEqual(kwargs['destination_gateway_uid_str'], 'R0dHR0dHR0dHR0dHR0dHRw')
        self.assertEqual(kwargs['message_type'], pam_pb2.CMT_CONNECT)
        payload = json.loads(kwargs['gateway_action'].toJSON())
        self.assertEqual(payload['action'], 'webrtc-session')
        self.assertEqual(payload['conversationId'], self.connection_uid_str)
        self.assertEqual(payload['inputs'], {'kind': 'disconnect', 'recordUid': 'UlJSUlJSUlJSUlJSUlJSUg',
                                             'conversationType': 'ssh', 'closeConnectionReason': 12})
        self.assertIn('disconnected', output)

    def test_cancel_sends_nothing(self):
        send, _, output = self._run([self.active], answer='n')
        send.assert_not_called()
        self.assertIn('Cancelled', output)

    def test_force_skips_confirmation(self):
        _, choice, _ = self._run([self.active, self.gone], force=True)
        choice.assert_not_called()

    def test_unknown_connection_is_an_error(self):
        with self.assertRaises(CommandError):
            self._run([self.gone])

    def test_warns_when_connection_is_still_listed(self):
        _, _, output = self._run([self.active] * 20, force=True)
        self.assertIn('still listed as active', output)

    def _with_second(self, second_uid):
        online = pam_pb2.PAMOnlineControllers()
        online.CopyFrom(self.active)
        online.controllers[0].connections.add(connectionUid=second_uid, type=pam_pb2.RDP, recordUid=b'R' * 16,
                                              userName='other@example.com', startedOn=2000)
        return online

    def test_unique_prefix_selects_the_connection(self):
        send = MagicMock(return_value={'response': {}})
        with patch(f'{self.MODULE}.router_helper.router_get_connected_gateways', side_effect=[self.active, self.gone]), \
                patch(f'{self.MODULE}.router_helper.router_send_action_to_gateway', send), \
                patch(f'{self.MODULE}.gateway_helper.get_all_gateways', return_value=[]), \
                patch(f'{self.MODULE}._record_title', return_value=None), \
                patch(f'{self.MODULE}.time.sleep'), patch('sys.stdout', io.StringIO()):
            PAMGatewayDisconnectCommand().execute(MagicMock(), connection_uid='Q0ND', force=True)
        payload = json.loads(send.call_args.kwargs['gateway_action'].toJSON())
        self.assertEqual(payload['conversationId'], self.connection_uid_str)

    def test_ambiguous_prefix_is_refused(self):
        # b'CCC' + 13 x b'D' shares the 'Q0ND' prefix with b'C' * 16
        online = self._with_second(b'CCC' + b'D' * 13)
        with self.assertRaises(CommandError) as ctx:
            self._run([online], selector='Q0ND', force=True)
        self.assertIn('matches 2 connections', str(ctx.exception))
        self.assertIn('more characters', str(ctx.exception))

    def test_prefix_too_short_is_refused(self):
        with patch(f'{self.MODULE}.router_helper.router_get_connected_gateways', return_value=self.active):
            with self.assertRaises(CommandError):
                PAMGatewayDisconnectCommand().execute(MagicMock(), connection_uid='Q0N', force=True)

    def test_short_ids_grow_until_unique(self):
        from keepercommander.commands.pam.gateway_connections import _short_ids
        rows = [{'connection_uid': 'abcdef1'}, {'connection_uid': 'abcdeX2'}, {'connection_uid': 'zzzz9'}]
        self.assertEqual(_short_ids(rows), {'abcdef1': 'abcdef', 'abcdeX2': 'abcdeX', 'zzzz9': 'zzzz'})
