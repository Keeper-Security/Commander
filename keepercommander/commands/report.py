#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import collections
import itertools
import logging
import datetime
import os
import sqlite3

from .base import suppress_exit, raise_parse_exception, dump_report_data, Command
from .. import api


def register_commands(commands):
    commands['aging-report'] = PasswordAgingReportCommand()


def register_command_info(aliases, command_info):
    for p in [aging_report_parser]:
        command_info[p.prog] = p.description


aging_report_parser = argparse.ArgumentParser(prog='aging-report', description='Run password aging report')
aging_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv'], default='table', help='output format.')
aging_report_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
aging_report_parser.add_argument('--days', dest='days', action='store', type=int, default=30, help='minimum days record has not been changed.')
aging_report_parser.add_argument('--user', dest='users', action='append', help='number of days to look back for last login.')
aging_report_parser.add_argument('--record', dest='records', action='append', help='record UID.')
aging_report_parser.add_argument('--verbose', dest='verbose', action='store_true', help='show more information on record usage')
aging_report_parser.error = raise_parse_exception
aging_report_parser.exit = suppress_exit


AuditEvent = collections.namedtuple('AuditEvent', ['type', 'uid', 'user', 'time'])


class PasswordAgingReportCommand(Command):
    def __init__(self):
        Command.__init__(self)
        self.user_map = None

    def get_parser(self):
        return aging_report_parser

    def execute(self, params, **kwargs):
        self.user_map = PasswordAgingReportCommand.get_usernames(params)
        reverse_user_map = {}
        for key in self.user_map:
            reverse_user_map[self.user_map[key]] = key
        users = set()
        uids = set()
        if kwargs.get('users'):
            for u in kwargs['users']:
                username = u.lower()
                if username in self.user_map:
                    users.add(self.user_map[username])
        if kwargs.get('uids'):
            for uid in kwargs['uids']:
                uids.add(uid)

        headers = ['Record UID', 'Owner', 'Days since changed']
        if kwargs['verbose']:
            headers.append('Days since used')
        rows = []
        keeper_dir = os.path.join(os.path.expanduser('~'), '.keeper')
        if not os.path.exists(keeper_dir):
            os.mkdir(keeper_dir)
        ent_id = PasswordAgingReportCommand.get_enterprise_id(params)
        with sqlite3.connect(os.path.join(keeper_dir, 'audit{0}.db'.format(ent_id))) as conn:
            self.sync_audit_data(params, conn)
            record_uid = None
            owner = 0
            priority = 0
            changed = 0
            used = 0
            deleted = 0
            datas = conn.execute('select type, uid, user, time from audit_uid_event order by uid')
            empty = [(0, None, 0, 0)]
            top_time = int(datetime.datetime.now().timestamp())
            for e_type, uid, user_id, time in itertools.chain(datas, empty):
                if uid != record_uid:
                    ok = record_uid and (deleted == 0 or deleted < used) and (changed > 0)
                    if ok:
                        ok = not users or owner in users
                    if ok:
                        days = int((top_time - changed) / (60 * 60 * 24))
                        if days >= kwargs['days']:
                            days_used = int((top_time - max(used, changed)) / (60 * 60 * 24))
                            ok = kwargs['verbose'] or len(uids) > 0 or days_used < kwargs['days']
                            if ok:
                                row = [record_uid, reverse_user_map.get(owner) or '', days]
                                if kwargs['verbose']:
                                    if used > 0:
                                        row.append(days_used)
                                rows.append(row)
                    record_uid = uid
                    owner = 0
                    priority = 0
                    changed = 0
                    used = 0
                    deleted = 0
                if len(uids) > 0 and uid not in uids:
                    continue
                owner_weight = 0
                if e_type == 7:         # usage
                    used = time
                elif e_type == 11:  # record_add
                    if changed < time:
                        changed = time
                    owner_weight = 8
                elif e_type == 12:      # record_delete
                    deleted = time
                elif e_type == 14:    # record_update
                    if changed < time:
                        changed = time
                    owner_weight = 1
                elif e_type == 17:
                    if changed < time:
                        changed = time
                    priority = 9
                elif e_type == 80:    # record_password_change
                    if changed < time:
                        changed = time
                    owner_weight = 5
                if owner_weight > priority and user_id > 0:
                    owner = user_id
                    priority = owner_weight

        dump_report_data(rows, headers, is_csv=(kwargs.get('format') == 'csv'), filename=kwargs.get('output'))

    @staticmethod
    def get_enterprise_id(params):
        return int(params.enterprise['users'][0]['enterprise_user_id']) >> 32

    @staticmethod
    def get_usernames(params):
        result = {}
        for u in params.enterprise['users']:
            result[u['username'].lower()] = u['enterprise_user_id']
        return result

    @staticmethod
    def convert_events(events, user_map):
        for event in events:
            tm = int(event['created' if 'created' in event else 'last_created'])
            e_type = event['audit_event_type']
            if e_type == 'record_add':
                e_type = 11
            elif e_type == 'record_delete':
                e_type = 12
            elif e_type == 'record_update':
                e_type = 14
            elif e_type == 'transfer_owner':
                e_type = 17
            elif e_type == 'record_password_change':
                e_type = 80
            elif e_type in {'fast_fill', 'copy_password', 'open_record'}:
                e_type = 7
            elif e_type in {127}:
                e_type = 7
            elif type(e_type) != int:
                continue
            user_id = 0
            if e_type == 17:
                if 'to_username' in event:
                    user_id = user_map.get(event['to_username']) or 0
            if not user_id:
                if 'username' in event:
                    user_id = user_map.get(event['username']) or 0
            uid = event.get('record_uid')
            yield AuditEvent(type=e_type, uid=uid, user=user_id, time=tm)

    def sync_audit_data(self, params, connection):
        rs = connection.execute('pragma table_info(\'audit_uid_event\')').fetchall()
        bottom_time = 0
        if not rs:
            connection.execute('create table audit_uid_event (type INTEGER NOT NULL, uid TEXT NOT NULL, user INTEGER NOT NULL, time INTEGER NOT NULL)')
            connection.execute('create index audit_uid_event_time_idx on audit_uid_event(time)')
            connection.execute('create unique index audit_uid_event_idx on audit_uid_event(uid, type)')
        else:
            for res in connection.execute('select max(time) from audit_uid_event'):
                bottom_time = res[0]

        top_time = int(datetime.datetime.now().timestamp())
        if top_time < bottom_time + (60 * 60):
            return

        logging.info('Building aging report...')
        from_time = bottom_time
        while True:
            rq = {
                'command': 'get_enterprise_audit_event_reports',
                'report_type': 'span',
                'aggregate': ['last_created'],
                'columns': ['username', 'record_uid', 'audit_event_type'],
                'order': 'ascending',
                'limit': 1000,
                'filter': {
                    'created': {
                        'min': from_time,
                        'exclude_min': True
                    },
                    'audit_event_type': ['record_update', 'record_password_change']
                }
            }
            rs = api.communicate(params, rq)

            datas = list(PasswordAgingReportCommand.convert_events(rs['audit_event_overview_report_rows'], self.user_map))
            if datas:
                from_time = datas[-1].time
                connection.executemany('insert or replace into audit_uid_event(type, uid, user, time) values (?, ?, ?, ?)', [x for x in datas if x.uid])
            if len(rs['audit_event_overview_report_rows']) < 1000:
                break

        from_time = bottom_time
        while True:
            rq = {
                'command': 'get_enterprise_audit_event_reports',
                'report_type': 'raw',
                'order': 'ascending',
                'limit': 1000,
                'filter': {
                    'created': {
                        'min': from_time,
                        'exclude_min': True
                    },
                    'audit_event_type': ['record_add', 'record_delete', 'transfer_owner']
                }
            }
            rs = api.communicate(params, rq)

            datas = list(PasswordAgingReportCommand.convert_events(rs['audit_event_overview_report_rows'], self.user_map))
            if datas:
                from_time = datas[-1].time
                connection.executemany('insert or replace into audit_uid_event(type, uid, user, time) values (?, ?, ?, ?)', [x for x in datas if x.uid])
            if len(rs['audit_event_overview_report_rows']) < 1000:
                break

        from_time = bottom_time
        while True:
            rq = {
                'command': 'get_enterprise_audit_event_reports',
                'report_type': 'span',
                'aggregate': ['last_created'],
                'columns': ['record_uid', 'audit_event_type'],
                'order': 'ascending',
                'limit': 1000,
                'filter': {
                    'created': {
                        'min': from_time,
                        'exclude_min': True
                    },
                    'audit_event_type': ['fast_fill', 'copy_password', 'open_record']
                }
            }
            rs = api.communicate(params, rq)

            datas = list(PasswordAgingReportCommand.convert_events(rs['audit_event_overview_report_rows'], self.user_map))
            if datas:
                from_time = datas[-1].time
                connection.executemany('insert or replace into audit_uid_event(type, uid, user, time) values (?, ?, ?, ?)', [x for x in datas if x.uid])
            if len(rs['audit_event_overview_report_rows']) < 1000:
                break
        logging.info('')
