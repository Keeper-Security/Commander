#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
# Example showing how to access the raw enterprise event logs
# for some custom processing.
#

from keepercommander import api
from keepercommander.__main__ import get_params_from_config

my_params = get_params_from_config('config.json')
while not my_params.user:
    my_params.user = input('User(Email): ')
api.login(my_params)
if not my_params.session_token:
    exit(1)

events = []
finished = False
# UNIX epoch time in seconds
last_event_time = 0
logged_ids = set()

print('Downloading ', end='', flush=True)

while not finished:
    finished = True
    rq = {
        'command': 'get_audit_event_reports',
        'report_type': 'raw',
        'scope': 'enterprise',
        'limit': 1000,
        'order': 'ascending'
    }

    if last_event_time > 0:
        rq['filter'] = {
            'created': {'min': last_event_time}  # return audit events starting last_event_time
        }

    rs = api.communicate(my_params, rq)
    print('.', end='', flush=True)
    if rs['result'] == 'success':
        finished = True
        if 'audit_event_overview_report_rows' in rs:
            audit_events = rs['audit_event_overview_report_rows']
            if len(audit_events) > 1:
                # remove events from the tail for the last second
                last_event_time = int(audit_events[-1]['created'])
                while len(audit_events) > 0:
                    event = audit_events[-1]
                    if int(event['created']) < last_event_time:
                        break
                    audit_events = audit_events[:-1]

                for event in audit_events:
                    event_id = event['id']
                    if event_id not in logged_ids:
                        logged_ids.add(event_id)
                        events.append(event)
                finished = len(events) == 0

print()
print("{0} audit log events".format(len(events)))
