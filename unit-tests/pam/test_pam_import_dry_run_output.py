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
"""`pam project import --dry-run` prints one line per record (like `extend`), not the JSON plan."""

from types import SimpleNamespace

import keepercommander.commands.record  # noqa: F401

from keepercommander.commands.pam_import.edit import PAMProjectImportCommand


def _rec(rtype, title, login='', folder_path='', users=None):
    return SimpleNamespace(type=rtype, title=title, login=login, folder_path=folder_path, users=users or [])


def test_prints_one_line_per_record_and_a_total(capsys):
    project = {'folders': {'resources_folder': 'QAReg - Resources', 'users_folder': 'QAReg - Users'}}
    machine = _rec('pamMachine', 'QAReg-Web-01', users=[_rec('pamUser', 'QAReg-Web-01 admin', 'qa-admin')])
    PAMProjectImportCommand._print_dry_run_records(
        project, [machine], [_rec('pamUser', 'QAReg-Svc-01', 'qa-svc'),
                             _rec('login', '', 'no-title', folder_path='QAReg - Users/Extra')])

    out = capsys.readouterr().out.splitlines()
    assert out == [
        '  [DRY RUN] [new]  folder=QAReg - Resources\trecord=pamMachine: QAReg-Web-01',
        '  [DRY RUN] [new]  folder=QAReg - Users\trecord=pamUser: QAReg-Svc-01',
        '  [DRY RUN] [new]  folder=QAReg - Users/Extra\trecord=login: no-title',
        '  [DRY RUN] [new]  folder=QAReg - Users\trecord=pamUser: QAReg-Web-01 admin (nested on QAReg-Web-01)',
        '[DRY RUN] 4 record(s) would be created',
    ]


def test_no_json_plan_is_printed(capsys):
    PAMProjectImportCommand._print_dry_run_records({}, [_rec('pamMachine', 'm')], [])
    out = capsys.readouterr().out
    assert '{' not in out and 'tiers' not in out
    assert 'folder=resources folder' in out  # fallback label when the folder name is unknown
