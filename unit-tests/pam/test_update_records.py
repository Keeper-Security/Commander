"""`update_records`: the record-field writer of `pam project update` (no server: the vault calls are replaced)."""
import copy
import logging
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander import utils, vault, vault_extensions
from keepercommander.commands.pam_import import update_diff as ud
from keepercommander.commands.pam_import import update_plan as up
from keepercommander.commands.pam_import import update_records as ur
from keepercommander.commands.pam_import.base import PamUserObject
from keepercommander.commands.pam_import.import_items import load_items
from keepercommander.proto import record_pb2

import test_update_plan as tp
from test_update_diff import _field, diff, vault_machine

UID = utils.generate_uid()


def typed(data, uid=UID):
    record = vault.TypedRecord()
    record.load_record_data(data)
    record.record_uid = uid
    record.record_key = b'\x07' * 32
    record.revision = 5
    return record


def data_of(record):
    return vault_extensions.extract_typed_record_data(record)


def roundtrip(raw, data, **kw):
    """Apply the changes of diff(raw, data) to a record and diff again: nothing may be left."""
    result = diff(raw, data, **kw)
    record = typed(data)
    applied = ur.apply_changes_to_record(record, result.changes)
    return result, applied, diff(raw, data_of(record), **kw)


class Quiet(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)


class TestApplyChanges(Quiet):
    def test_merge_changes_apply_and_leave_nothing_to_do(self):
        raw = {'type': 'pamMachine', 'title': 'Renamed', 'notes': 'n', 'host': 'h2', 'operating_system': 'windows',
               'instance_name': 'i-1', 'pam_settings': {'connection': {'protocol': 'ssh', 'port': '22'}}}
        result, applied, again = roundtrip(raw, vault_machine())
        self.assertGreaterEqual(len(result.changes), 5)
        self.assertEqual(applied, len(result.changes))
        self.assertEqual(again.changes, [])

    def test_the_values_land_where_the_change_says(self):
        raw = {'type': 'pamMachine', 'host': 'h2', 'pam_settings': {'connection': {'protocol': 'ssh', 'port': '22'}}}
        result = diff(raw, vault_machine())
        record = typed(vault_machine())
        ur.apply_changes_to_record(record, result.changes)
        host = next(f for f in record.fields if f.type == 'pamHostname')
        settings = next(f for f in record.fields if f.type == 'pamSettings')
        self.assertEqual(host.value, [{'hostName': 'h2', 'port': '22'}])                  # the port stays
        self.assertEqual(settings.value[0]['connection'], {'protocol': 'ssh', 'port': '22', 'recordingIncludeKeys': True})

    def test_overwrite_removals_apply_and_leave_nothing_to_do(self):
        raw = {'type': 'pamMachine', 'host': 'h1', 'port': '22', 'pam_settings': {'connection': {'protocol': 'ssh'}}}
        result, applied, again = roundtrip(raw, vault_machine(), mode=ud.MODE_OVERWRITE)
        self.assertTrue([c for c in result.changes if c.op == ud.OP_REMOVE])
        self.assertEqual(again.changes, [])
        record = typed(vault_machine())
        ur.apply_changes_to_record(record, result.changes)
        self.assertEqual(next(f for f in record.fields if f.label == 'operatingSystem').value, [])      # a typed field is emptied
        self.assertEqual(next(f for f in record.fields if f.type == 'pamHostname').label or '', '')

    def test_custom_fields_are_added_changed_and_removed(self):
        raw = {'type': 'pamUser', 'title': 'u', 'login': 'l',
               'custom': [{'label': 'Owner', 'value': 'ops'}, {'label': 'Team', 'value': 'x'}]}
        obj = PamUserObject.load(raw)
        current = {'title': 'u', 'notes': '', 'type': 'pamUser', 'fields': [_field('login', 'l')],
                   'custom': [_field('text', 'old', 'Owner'), _field('text', 'keep', 'Other')]}
        for mode, expected in ((ud.MODE_MERGE, {'Owner': 'ops', 'Team': 'x', 'Other': 'keep'}),
                               (ud.MODE_OVERWRITE, {'Owner': 'ops', 'Team': 'x'})):
            result = ud.diff_record(raw, 'pamUser', obj, current, mode=mode)
            record = typed(current)
            ur.apply_changes_to_record(record, result.changes)
            self.assertEqual({f.label: f.value[0] for f in record.custom}, expected, mode)
            self.assertEqual(ud.diff_record(raw, 'pamUser', obj, data_of(record), mode=mode).changes, [], mode)

    def test_a_typed_field_the_record_does_not_have_is_skipped_not_invented(self):
        target = ud.us.Target(ud.us.KIND_RECORD, field='text', label='nope', scope=ud.us.SCOPE_TYPED)
        change = ud.Change(ud.KIND_RECORD, ud.OP_ADD, 'text "nope"', None, 'x', target=target)
        record = typed(vault_machine())
        self.assertEqual(ur.apply_changes_to_record(record, [change]), 0)
        self.assertEqual(record.custom, [])

    def test_a_checkbox_written_in_the_custom_section_is_found_there(self):
        data = vault_machine()
        data['fields'] = [f for f in data['fields'] if f.get('label') != 'sslVerification']
        data['custom'] = [_field('checkbox', False, 'sslVerification')]
        raw = {'type': 'pamMachine', 'ssl_verification': True}
        result, applied, again = roundtrip(raw, data)
        self.assertEqual((applied, again.changes), (1, []))


class FakeVault:
    """Replaces the vault calls of apply_records: remembers what was sent, answers per record."""

    def __init__(self, data_by_uid, answers=None):
        self.data = data_by_uid                      # uid -> record JSON (what load returns)
        self.answers = answers or {}                 # uid -> [status, status ...] (one per send)
        self.sent = []                               # [(uid, nsf)]
        self.reread_calls = []

    def is_nsf(self, uid):
        return False

    def load(self, uid, nsf):
        return typed(self.data[uid], uid)

    def send(self, pbs, nsf):
        out = []
        for pb in pbs:
            uid = utils.base64_url_encode(pb.record_uid)
            self.sent.append((uid, nsf))
            queue = self.answers.get(uid)
            status = queue.pop(0) if queue else record_pb2.RS_SUCCESS
            entry = record_pb2.RecordModifyStatus()
            entry.record_uid = pb.record_uid
            entry.status = status
            out.append(entry)
        return out


class TestApplyRecords(Quiet):
    def plan(self, raw=None, mode=ud.MODE_MERGE, include_passwords=False, st=None):
        raw = raw or tp.machine_json(users=[], operating_system='windows')
        items, _ = load_items({'resources': [raw]}, tp.CFG)
        return up.build_plan(items, tp.index(), st or tp.state(), config_uid=tp.CFG, scope_records=[], mode=mode,
                             include_passwords=include_passwords)

    def run_apply(self, plan, fake, reread=None):
        with patch.object(ur, '_build_typed_record_update_pb', side_effect=lambda p, r, e: _pb(r)):
            return ur.apply_records(MagicMock(), plan, is_nsf=fake.is_nsf, load=fake.load, send=fake.send,
                                    reread=reread or (lambda uids: {}))

    def test_a_changed_record_is_sent_once_and_reported(self):
        plan = self.plan()
        fake = FakeVault({tp.M1: tp.vault_machine()})
        report = self.run_apply(plan, fake)
        self.assertEqual([uid for uid, _ in fake.sent], [tp.M1])
        self.assertEqual(report.errors, [])
        self.assertTrue(report.applied[0].startswith('M1: record fields ('))

    def test_nothing_is_sent_for_an_identical_plan(self):
        plan = self.plan(tp.machine_json(users=[]))
        fake = FakeVault({tp.M1: tp.vault_machine()})
        report = self.run_apply(plan, fake)
        self.assertEqual((fake.sent, report.applied, report.errors), ([], [], []))

    def test_a_status_that_is_not_success_is_an_apply_error_and_the_run_goes_on(self):
        plan = self.plan()
        fake = FakeVault({tp.M1: tp.vault_machine()}, answers={tp.M1: [record_pb2.RS_ACCESS_DENIED]})
        report = self.run_apply(plan, fake)
        self.assertEqual(len(report.errors), 1)
        self.assertIn('M1: record fields were not written: access denied', report.errors[0])

    def test_a_failing_call_marks_its_records_as_errors(self):
        plan = self.plan()
        fake = FakeVault({tp.M1: tp.vault_machine()})
        fake.send = MagicMock(side_effect=RuntimeError('throttled'))
        report = self.run_apply(plan, fake)
        self.assertIn('M1: record fields were not written: throttled', report.errors[0])

    def test_out_of_sync_is_reread_compared_again_and_sent_once_more(self):
        plan = self.plan()
        fake = FakeVault({tp.M1: tp.vault_machine()}, answers={tp.M1: [record_pb2.RS_OUT_OF_SYNC]})
        fresh = tp.state().records[tp.M1]
        reread = MagicMock(return_value={tp.M1: fresh})
        report = self.run_apply(plan, fake, reread=reread)
        reread.assert_called_once_with([tp.M1])
        self.assertEqual([uid for uid, _ in fake.sent], [tp.M1, tp.M1])
        self.assertEqual(report.errors, [])

    def test_a_record_the_first_attempt_already_wrote_is_not_sent_again(self):
        plan = self.plan()
        fake = FakeVault({tp.M1: tp.vault_machine()}, answers={tp.M1: [record_pb2.RS_OUT_OF_SYNC]})
        written = tp.state().records[tp.M1]
        written.data = copy.deepcopy(written.data)
        for fld in written.data['fields']:
            if fld.get('label') == 'operatingSystem':
                fld['value'] = ['windows']                    # the other writer (or our first attempt) changed it
        report = self.run_apply(plan, fake, reread=lambda uids: {tp.M1: written})
        self.assertEqual([uid for uid, _ in fake.sent], [tp.M1])               # no second send
        self.assertEqual(report.errors, [])
        self.assertIn('already up to date', report.applied[0])

    def test_out_of_sync_twice_is_an_error_to_run_update_again(self):
        plan = self.plan()
        fake = FakeVault({tp.M1: tp.vault_machine()},
                         answers={tp.M1: [record_pb2.RS_OUT_OF_SYNC, record_pb2.RS_OUT_OF_SYNC]})
        report = self.run_apply(plan, fake, reread=lambda uids: {tp.M1: tp.state().records[tp.M1]})
        self.assertEqual(len(fake.sent), 2)
        self.assertIn('changed while the update ran', report.errors[0])


class TestNsfRecords(TestApplyRecords):
    """A record in a Nested Share Folder: loaded from the NSF-aware loader, sent with the NSF revision and the NSF call."""

    def test_the_nsf_revision_is_used_and_the_nsf_call_is_made(self):
        plan = self.plan()
        fake = FakeVault({tp.M1: tp.vault_machine()})
        fake.is_nsf = lambda uid: True
        seen = {}

        def build(_params, record, existing):
            seen['revisions'] = (record.revision, existing.revision)
            return _pb(record)

        with patch.object(ur, '_build_typed_record_update_pb', side_effect=build),                 patch('keepercommander.nested_share_folder.common.get_record_revision', return_value=99):
            report = ur.apply_records(MagicMock(), plan, is_nsf=fake.is_nsf, load=fake.load, send=fake.send,
                                      reread=lambda uids: {})
        self.assertEqual(seen['revisions'], (99, 99))                 # the loaded NSF record carries the stale copy's revision
        self.assertEqual(fake.sent, [(tp.M1, True)])
        self.assertEqual(report.errors, [])


class TestPasswordRetryRule(Quiet):
    """Owner rule 2026-11-12: on the retry a password is written only if it was scheduled AND the vault one is unchanged."""

    def setUp(self):
        super().setUp()
        raw = {'type': 'pamUser', 'title': 'admin1', 'login': 'root', 'password': 'NEW'}
        self.item_obj = PamUserObject.load(raw)
        self.data = {'title': 'admin1', 'notes': '', 'type': 'pamUser',
                     'fields': [_field('login', 'root'), _field('password', 'OLD')], 'custom': []}
        self.raw = raw

    def result(self, vault_password):
        data = copy.deepcopy(self.data)
        data['fields'][1]['value'] = [vault_password]
        items, _ = load_items({'users': [self.raw]}, tp.CFG)
        item = items[0]
        item.uid = tp.U1
        res = ud.diff_record(self.raw, 'pamUser', item.obj, data, include_passwords=True)
        return up.ItemResult(item=item, uid=tp.U1, title='admin1', record_type='pamUser', changes=res.changes)

    def test_a_scheduled_and_unchanged_password_is_written_again(self):
        report = ur.RecordWriteReport()
        keep = ur._retry_changes(self.result('OLD'), self.result('OLD'), report)
        self.assertEqual([c.path for c in keep], ['password'])
        self.assertEqual(report.warnings, [])

    def test_a_password_changed_meanwhile_is_skipped_with_a_warning(self):
        report = ur.RecordWriteReport()
        keep = ur._retry_changes(self.result('OLD'), self.result('ROTATED'), report)
        self.assertEqual(keep, [])
        self.assertIn('the password in the vault changed while the update ran', report.warnings[0])

    def test_a_password_that_was_not_scheduled_is_never_added_by_a_retry(self):
        report = ur.RecordWriteReport()
        original = self.result('NEW')                       # vault already equals the JSON: nothing scheduled
        keep = ur._retry_changes(original, self.result('ROTATED'), report)
        self.assertEqual(keep, [])
        self.assertEqual(report.warnings, [])


def _pb(record):
    pb = record_pb2.RecordUpdate()
    pb.record_uid = utils.base64_url_decode(record.record_uid)
    return pb


if __name__ == '__main__':
    unittest.main()
