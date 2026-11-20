"""`update_rotation`: the rotation writer of `pam project update` (no server: the router call is replaced)."""
import json
import logging
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(__file__))

import keepercommander.commands.record  # noqa: F401,E402

from keepercommander import crypto, utils  # noqa: E402
from keepercommander.commands.pam_import import update_plan as up  # noqa: E402
from keepercommander.commands.pam_import import update_rotation as ur  # noqa: E402
from keepercommander.commands.pam_import.import_items import load_items  # noqa: E402

import test_update_plan as tp  # noqa: E402

KEY = b'k' * 32
STORED_SCHEDULE = json.dumps([{'type': 'CRON', 'cron': '0 30 18 * * ?', 'tz': 'Etc/UTC'}])
STORED_RULES = {'length': 32, 'caps': 5, 'lowercase': 5, 'digits': 5, 'special': 5, 'specialChars': '!@#'}


def stored_entry(**over):
    entry = {'record_uid': tp.U1, 'revision': 7, 'configuration_uid': tp.CFG, 'resource_uid': tp.M1,
             'schedule': STORED_SCHEDULE, 'disabled': False,
             'pwd_complexity': utils.base64_url_encode(crypto.encrypt_aes_v2(json.dumps(STORED_RULES).encode(), KEY))}
    entry.update(over)
    return entry


def vault_rotation(entry):
    return {'configuration_uid': entry['configuration_uid'], 'resource_uid': entry['resource_uid'],
            'disabled': entry['disabled'], 'schedule': json.loads(entry['schedule']) if entry['schedule'] else '',
            'pwd_complexity': dict(STORED_RULES)}


def make_plan(rotation_json, entry=None, rotation_state='entry'):
    raw = tp.machine_json()
    raw['users'][0]['rotation_settings'] = rotation_json
    items, _ = load_items({'resources': [raw]}, tp.CFG)
    entry = entry or stored_entry()
    state = tp.state(rotation=vault_rotation(entry) if rotation_state == 'entry' else rotation_state)
    return up.build_plan(items, tp.index(), state, config_uid=tp.CFG, scope_records=[]), entry


def params_for(entry):
    return SimpleNamespace(record_rotation_cache={tp.U1: entry} if entry else {}, sync_data=False)


class Sender:
    def __init__(self, fail=False):
        self.requests, self.fail = [], fail

    def __call__(self, rq):
        if self.fail:
            raise RuntimeError('RRC_BAD_REQUEST schedule in the past')
        self.requests.append(rq)


SAME = {'rotation': 'general', 'enabled': 'on', 'schedule': {'type': 'cron', 'cron': '0 30 18 * * ?'},
        'password_complexity': '32,5,5,5,5'}


class TestApplyRotations(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def run_rotations(self, rotation_json, entry=None, send=None, rotation_state='entry'):
        plan, entry = make_plan(rotation_json, entry, rotation_state)
        params = params_for(entry if rotation_state == 'entry' else None)
        send = send or Sender()
        report = ur.apply_rotations(params, plan, send=send, record_key=lambda uid: KEY)
        return report, send, params

    def test_every_changed_property_is_written_and_the_identity_stays(self):
        report, send, params = self.run_rotations(dict(SAME, enabled='off', password_complexity='24,4,4,4,4',
                                                       schedule={'type': 'cron', 'cron': '0 0 4 * * ?'}))
        self.assertEqual((report.errors, report.not_applied), ([], []))
        self.assertEqual(report.applied, ['admin1: rotation (3)'])
        rq = send.requests[0]
        self.assertEqual((rq.revision, rq.noop, rq.disabled), (7, False, True))
        self.assertEqual(bytes(rq.recordUid), utils.base64_url_decode(tp.U1))
        self.assertEqual(bytes(rq.configurationUid), utils.base64_url_decode(tp.CFG))
        self.assertEqual(bytes(rq.resourceUid), utils.base64_url_decode(tp.M1))       # the machine stays
        self.assertEqual(json.loads(rq.schedule), [{'type': 'CRON', 'cron': '0 0 4 * * ?', 'tz': 'Etc/UTC'}])
        rules = json.loads(crypto.decrypt_aes_v2(bytes(rq.pwdComplexity), KEY).decode())
        self.assertEqual(rules, {'length': 24, 'caps': 4, 'lowercase': 4, 'digits': 4, 'special': 4,
                                 'specialChars': '!@#'})                              # the stored special chars stay
        self.assertFalse(rq.HasField('serviceResources'))
        self.assertTrue(params.sync_data)

    def test_what_did_not_change_is_sent_back_exactly_as_stored(self):
        report, send, params = self.run_rotations(dict(SAME, enabled='off'))
        rq = send.requests[0]
        entry = params.record_rotation_cache[tp.U1]
        self.assertTrue(rq.disabled)
        self.assertEqual(rq.schedule, entry['schedule'])                               # the stored text, byte for byte
        self.assertEqual(bytes(rq.pwdComplexity), utils.base64_url_decode(entry['pwd_complexity']))

    def test_on_demand_is_an_empty_schedule_and_a_time_zone_is_kept(self):
        _, send, _ = self.run_rotations(dict(SAME, schedule={'type': 'on-demand'}))
        self.assertEqual(send.requests[0].schedule, '')
        _, send, _ = self.run_rotations(dict(SAME, schedule={'type': 'cron', 'cron': '0 0 4 * * ?',
                                                             'tz': 'America/Chicago'}))
        self.assertEqual(json.loads(send.requests[0].schedule),
                         [{'type': 'CRON', 'cron': '0 0 4 * * ?', 'tz': 'America/Chicago'}])

    def test_an_identical_rotation_sends_nothing(self):
        report, send, params = self.run_rotations(SAME)
        self.assertEqual((send.requests, report.applied, report.errors), ([], [], []))
        self.assertFalse(params.sync_data)

    def test_a_rejected_request_is_an_error_for_that_user(self):
        report, _, params = self.run_rotations(dict(SAME, enabled='off'), send=Sender(fail=True))
        self.assertEqual(report.applied, [])
        self.assertEqual(len(report.errors), 1)
        self.assertIn('admin1: rotation was not written: RRC_BAD_REQUEST schedule in the past', report.errors[0])
        self.assertFalse(params.sync_data)

    def test_a_user_without_a_rotation_is_not_written_yet(self):
        report, send, _ = self.run_rotations(SAME, rotation_state=None)
        self.assertEqual(send.requests, [])
        self.assertEqual(len(report.not_applied), 1)
        self.assertIn('a rotation the user does not have yet', report.not_applied[0])

    def test_other_profiles_are_not_written_yet(self):
        report, send, _ = self.run_rotations(dict(SAME, rotation='iam_user', enabled='off'),
                                             entry=stored_entry(resource_uid=tp.CFG))
        self.assertEqual(send.requests, [])
        self.assertIn('iam_user rotation profile is not written yet', report.not_applied[0])

    def test_a_general_json_on_a_noop_vault_rotation_is_not_written(self):
        plan, entry = make_plan(dict(SAME, enabled='off'))
        entry = dict(entry, resource_uid=tp.CFG)                                      # the vault rotation has no machine
        send = Sender()
        report = ur.apply_rotations(params_for(entry), plan, send=send, record_key=lambda uid: KEY)
        self.assertEqual(send.requests, [])
        self.assertIn('not a general one', report.not_applied[0])

    def test_a_missing_cache_entry_is_an_error(self):
        plan, entry = make_plan(dict(SAME, enabled='off'))
        report = ur.apply_rotations(params_for(None), plan, send=Sender(), record_key=lambda uid: KEY)
        self.assertIn('rotation is not in the vault cache', report.errors[0])


if __name__ == '__main__':
    unittest.main()
