"""`update_rotation`: the rotation writer of `pam project update` (no server: the router call is replaced)."""
import json
import logging
import os
import sys
import unittest
from dataclasses import replace
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(__file__))

import keepercommander.commands.record  # noqa: F401,E402

from keepercommander import crypto, utils  # noqa: E402
from keepercommander.commands.pam_import import update_plan as up  # noqa: E402
from keepercommander.commands.pam_import import update_rotation as ur  # noqa: E402
from keepercommander.commands.pam_import.import_items import load_items  # noqa: E402
from keepercommander.commands.pam_import.record_matcher import MatchRecord, RecordIndex  # noqa: E402

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


def make_plan(rotation_json, entry=None, rotation_state='entry', json_admin=True, **state_args):
    raw = tp.machine_json()
    raw['users'][0]['rotation_settings'] = rotation_json
    if not json_admin:
        raw['pam_settings']['connection'].pop('administrative_credentials')
    items, _ = load_items({'resources': [raw]}, tp.CFG)
    entry = entry or stored_entry()
    state = tp.state(rotation=vault_rotation(entry) if rotation_state == 'entry' else rotation_state, **state_args)
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

    def run_add(self, rotation_json, add=None, **plan_args):
        plan, _ = make_plan(rotation_json, rotation_state=None, **plan_args)
        send, added = Sender(), []
        report = ur.apply_rotations(params_for(None), plan, send=send, record_key=lambda uid: KEY,
                                    add=add or (lambda args, label: added.append((args, label))))
        return report, send, added

    def test_a_user_without_a_rotation_gets_it_through_the_rotation_command(self):
        report, send, added = self.run_add(SAME)
        self.assertEqual((report.errors, report.not_applied), ([], []))
        self.assertEqual(report.applied, ['admin1: rotation (added)'])
        self.assertEqual(send.requests, [])                    # not set_record_rotation: the command links the user
        args, label = added[0]
        self.assertEqual(label, 'admin1')
        self.assertEqual((args['config'], args['record_name'], args['resource'], args['admin']),
                         (tp.CFG, tp.U1, tp.M1, tp.U1))
        self.assertTrue(args['force'])
        self.assertEqual((args['enable'], args['schedule_cron_data'], args['pwd_complexity']),
                         (True, ['0 30 18 * * ?'], '32,5,5,5,5'))

    def test_the_admin_set_by_the_same_run_is_enough(self):
        plan, _ = make_plan(SAME, rotation_state=None, acl_admin=None)    # the vault machine has no admin yet
        added = []
        report = ur.apply_rotations(params_for(None), plan, add=lambda args, label: added.append(args))
        self.assertEqual((report.errors, report.not_applied), ([], []))
        self.assertEqual(added[0]['admin'], tp.U1)

    def test_a_machine_without_an_admin_is_not_written_yet(self):
        report, _, added = self.run_add(SAME, json_admin=False, acl_admin=None)
        self.assertEqual(added, [])
        self.assertIn('the machine has no administrative credential', report.not_applied[0])

    def test_an_unknown_machine_is_not_written_yet(self):
        plan, _ = make_plan(SAME, rotation_state=None)
        for result in plan.results:
            result.changes[:] = [c if c.path != 'rotation' else replace(c, data=None) for c in result.changes]
        added = []
        report = ur.apply_rotations(params_for(None), plan, add=lambda args, label: added.append(args))
        self.assertEqual(added, [])
        self.assertIn('the machine of the user is not known', report.not_applied[0])

    def test_a_rejected_add_is_an_error_for_that_user(self):
        def fail(args, label):
            raise RuntimeError('does not have admin credentials')
        report, _, _ = self.run_add(SAME, add=fail)
        self.assertEqual(report.applied, [])
        self.assertIn('admin1: rotation was not written: does not have admin credentials', report.errors[0])

    def test_an_added_profile_rotation_of_a_nested_user_is_not_written_yet(self):
        report, _, added = self.run_add(dict(SAME, rotation='iam_user'))
        self.assertEqual(added, [])
        self.assertIn('must be a top-level user', report.not_applied[0])
        self.assertIn('top-level "pam_data.users"', report.not_applied[0])          # tells what to do about it

    def test_the_plan_names_the_machine_and_its_admin_in_the_added_rotation(self):
        plan, _ = make_plan(SAME, rotation_state=None)
        change = next(c for r in plan.results for c in ur.rotation_changes(r) if c.path == 'rotation')
        self.assertEqual(change.data, up.RotationAdd(tp.M1, tp.U1))

    # ---- iam_user / scripts_only / saas: top-level users, the profile of the vault rotation comes from the graph ----
    IAM_ACL = {'is_iam_user': True, 'belongs_to': True}
    NOOP_ACL = {'rotation_settings': {'noop': True}}
    SAAS_ACL = {'rotation_settings': {'noop': True, 'saas_record_uid_list': ['S' * 22]}}

    @staticmethod
    def profile_json(profile, **over):
        data = {'rotation': profile, 'enabled': 'on', 'schedule': {'type': 'cron', 'cron': '0 30 18 * * ?'},
                'password_complexity': '32,5,5,5,5'}
        if profile == 'saas':
            data['saas_config'] = 'saas-cfg'
        data.update(over)
        return data

    def global_plan(self, rotation_json, entry=None, rotation_state='entry', saas_records=(), **state_args):
        user = {'type': 'pamUser', 'title': 'admin1', 'login': 'root', 'password': 'pw',
                'rotation_settings': rotation_json}
        items, _ = load_items({'users': [user]}, tp.CFG)
        entry = entry or stored_entry(resource_uid='')
        state = tp.state(rotation=vault_rotation(entry) if rotation_state == 'entry' else rotation_state, **state_args)
        index = tp.index()
        if saas_records:                # SaaS configuration records of the vault: (uid, title)
            index = RecordIndex([MatchRecord(uid=tp.M1, title='M1', record_type='pamMachine'),
                                 MatchRecord(uid=tp.U1, title='admin1', record_type='pamUser', login='root')]
                                + [MatchRecord(uid=uid, title=name, record_type='saasConfiguration')
                                   for uid, name in saas_records])
        return up.build_plan(items, index, state, config_uid=tp.CFG, scope_records=[]), entry

    def run_global(self, rotation_json, entry=None, rotation_state='entry', **state_args):
        plan, entry = self.global_plan(rotation_json, entry, rotation_state, **state_args)
        send, added = Sender(), []
        report = ur.apply_rotations(params_for(entry if rotation_state == 'entry' else None), plan, send=send,
                                    record_key=lambda uid: KEY, add=lambda args, label: added.append(args))
        return plan, report, send, added

    def test_an_iam_user_change_keeps_the_profile(self):
        plan, report, send, _ = self.run_global(self.profile_json('iam_user', enabled='off'),
                                                entry=stored_entry(resource_uid=tp.CFG), user_acl=self.IAM_ACL)
        self.assertEqual((report.errors, report.not_applied), ([], []))
        self.assertEqual(plan.results[0].vault_rotation_profile, 'iam_user')
        rq = send.requests[0]
        self.assertEqual((bytes(rq.resourceUid), rq.noop, rq.disabled), (b'', False, True))   # no machine, not NOOP
        self.assertEqual(bytes(rq.configurationUid), utils.base64_url_decode(tp.CFG))
        self.assertEqual(rq.revision, 7)

    def test_a_scripts_only_change_is_sent_as_noop(self):
        _, report, send, _ = self.run_global(self.profile_json('scripts_only', enabled='off'),
                                             entry=stored_entry(resource_uid=''), user_acl=self.NOOP_ACL)
        self.assertEqual((report.errors, report.not_applied), ([], []))
        self.assertEqual(report.applied, ['admin1: rotation (1)'])
        rq = send.requests[0]
        self.assertEqual((bytes(rq.resourceUid), rq.noop, rq.disabled), (b'', True, True))
        entry = stored_entry()
        self.assertEqual(rq.schedule, entry['schedule'])                       # what did not change is sent back as stored

    def test_a_json_profile_that_is_not_the_vault_profile_is_a_warning_and_nothing_is_written(self):
        for json_profile, acl in (('scripts_only', self.SAAS_ACL), ('iam_user', self.NOOP_ACL),
                                  ('scripts_only', None), ('iam_user', self.SAAS_ACL)):
            plan, report, send, _ = self.run_global(self.profile_json(json_profile, enabled='off'),
                                                    entry=stored_entry(resource_uid=''), user_acl=acl)
            self.assertEqual((send.requests, report.applied, report.not_applied), ([], [], []), (json_profile, acl))
            self.assertTrue(any('rotation type' in w for w in plan.results[0].warnings), plan.results[0].warnings)

    def test_a_saas_change_names_the_saas_record_again(self):
        plan, report, send, _ = self.run_global(self.profile_json('saas', enabled='off'),
                                                entry=stored_entry(resource_uid=''), user_acl=self.SAAS_ACL)
        self.assertEqual((report.errors, report.not_applied), ([], []))
        self.assertEqual(report.applied, ['admin1: rotation (1)'])
        self.assertEqual(plan.results[0].vault_saas_uids, ['S' * 22])
        rq = send.requests[0]
        self.assertEqual((bytes(rq.resourceUid), rq.noop, rq.disabled), (b'', True, True))
        self.assertEqual(bytes(rq.saasConfiguration), utils.base64_url_decode('S' * 22))   # else the router drops it
        self.assertEqual(rq.revision, 7)

    def test_the_saas_record_the_json_names_must_be_the_one_the_vault_rotation_uses(self):
        same = ('S' * 22, 'saas-cfg')
        _, report, send, _ = self.run_global(self.profile_json('saas', enabled='off'), entry=stored_entry(resource_uid=''),
                                             user_acl=self.SAAS_ACL, saas_records=[same])
        self.assertEqual((report.errors, report.not_applied, len(send.requests)), ([], [], 1))     # same record: written
        # another SaaS record: identity mismatch - a warning, nothing written (update never moves a rotation)
        plan, report, send, _ = self.run_global(self.profile_json('saas', enabled='off'), entry=stored_entry(resource_uid=''),
                                                user_acl=self.SAAS_ACL, saas_records=[('T' * 22, 'saas-cfg')])
        self.assertEqual((send.requests, report.applied, report.not_applied), ([], [], []))
        self.assertTrue(any('SaaS configuration' in w and 'T' * 22 in w and 'S' * 22 in w for w in plan.results[0].warnings),
                        plan.results[0].warnings)
        # a reference update cannot find: the rotation is still written, and the warning says the record was not compared
        plan, report, send, _ = self.run_global(self.profile_json('saas', enabled='off'), entry=stored_entry(resource_uid=''),
                                                user_acl=self.SAAS_ACL)
        self.assertEqual(len(send.requests), 1)
        self.assertTrue(any('not compared' in w for w in plan.results[0].warnings), plan.results[0].warnings)

    def test_a_saas_rotation_that_does_not_name_exactly_one_record_is_not_written(self):
        two = {'rotation_settings': {'noop': True, 'saas_record_uid_list': ['S' * 22, 'T' * 22]}}
        _, report, send, _ = self.run_global(self.profile_json('saas', enabled='off'),
                                             entry=stored_entry(resource_uid=''), user_acl=two)
        self.assertEqual(send.requests, [])
        self.assertIn('names 2 SaaS configuration records', report.not_applied[0])

    def test_a_profile_the_graph_did_not_confirm_is_not_written(self):
        plan, entry = self.global_plan(self.profile_json('scripts_only', enabled='off'),
                                       entry=stored_entry(resource_uid=''), user_acl=self.NOOP_ACL)
        plan.results[0].vault_rotation_profile = None                      # the graph could not be read
        send = Sender()
        report = ur.apply_rotations(params_for(entry), plan, send=send, record_key=lambda uid: KEY)
        self.assertEqual(send.requests, [])
        self.assertIn('could not be read from the PAM graph', report.not_applied[0])    # says WHY, not "profile not written"

    def test_the_web_vault_unsupported_saas_combinations_are_never_rewritten(self):
        """"IAM User + SaaS Account" / "General + SaaS Account": the Web Vault refuses to save them; a request without
        saasConfiguration could drop the SaaS record, so update only warns."""
        iam_saas = {'is_iam_user': True, 'rotation_settings': {'noop': True, 'saas_record_uid_list': ['S' * 22]}}
        for json_profile in ('iam_user', 'saas'):
            plan, report, send, _ = self.run_global(self.profile_json(json_profile, enabled='off'),
                                                    entry=stored_entry(resource_uid=''), user_acl=iam_saas)
            self.assertEqual((send.requests, report.applied, report.not_applied), ([], [], []), json_profile)
            self.assertEqual(plan.results[0].vault_rotation_profile, 'iam_saas')
            self.assertTrue(any('the vault has "iam_saas"' in w for w in plan.results[0].warnings))
        # General + SaaS: the SaaS list sits on the user -> machine edge of a general rotation
        plain, _ = make_plan(dict(SAME, enabled='off'))
        self.assertEqual(len(ur.rotation_changes(plain.results[-1])), 1)       # without the SaaS list the JSON is written
        with_saas, entry = make_plan(dict(SAME, enabled='off'),
                                     user_machine_acl={'rotation_settings': {'saas_record_uid_list': ['S' * 22]}})
        send = Sender()
        report = ur.apply_rotations(params_for(entry), with_saas, send=send, record_key=lambda uid: KEY)
        self.assertEqual((send.requests, report.applied, report.not_applied), ([], [], []))
        self.assertEqual(with_saas.results[-1].vault_rotation_profile, 'general_saas')
        self.assertTrue(any('the vault has "general_saas"' in w for r in with_saas.results for w in r.warnings))

    def test_an_added_iam_user_or_scripts_only_rotation_uses_the_import_arguments(self):
        for profile in ('iam_user', 'scripts_only'):
            _, report, send, added = self.run_global(self.profile_json(profile), rotation_state=None)
            self.assertEqual((report.errors, report.not_applied), ([], []), profile)
            self.assertEqual(report.applied, ['admin1: rotation (added)'])
            self.assertEqual(send.requests, [])
            args = added[0]
            self.assertEqual((args['config'], args['record_name'], args['rotation_profile'], args['force']),
                             (tp.CFG, tp.U1, profile, True))
            self.assertNotIn('admin', args)                                # no machine, no admin
            self.assertNotIn('resource', args)
            self.assertEqual((args['enable'], args['schedule_cron_data'], args['pwd_complexity']),
                             (True, ['0 30 18 * * ?'], '32,5,5,5,5'))

    def test_an_added_saas_rotation_carries_the_saas_configuration(self):
        from unittest import mock
        with mock.patch('keepercommander.commands.pam_import.batch_step2.resolve_saas_config_uid',
                        return_value='S' * 22) as resolve:
            _, report, _, added = self.run_global(self.profile_json('saas'), rotation_state=None)
        resolve.assert_called_once_with(mock.ANY, 'saas-cfg', [])
        self.assertEqual((report.errors, report.not_applied), ([], []))
        self.assertEqual((added[0]['rotation_profile'], added[0]['saas_config_uid'], added[0]['saas_in_request']),
                         ('saas', 'S' * 22, True))

    def test_an_added_saas_rotation_without_a_usable_saas_configuration_is_an_error(self):
        from unittest import mock
        with mock.patch('keepercommander.commands.pam_import.batch_step2.resolve_saas_config_uid', return_value=''):
            _, report, _, added = self.run_global(self.profile_json('saas'), rotation_state=None)
        self.assertEqual(added, [])
        self.assertIn('not a single SaaS configuration record', report.errors[0])

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
