"""`update_apply` (graph side): the router requests built from a plan, with the router replaced (no server)."""
import json
import logging
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(__file__))

import keepercommander.commands.record  # noqa: F401,E402

from keepercommander.commands.pam_import import update_apply as ua  # noqa: E402
from keepercommander.commands.pam_import import update_compare as uc  # noqa: E402
from keepercommander.commands.pam_import import update_diff as ud  # noqa: E402
from keepercommander.commands.pam_import import update_plan as up  # noqa: E402
from keepercommander.commands.pam_import.base import PamWorkflowOptions  # noqa: E402
from keepercommander.commands.pam_import.import_items import load_items  # noqa: E402
from keepercommander.keeper_dag.crypto import decrypt_aes  # noqa: E402
from keepercommander.utils import base64_url_decode  # noqa: E402

import test_update_plan as tp  # noqa: E402

KEY = b'k' * 32
OTHER = 'OTHER' + 'A' * 17


class Quiet(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)


def params():
    return SimpleNamespace(record_cache={tp.M1: {'record_key_unencrypted': KEY}})


def plan_for(raw, st=None, **kw):
    items, _ = load_items({'resources': [raw]}, tp.CFG)
    return up.build_plan(items, tp.index(), st or tp.state(), config_uid=tp.CFG, scope_records=[], **kw)


class Recorder:
    def __init__(self, fail=False):
        self.requests = []
        self.workflows = []
        self.fail = fail

    def send(self, rq):
        if self.fail:
            raise RuntimeError('RRC_NOT_ALLOWED: you may not')
        self.requests.append(rq)

    def workflow(self, uid, title, opts):
        if self.fail:
            raise RuntimeError('workflow boom')
        self.workflows.append((uid, title, opts))


def run(plan, recorder=None):
    recorder = recorder or Recorder()
    report = ua.apply_graph(params(), plan, tp.CFG, send=recorder.send, workflow=recorder.workflow)
    return report, recorder


def machine(**options):
    raw = tp.machine_json(users=[])
    raw['pam_settings']['options'] = options
    return raw


class TestMeta(Quiet):
    def test_changed_flags_become_one_merged_meta_request(self):
        report, rec = run(plan_for(machine(connections='off', tunneling='on', rotation='on')))
        rq, = rec.requests
        meta = json.loads(rq.meta)
        self.assertEqual(meta, {'version': 1, 'allowedSettings': {'connections': False, 'portForwards': True,
                                                                  'rotation': True}})
        self.assertEqual(base64_url_decode(tp.M1), rq.recordUid)
        self.assertFalse(rq.HasField('connectUsers') or rq.HasField('jitSettings') or rq.HasField('keeperAiSettings'))
        self.assertEqual(report.applied, ['M1: graph settings'])

    def test_unchanged_flags_send_nothing(self):
        report, rec = run(plan_for(machine(connections='on')))
        self.assertEqual((rec.requests, report.applied, report.errors), ([], [], []))

    def test_no_update_services_is_the_update_services_field_not_meta(self):
        plan = plan_for(machine(update_services='off'))
        rq, = run(plan)[1].requests
        self.assertTrue(rq.HasField('updateServices'))
        self.assertFalse(rq.updateServices)          # off -> no_update_services true -> updateServices false
        self.assertFalse(rq.HasField('meta'))

    def test_rotate_on_termination_is_a_meta_key(self):
        raw = tp.machine_json(users=[])
        raw['pam_settings']['connection']['rotate_creds_on_session_termination'] = True
        rq, = run(plan_for(raw))[1].requests
        self.assertEqual(json.loads(rq.meta)['rotateOnTermination'], True)

    def test_a_reset_to_default_is_never_sent(self):
        plan = plan_for(machine(connections='default'))
        self.assertTrue(any('through the router' in w for w in plan.warnings))
        self.assertEqual(run(plan)[1].requests, [])


class TestBlobs(Quiet):
    def test_jit_blob_is_the_stored_one_plus_the_changed_keys_encrypted_with_the_record_key(self):
        st = tp.state()
        st.graphs[0] = st.graphs[0].__class__(0, list(st.graphs[0]._all.values()) + [
            tp_edge('data', 'jit_settings', {'createEphemeral': False, 'elevate': True, 'elevationMethod': 'group'})])
        raw = machine(jit_settings={'create_ephemeral': True})
        plan = plan_for(raw, st=st)
        rq, = run(plan)[1].requests
        blob = json.loads(decrypt_aes(rq.jitSettings, KEY))
        self.assertEqual(blob, {'createEphemeral': True, 'elevate': True, 'elevationMethod': 'group'})
        self.assertTrue(rq.HasField('meta'))                  # the router only loads the edges for a request with meta
        self.assertEqual(json.loads(rq.meta), {'version': 1, 'allowedSettings': {}})

    def test_ai_blob_keeps_unchanged_tags(self):
        st = tp.state()
        current = {'version': 'v1.0.0', 'riskLevels': {'high': {'tags': {'allow': [
            {'tag': 'ls', 'auditLog': [{'date': 1, 'userId': 'u', 'action': 'added_to_allow'}]}], 'deny': []}}}}
        st.graphs[0] = st.graphs[0].__class__(0, list(st.graphs[0]._all.values()) + [tp_edge('data', 'ai_settings', current)])
        raw = machine(ai_settings={'risk_levels': {'high': {'activities': {'allow': ['ls', 'cat']}}}})
        rq, = run(plan_for(raw, st=st))[1].requests
        blob = json.loads(decrypt_aes(rq.keeperAiSettings, KEY))
        tags = blob['riskLevels']['high']['tags']['allow']
        self.assertEqual([t['tag'] for t in tags], ['ls', 'cat'])
        self.assertEqual(tags[0]['auditLog'][0]['date'], 1)
        self.assertTrue(rq.HasField('meta'))

    def test_a_missing_record_key_is_an_apply_error_for_that_resource(self):
        st = tp.state()
        raw = machine(jit_settings={'create_ephemeral': True})
        plan = plan_for(raw, st=st)
        report = ua.apply_graph(SimpleNamespace(record_cache={}), plan, tp.CFG, send=Recorder().send,
                                workflow=Recorder().workflow)
        self.assertIn('the record key of', report.errors[0])


def tp_edge(kind, path, contents):
    from keepercommander.commands.pam_import.vault_reader import CurrentEdge
    return CurrentEdge(tp.M1, tp.M1, kind, path, contents)


class TestCredentials(Quiet):
    def raw(self, **conn):
        raw = tp.machine_json(users=[])
        raw['pam_settings']['connection'].update(conn)
        return raw

    def test_a_new_admin_is_sent_with_the_current_launch_holders(self):
        st = tp.state(acl_admin=tp.U2)
        st.graphs[0] = st.graphs[0].__class__(0, list(st.graphs[0]._all.values()) + [
            __import__('keepercommander.commands.pam_import.vault_reader', fromlist=['CurrentEdge']).CurrentEdge(
                'LAUNCH' + 'A' * 16, tp.M1, 'acl', None, {'is_launch_credential': True})])
        plan = plan_for(self.raw(administrative_credentials='admin1'), st=st)
        rq, = run(plan)[1].requests
        self.assertEqual(rq.adminUid, base64_url_decode(tp.U1))
        self.assertEqual(list(rq.connectUsers.uids), [base64_url_decode('LAUNCH' + 'A' * 16)])
        self.assertFalse(rq.HasField('meta'))

    def test_a_new_launch_credential_replaces_the_list_and_leaves_the_admin_alone(self):
        plan = plan_for(self.raw(launch_credentials='admin1'))
        rq, = run(plan)[1].requests
        self.assertEqual(list(rq.connectUsers.uids), [base64_url_decode(tp.U1)])
        self.assertFalse(rq.HasField('adminUid'))

    def test_the_unchanged_admin_sends_nothing(self):
        self.assertEqual(run(plan_for(self.raw()))[1].requests, [])


class TestWorkflow(Quiet):
    STORED = {'parameters': {'approvalsNeeded': 1, 'checkoutNeeded': False, 'requireReason': True,
                             'accessLength': '86400000'},
              'approvers': [{'user': 'a@x.com'}, {'teamUid': 'dGVhbQ+/'}]}

    def plan(self, wf, current=None, **kw):
        raw = machine(workflow=wf)
        st = tp.state()
        st.workflows[tp.M1] = current if current is not None else self.STORED
        return plan_for(raw, st=st, **kw)

    def test_merge_overlays_only_the_written_keys_on_the_stored_workflow(self):
        report, rec = run(self.plan({'checkout_needed': True, 'approvers': [
            {'principal': {'type': 'user', 'email': 'b@x.com'}}]}))
        (uid, title, opts), = rec.workflows
        self.assertEqual((uid, title), (tp.M1, 'M1'))
        self.assertTrue(opts.checkout_needed)
        self.assertTrue(opts.require_reason)                 # not written in the JSON: kept
        self.assertEqual(opts.approvals_needed, 1)
        self.assertEqual(sorted(a['email'] or a['team_uid_b64'] for a in opts.approvers),
                         ['a@x.com', 'b@x.com', 'dGVhbQ-_'])        # union, team uid in the url-safe form
        self.assertEqual(report.applied, ['M1: workflow'])

    def test_an_unchanged_workflow_is_not_sent(self):
        report, rec = run(self.plan({'approvals_needed': 1, 'require_reason': True}))
        self.assertEqual((rec.workflows, report.applied), ([], []))

    def test_an_approver_that_cannot_be_resolved_stops_the_workflow_update_with_a_warning(self):
        current = dict(self.STORED, approvers=[{'userId': 77}])
        plan = self.plan({'checkout_needed': True}, current=current)
        self.assertTrue(any('cannot be updated safely' in w for w in plan.warnings))
        self.assertEqual(run(plan)[1].workflows, [])

    def test_overwrite_with_the_graph_flag_makes_the_approvers_equal_to_the_json(self):
        wf = {'approvals_needed': 1, 'approvers': [{'principal': {'type': 'user', 'email': 'b@x.com'}}]}
        _, rec = run(self.plan(wf, mode='overwrite', graph_overwrite=True))
        self.assertEqual([a['email'] for a in rec.workflows[0][2].approvers], ['b@x.com'])

    def test_a_new_workflow_is_sent_as_the_json_options(self):
        raw = machine(workflow={'approvals_needed': 1, 'approvers': [{'principal': {'type': 'user', 'email': 'a@x.com'}}]})
        st = tp.state()
        st.workflows[tp.M1] = None                           # the reader records "no workflow" as None
        _, rec = run(plan_for(raw, st=st))
        self.assertEqual(rec.workflows[0][2].approvals_needed, 1)


class TestErrorsAndLimits(Quiet):
    def test_router_failures_are_collected_per_resource_and_the_run_goes_on(self):
        plan = plan_for(machine(connections='off'))
        report, _ = run(plan, Recorder(fail=True))
        self.assertEqual(len(report.errors), 1)
        self.assertIn('M1: graph settings were not written: RRC_NOT_ALLOWED', report.errors[0])
        self.assertFalse(report.ok)

    def test_a_workflow_failure_is_reported_separately(self):
        plan = TestWorkflow().plan({'checkout_needed': True})
        report, _ = run(plan, Recorder(fail=True))
        self.assertTrue(any('the workflow was not written: workflow boom' in e for e in report.errors))

    def test_rotation_and_record_field_changes_are_left_to_update_rotation_and_update_records(self):
        raw = tp.machine_json(operating_system='windows')
        raw['users'][0]['rotation_settings']['schedule'] = {'type': 'cron', 'cron': '0 0 4 * * ?'}
        st = tp.state(rotation=dict(tp.IDLE_ROTATION, schedule=[{'type': 'CRON', 'cron': '0 30 18 * * ?'}]))
        report, rec = run(plan_for(raw, st=st))
        self.assertEqual((report.not_applied, report.applied, report.errors), ([], [], []))    # written by update_rotation / update_records, not here
        self.assertEqual(rec.requests, [])

    def test_the_request_is_built_only_from_graph_changes(self):
        plan = plan_for(tp.machine_json(users=[], operating_system='windows'))
        self.assertIsNone(ua.build_resource_request(params(), tp.CFG, plan.results[0]))


class TestWorkflowOptionsFromConfig(Quiet):
    def test_round_trip_of_days_ranges_and_timezone(self):
        config = {'parameters': {'approvalsNeeded': 2, 'accessLength': '7200000', 'requireMFA': True,
                                 'allowedTimes': {'allowedDays': ['MONDAY', 'FRIDAY'],
                                                  'timeRanges': [{'startTime': 900, 'endTime': 1730}],
                                                  'timeZone': 'UTC'}},
                  'approvers': [{'user': 'a@x.com', 'escalation': True, 'escalationAfterMs': '60000'}]}
        opts = uc.workflow_options_from_config(config)
        self.assertEqual((opts.approvals_needed, opts.access_duration_ms, opts.require_mfa), (2, 7_200_000, True))
        self.assertEqual((opts.allowed_days, opts.time_ranges, opts.timezone),
                         (['mon', 'fri'], [{'start': '09:00', 'end': '17:30'}], 'UTC'))
        self.assertEqual(opts.approvers[0]['escalation_after_ms'], 60000)
        # and it compares equal to itself
        raw = {'approvals_needed': 2, 'allowed_times': {'allowed_days': ['mon', 'fri']}}
        self.assertEqual(uc.diff_workflow(PamWorkflowOptions.load({'approvals_needed': 2, 'allowed_times': {
            'allowed_days': ['mon', 'fri']}}), raw, config), ([], []))


if __name__ == '__main__':
    unittest.main()
