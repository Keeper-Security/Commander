"""`update_compare`: KeeperAI, rotation, workflow and credential-reference comparators."""
import copy
import logging
import unittest

from keepercommander.commands.pam_import import update_compare as uc
from keepercommander.commands.pam_import import update_diff as ud
from keepercommander.commands.pam_import.base import PamRotationSettingsObject, PamWorkflowOptions

NOW = 1_700_000_000_000


def quiet(test):
    def wrapper(self, *a, **k):
        logging.disable(logging.CRITICAL)
        try:
            return test(self, *a, **k)
        finally:
            logging.disable(logging.NOTSET)
    return wrapper


def entry(tag, action='added_to_allow', date=1, user='u0'):
    return {'tag': tag, 'auditLog': [{'date': date, 'userId': user, 'action': action}]}


def blob(**levels):
    return {'version': 'v1.0.0', 'riskLevels': levels}


class TestAiSettings(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.current = blob(high={'aiSessionTerminate': False,
                                  'tags': {'allow': [entry('ls', date=5), entry('pwd', date=6)],
                                           'deny': [entry('rm', 'added_to_deny', date=7)]}})

    def plan(self, raw, current=None, **kw):
        return uc.plan_ai(raw, self.current if current is None else current, user_id='me', now_ms=NOW, **kw)

    def test_same_rules_with_different_audit_logs_are_no_change(self):
        raw = {'risk_levels': {'high': {'ai_session_terminate': False,
                                        'activities': {'allow': ['ls', 'pwd'], 'deny': ['rm']}}}}
        new, changes, warnings = self.plan(raw)
        self.assertEqual((new, changes, warnings), (None, [], []))

    def test_a_new_tag_is_added_and_old_entries_keep_their_audit_log(self):
        raw = {'risk_levels': {'high': {'activities': {'allow': ['ls', 'cat']}}}}
        new, changes, _ = self.plan(raw)
        self.assertEqual([(c.op, c.path, c.new) for c in changes], [(ud.OP_ADD, 'ai_settings.riskLevels.high.allow', 'cat')])
        allow = new['riskLevels']['high']['tags']['allow']
        self.assertEqual(allow[0], entry('ls', date=5))                      # untouched, with its own log
        self.assertEqual(allow[2], entry('cat', 'added_to_allow', date=NOW, user='me'))
        self.assertEqual(new['version'], 'v1.0.0')
        self.assertEqual(self.current['riskLevels']['high']['tags']['allow'][0], entry('ls', date=5))   # input intact

    def test_a_tag_in_the_other_list_is_moved_in_merge(self):
        raw = {'risk_levels': {'high': {'activities': {'allow': ['rm']}}}}
        new, changes, _ = self.plan(raw)
        change, = changes
        self.assertEqual((change.op, change.note, change.old, change.new), (ud.OP_CHANGE, 'moved', 'rm (in deny)', 'rm (in allow)'))
        tags = new['riskLevels']['high']['tags']
        self.assertEqual([e['tag'] for e in tags['deny']], [])
        self.assertEqual([e['tag'] for e in tags['allow']], ['ls', 'pwd', 'rm'])

    def test_only_the_lists_the_json_wrote_are_looked_at(self):
        raw = {'risk_levels': {'high': {'activities': {'allow': ['ls']}}}}      # no deny key, no terminate key
        self.assertEqual(self.plan(raw)[1], [])

    def test_session_terminate_change_and_add(self):
        raw = {'risk_levels': {'high': {'ai_session_terminate': True}, 'low': {'ai_session_terminate': True}}}
        new, changes, _ = self.plan(raw)
        self.assertEqual({(c.op, c.path) for c in changes},
                         {(ud.OP_CHANGE, 'ai_settings.riskLevels.high.aiSessionTerminate'),
                          (ud.OP_ADD, 'ai_settings.riskLevels.low.aiSessionTerminate')})
        self.assertIs(new['riskLevels']['high']['aiSessionTerminate'], True)

    def test_removing_tags_needs_overwrite_and_the_graph_flag(self):
        raw = {'risk_levels': {'high': {'activities': {'allow': ['ls'], 'deny': []}}}}
        self.assertEqual(self.plan(raw, mode='overwrite')[1], [])
        new, changes, _ = self.plan(raw, mode='overwrite', graph_overwrite=True)
        self.assertEqual({(c.op, c.path, c.old) for c in changes},
                         {(ud.OP_REMOVE, 'ai_settings.riskLevels.high.allow', 'pwd'),
                          (ud.OP_REMOVE, 'ai_settings.riskLevels.high.deny', 'rm')})
        self.assertEqual([e['tag'] for e in new['riskLevels']['high']['tags']['allow']], ['ls'])

    def test_a_moved_tag_is_not_also_removed_in_overwrite(self):
        raw = {'risk_levels': {'high': {'activities': {'allow': ['ls', 'pwd', 'rm'], 'deny': []}}}}
        _, changes, _ = self.plan(raw, mode='overwrite', graph_overwrite=True)
        self.assertEqual([(c.op, c.note) for c in changes], [(ud.OP_CHANGE, 'moved')])

    def test_idempotent(self):
        raw = {'risk_levels': {'high': {'ai_session_terminate': True, 'activities': {'allow': ['ls', 'cat'], 'deny': ['rm', 'dd']}}}}
        new, changes, _ = self.plan(raw)
        self.assertTrue(changes)
        again, changes2, _ = self.plan(raw, current=new)
        self.assertEqual((again, changes2), (None, []))

    def test_everything_is_added_when_nothing_is_stored(self):
        raw = {'risk_levels': {'critical': {'ai_session_terminate': True, 'activities': {'deny': ['rm']}}}}
        new, changes, _ = uc.plan_ai(raw, None, user_id='me', now_ms=NOW)
        self.assertEqual(len(changes), 2)
        self.assertEqual(new['riskLevels']['critical']['tags']['deny'][0]['auditLog'][0]['action'], 'added_to_deny')

    def test_a_tag_in_both_lists_of_the_json_is_skipped_with_a_warning(self):
        raw = {'risk_levels': {'high': {'activities': {'allow': ['x'], 'deny': ['x']}}}}
        new, changes, warnings = self.plan(raw)
        self.assertEqual((new, changes), (None, []))
        self.assertIn('both allow and deny', warnings[0])

    def test_not_an_object_and_unusable_settings(self):
        self.assertEqual(self.plan('x'), (None, [], []))
        self.assertIn('no usable risk level', self.plan({'risk_levels': {}})[2][0])


def rotation(**data):
    base = {'rotation': 'general', 'enabled': 'on', 'schedule': {'type': 'cron', 'cron': '0 30 18 * * ?'},
            'password_complexity': '32,5,5,5,5'}
    base.update(data)
    return PamRotationSettingsObject.load(base), set(base)


def stored(**over):
    cur = {'record_uid': 'U', 'configuration_uid': 'CFG', 'resource_uid': 'MACH', 'disabled': False,
           'schedule': [{'type': 'CRON', 'cron': '0 30 18 * * ?', 'tz': 'Etc/UTC'}],
           'pwd_complexity': {'length': 32, 'caps': 5, 'lowercase': 5, 'digits': 5, 'special': 5, 'specialChars': '!@'}}
    cur.update(over)
    return cur


class TestRotation(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def diff(self, current, **data):
        obj, explicit = rotation(**data)
        return uc.diff_rotation(obj, explicit, current, expected_resource_uid='MACH', expected_config_uid='CFG', title='u')

    def test_identical(self):
        self.assertEqual(self.diff(stored()), ([], []))

    def test_question_mark_and_star_and_utc_spellings_are_the_same(self):
        cur = stored(schedule=[{'type': 'CRON', 'cron': '0 30 18 * * *', 'tz': 'UTC'}])
        self.assertEqual(self.diff(cur), ([], []))
        self.assertEqual(self.diff(stored(schedule=[{'type': 'CRON', 'cron': '0 30 18 * * ?'}])), ([], []))

    def test_a_simple_web_vault_daily_schedule_equals_the_cron(self):
        cur = stored(schedule=[{'type': 'DAILY', 'time': '18:30:00', 'tz': 'UTC'}])
        self.assertEqual(self.diff(cur), ([], []))
        weekly = stored(schedule=[{'type': 'WEEKLY', 'time': '18:30', 'weekday': 'SATURDAY'}])
        self.assertEqual(self.diff(weekly, schedule={'type': 'cron', 'cron': '0 30 18 ? * SAT'}), ([], []))
        monthly = stored(schedule=[{'type': 'MONTHLY_BY_DAY', 'time': '18:30:00', 'monthDay': '1'}])
        self.assertEqual(self.diff(monthly, schedule={'type': 'cron', 'cron': '0 30 18 1 * ?'}), ([], []))

    def test_other_web_vault_schedules_are_a_difference(self):
        for item in ({'type': 'YEARLY', 'time': '18:30:00'}, {'type': 'DAILY', 'time': '18:30:00', 'intervalCount': 2},
                     {'type': 'RUN_ONCE', 'time': '2030-01-01T00:00:00'}):
            changes, _ = self.diff(stored(schedule=[item]))
            self.assertEqual([c.path for c in changes], ['rotation.schedule'])
            self.assertIn('Web Vault schedule', changes[0].old)

    def test_a_different_cron_or_time_zone_is_a_change(self):
        changes, _ = self.diff(stored(), schedule={'type': 'cron', 'cron': '0 0 4 * * ?'})
        self.assertEqual((changes[0].path, changes[0].old, changes[0].new),
                         ('rotation.schedule', 'cron "0 30 18 * * *" (UTC)', 'cron "0 0 4 * * *" (UTC)'))
        changes, _ = self.diff(stored(), schedule={'type': 'cron', 'cron': '0 30 18 * * ?', 'tz': 'America/Chicago'})
        self.assertEqual(changes[0].new, 'cron "0 30 18 * * *" (America/Chicago)')

    def test_on_demand(self):
        self.assertEqual(self.diff(stored(schedule=''), schedule={'type': 'on-demand'}), ([], []))
        self.assertEqual(self.diff(stored(schedule=[]), schedule={'type': 'on-demand'}), ([], []))
        changes, _ = self.diff(stored(), schedule={'type': 'on-demand'})
        self.assertEqual((changes[0].old, changes[0].new), ('cron "0 30 18 * * *" (UTC)', 'on-demand'))
        changes, _ = self.diff(stored(schedule=''))
        self.assertEqual(changes[0].op, ud.OP_ADD)

    def test_enabled(self):
        changes, _ = self.diff(stored(disabled=True))
        self.assertEqual([(c.path, c.old, c.new) for c in changes], [('rotation.enabled', 'off', 'on')])
        self.assertEqual(self.diff(stored(disabled=True), enabled='default'), ([], []))

    def test_complexity(self):
        changes, _ = self.diff(stored(), password_complexity='20,4,4,4,4')
        self.assertEqual([(c.path, c.old, c.new) for c in changes],
                         [('rotation.password_complexity', '32,5,5,5,5', '20,4,4,4,4')])
        changes, _ = self.diff(stored(pwd_complexity=None))
        self.assertEqual(changes[0].op, ud.OP_ADD)

    def test_only_written_keys_are_compared(self):
        obj, _ = rotation()
        changes, _ = uc.diff_rotation(obj, {'rotation'}, stored(disabled=True, schedule='', pwd_complexity=None),
                                      expected_resource_uid='MACH', expected_config_uid='CFG')
        self.assertEqual(changes, [])

    def test_identity_mismatch_is_a_warning_and_skips_the_user(self):
        changes, warnings = self.diff(stored(resource_uid='OTHER'), enabled='off')
        self.assertEqual(changes, [])
        self.assertIn('owner (resource)', warnings[0])
        changes, warnings = self.diff(stored(configuration_uid='OTHER'))
        self.assertIn('configuration', warnings[0])

    def test_non_general_rotation_belongs_to_the_configuration(self):
        obj, explicit = rotation(rotation='iam_user')
        cur = stored(resource_uid='CFG')
        self.assertEqual(uc.diff_rotation(obj, explicit, cur, expected_resource_uid='MACH', expected_config_uid='CFG'),
                         ([], []))

    def test_a_noop_rotation_has_an_empty_resource_in_the_vault(self):
        """QA 2026-11-19: a scripts_only rotation read back with an empty resource was reported as an owner mismatch."""
        obj, explicit = rotation(rotation='scripts_only')
        for resource in ('', 'CFG'):
            cur = stored(resource_uid=resource)
            self.assertEqual(uc.diff_rotation(obj, explicit, cur, expected_resource_uid='MACH', expected_config_uid='CFG'),
                             ([], []), resource)
        changes, warnings = uc.diff_rotation(obj, {'rotation', 'enabled'}, stored(resource_uid='', disabled=True),
                                             expected_resource_uid='MACH', expected_config_uid='CFG')
        self.assertEqual(([c.path for c in changes], warnings), (['rotation.enabled'], []))

    def test_the_vault_profile_is_read_from_the_user_to_configuration_acl_edge(self):
        def edge(contents, tail='U', head='CFG', edge_type='acl'):
            return {'tail': tail, 'head': head, 'edge_type': edge_type, 'contents': contents}
        profile = lambda *edges: uc.vault_rotation_profile(edges, 'U', 'CFG')       # noqa: E731
        self.assertEqual(profile(edge({'is_iam_user': True, 'belongs_to': True})), 'iam_user')
        self.assertEqual(profile(edge({'rotation_settings': {'noop': True}})), 'scripts_only')
        self.assertEqual(profile(edge({'rotation_settings': {'noop': True, 'saas_record_uid_list': ['S']}})), 'saas')
        self.assertEqual(profile(edge({'rotation_settings': {'noop': True, 'saas_record_uid_list': []}})), 'scripts_only')
        self.assertEqual(profile(edge({'belongs_to': True})), '')                          # general / nothing
        self.assertEqual(profile(), '')
        # another user, another head, or another edge type does not count
        self.assertEqual(profile(edge({'is_iam_user': True}, tail='OTHER'), edge({'is_iam_user': True}, head='MACH'),
                                 edge({'is_iam_user': True}, edge_type='link')), '')

    def test_a_different_saas_record_is_a_warning(self):
        obj, explicit = rotation(rotation='saas', enabled='off')
        cur = stored(resource_uid='')
        args = dict(expected_resource_uid='MACH', expected_config_uid='CFG', title='u', vault_profile='saas')
        changes, warnings = uc.diff_rotation(obj, explicit, cur, json_saas_uid='NEW', vault_saas=['OLD'], **args)
        self.assertEqual(changes, [])
        self.assertIn('SaaS configuration (the vault rotation uses "OLD", the JSON names "NEW")', warnings[0])
        for json_uid, vault in (('OLD', ['OLD']), ('', ['OLD']), ('NEW', []), ('NEW', None)):   # same / not known: compared as before
            changes, warnings = uc.diff_rotation(obj, explicit, cur, json_saas_uid=json_uid, vault_saas=vault, **args)
            self.assertEqual((len(changes), warnings), (1, []), (json_uid, vault))

    def test_the_unsupported_saas_combinations_are_told_apart(self):
        def edge(contents, tail='U', head='CFG'):
            return {'tail': tail, 'head': head, 'edge_type': 'acl', 'contents': contents}
        saas = {'saas_record_uid_list': ['S']}
        # IAM User + SaaS Account: is_iam_user AND a SaaS list on the configuration edge
        self.assertEqual(uc.vault_rotation_profile([edge({'is_iam_user': True, 'rotation_settings': saas})],
                                                   'U', 'CFG', 'MACH'), 'iam_saas')
        # General + SaaS Account: the SaaS list is on the user -> machine edge (only looked at with a machine)
        machine_edge = edge({'belongs_to': True, 'rotation_settings': saas}, head='MACH')
        self.assertEqual(uc.vault_rotation_profile([machine_edge], 'U', 'CFG', 'MACH'), 'general_saas')
        self.assertEqual(uc.vault_rotation_profile([machine_edge], 'U', 'CFG'), '')
        self.assertEqual(uc.vault_rotation_profile([edge({'belongs_to': True}, head='MACH')], 'U', 'CFG', 'MACH'), '')
        # a general JSON is checked against the combinations only; any other profile is caught by the owner check
        obj, explicit = rotation(enabled='off')
        for vault in ('iam_saas', 'general_saas'):
            changes, warnings = uc.diff_rotation(obj, explicit, stored(), expected_resource_uid='MACH',
                                                 expected_config_uid='CFG', vault_profile=vault)
            self.assertEqual(changes, [], vault)
            self.assertIn(f'type (the vault has "{vault}")', warnings[0])
        changes, warnings = uc.diff_rotation(obj, explicit, stored(), expected_resource_uid='MACH',
                                             expected_config_uid='CFG', vault_profile='')
        self.assertEqual((len(changes), warnings), (1, []))

    def test_the_saas_record_is_read_from_the_same_edge(self):
        saas = {'tail': 'U', 'head': 'CFG', 'edge_type': 'acl',
                'contents': {'rotation_settings': {'noop': True, 'saas_record_uid_list': ['S1', 'S2']}}}
        self.assertEqual(uc.vault_saas_uids([saas], 'U', 'CFG'), ['S1', 'S2'])
        self.assertEqual(uc.vault_saas_uids([saas], 'OTHER', 'CFG'), [])
        self.assertEqual(uc.vault_saas_uids([dict(saas, head='MACH')], 'U', 'CFG'), [])
        self.assertEqual(uc.vault_saas_uids([dict(saas, edge_type='link')], 'U', 'CFG'), [])
        noop = dict(saas, contents={'rotation_settings': {'noop': True}})
        self.assertEqual(uc.vault_saas_uids([noop], 'U', 'CFG'), [])

    def test_a_json_profile_that_is_not_the_vault_profile_is_a_warning(self):
        obj, explicit = rotation(rotation='scripts_only', enabled='off')
        cur = stored(resource_uid='')
        for vault in ('saas', 'iam_user', ''):
            changes, warnings = uc.diff_rotation(obj, explicit, cur, expected_resource_uid='MACH',
                                                 expected_config_uid='CFG', title='u', vault_profile=vault)
            self.assertEqual(changes, [], vault)
            self.assertIn(f'rotation type (the vault has "{vault or "general"}")', warnings[0])
        changes, warnings = uc.diff_rotation(obj, explicit, cur, expected_resource_uid='MACH', expected_config_uid='CFG',
                                             vault_profile='scripts_only')
        self.assertEqual(warnings, [])
        self.assertEqual([c.path for c in changes], ['rotation.enabled'])
        # an unknown vault profile (the graph was not read) compares as before; a general JSON is not checked here
        self.assertEqual(uc.diff_rotation(obj, {'rotation'}, cur, expected_config_uid='CFG', vault_profile=None), ([], []))

    def test_a_machine_rotation_where_the_json_says_noop_is_still_a_mismatch(self):
        obj, explicit = rotation(rotation='scripts_only')
        changes, warnings = uc.diff_rotation(obj, explicit, stored(resource_uid='MACH'),
                                             expected_resource_uid='MACH', expected_config_uid='CFG', title='u')
        self.assertEqual(changes, [])
        self.assertIn('owner (resource)', warnings[0])

    def test_a_general_json_on_an_empty_resource_is_still_a_mismatch(self):
        changes, warnings = self.diff(stored(resource_uid=''), enabled='off')
        self.assertEqual(changes, [])
        self.assertIn('owner (resource)', warnings[0])

    def test_no_rotation_in_the_vault_is_one_add(self):
        changes, warnings = self.diff(None)
        change, = changes
        self.assertEqual((change.op, change.path, warnings), (ud.OP_ADD, 'rotation', []))
        self.assertEqual(change.new['rotation'], 'general')


def wf(**data):
    raw = {'approvals_needed': 1, 'checkout_needed': True, 'require_reason': True, 'access_duration': '2h',
           'allowed_times': {'allowed_days': ['mon', 'fri'], 'time_ranges': [{'start': '09:00', 'end': '17:30'}],
                             'timezone': 'America/Chicago'},
           'approvers': [{'principal': {'type': 'user', 'email': 'A@x.com'}, 'escalation': True, 'escalation_after': '1h'},
                         {'principal': {'type': 'team', 'team_uid_base64url': 'dGVhbQ-_'}}]}
    raw.update(data)
    return raw, PamWorkflowOptions.load(raw)


STORED_WF = {
    'parameters': {'approvalsNeeded': 1, 'checkoutNeeded': True, 'requireReason': True, 'accessLength': '7200000',
                   'allowedTimes': {'allowedDays': ['FRIDAY', 'MONDAY'], 'timeRanges': [{'startTime': 900, 'endTime': 1730}],
                                    'timeZone': 'America/Chicago'}},
    'approvers': [{'user': 'a@x.com', 'escalation': True, 'escalationAfterMs': '3600000'},
                  {'teamUid': 'dGVhbQ+/'}],
}


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def diff(self, current=STORED_WF, **kw):
        raw, opts = wf(**kw.pop('data', {}))
        return uc.diff_workflow(opts, raw, copy.deepcopy(current), **kw)

    def test_identical(self):
        self.assertEqual(self.diff(), ([], []))

    def test_flag_duration_days_ranges_timezone(self):
        cur = copy.deepcopy(STORED_WF)
        cur['parameters'].update({'requireReason': False, 'accessLength': '3600000'})
        cur['parameters']['allowedTimes'].update({'allowedDays': ['MONDAY'], 'timeRanges': [{'startTime': 800, 'endTime': 1700}],
                                                  'timeZone': 'UTC'})
        changes, _ = self.diff(cur)
        self.assertEqual({c.path for c in changes},
                         {'workflow.require_reason', 'workflow.access_duration', 'workflow.allowed_days',
                          'workflow.time_ranges', 'workflow.timezone'})

    def test_only_written_keys_are_compared(self):
        raw = {'approvals_needed': 1}
        opts = PamWorkflowOptions.load(raw)
        cur = copy.deepcopy(STORED_WF)
        cur['parameters']['requireReason'] = False
        self.assertEqual(uc.diff_workflow(opts, raw, cur), ([], []))

    def test_approvers_are_a_union_and_escalation_changes_are_found(self):
        cur = copy.deepcopy(STORED_WF)
        cur['approvers'] = [{'user': 'a@x.com'}, {'user': 'old@x.com'}]
        changes, _ = self.diff(cur)
        self.assertEqual({(c.op, c.path) for c in changes},
                         {(ud.OP_CHANGE, 'workflow.approvers.user:a@x.com'), (ud.OP_ADD, 'workflow.approvers')})
        self.assertFalse([c for c in changes if c.op == ud.OP_REMOVE])          # merge never removes
        esc = next(c for c in changes if c.path == 'workflow.approvers.user:a@x.com')
        self.assertEqual((esc.old, esc.new), ('no escalation', 'escalates after 1h'))

    def test_escalation_text(self):
        self.assertEqual(uc._escalation_text((False, 0)), 'no escalation')
        self.assertEqual(uc._escalation_text((True, 7200000)), 'escalates after 2h')
        self.assertEqual(uc._escalation_text((True, 1800000)), 'escalates after 30m')
        self.assertEqual(uc._escalation_text((True, 90000)), 'escalates after 90s')
        self.assertEqual(uc._escalation_text((True, 0)), 'escalates at once')

    def test_team_uids_compare_across_base64_variants(self):
        # the stored one is standard base64 (+ /), the JSON one url-safe (- _): the same team
        self.assertEqual(self.diff(), ([], []))

    def test_overwrite_removes_approvers_only_with_the_graph_flag(self):
        cur = copy.deepcopy(STORED_WF)
        cur['approvers'].append({'user': 'old@x.com'})
        self.assertEqual(self.diff(cur, mode='overwrite'), ([], []))
        changes, _ = self.diff(cur, mode='overwrite', graph_overwrite=True)
        self.assertEqual([(c.op, c.old) for c in changes], [(ud.OP_REMOVE, 'user:old@x.com')])

    def test_user_id_only_approvers_can_be_resolved(self):
        cur = copy.deepcopy(STORED_WF)
        cur['approvers'][0] = {'userId': 77, 'escalation': True, 'escalationAfterMs': '3600000'}
        self.assertEqual(self.diff(cur, user_email_of=lambda i: 'a@x.com'), ([], []))

    def test_no_workflow_in_the_vault_is_one_add(self):
        changes, _ = self.diff(None)
        self.assertEqual([(c.op, c.path) for c in changes], [(ud.OP_ADD, 'workflow')])

    def test_a_trivial_section_is_a_warning(self):
        raw = {'approvals_needed': 0}
        changes, warnings = uc.diff_workflow(PamWorkflowOptions.load(raw), raw, STORED_WF, title='R')
        self.assertEqual(changes, [])
        self.assertIn('trivial', warnings[0])

    def test_no_section_nothing_to_do(self):
        self.assertEqual(uc.diff_workflow(None, None, STORED_WF), ([], []))


class TestCredentialRefs(unittest.TestCase):
    RES = 'MACH'

    def edges(self, admin=None, launch=None, extra=()):
        out = []
        if admin:
            out.append({'tail': admin, 'head': self.RES, 'edge_type': 'acl', 'contents': {'is_admin': True}})
        if launch:
            out.append({'tail': launch, 'head': self.RES, 'edge_type': 'acl', 'contents': {'is_launch_credential': True}})
        out.extend(extra)
        return out

    def diff(self, resolved, explicit, conn=None, **edge_kw):
        return uc.diff_credential_refs(resolved, explicit, conn, self.edges(**edge_kw), self.RES, title='M')

    def test_same_credentials_are_no_change(self):
        resolved = {'admin_credential': 'A', 'launch_credential': 'L'}
        changes, warnings = self.diff(resolved, resolved, {'userRecords': ['A']}, admin='A', launch='L')
        self.assertEqual((changes, warnings), ([], []))

    def test_replacing_the_admin_changes_the_edge_only_and_warns(self):
        # the import does not write connection.userRecords (dump of a PROD import): nothing to compare in the record
        changes, warnings = self.diff({'admin_credential': 'B'}, {'admin_credential'}, {'userRecords': ['A']}, admin='A')
        self.assertEqual({(c.kind, c.op, c.path) for c in changes}, {(ud.KIND_GRAPH, ud.OP_CHANGE, 'acl.is_admin')})
        self.assertIn('administrative credential changes from A to B', warnings[0])

    def test_launch_credential_is_a_single_slot(self):
        changes, warnings = self.diff({'launch_credential': 'L2'}, {'launch_credential'}, launch='L1')
        self.assertEqual([(c.path, c.old, c.new) for c in changes], [('acl.is_launch_credential', 'L1', 'L2')])
        self.assertIn('launch credential changes', warnings[0])

    def test_two_holders_of_one_slot_collapse_to_the_wanted_one(self):
        extra = [{'tail': 'X', 'head': self.RES, 'edge_type': 'acl', 'contents': {'is_launch_credential': True}}]
        changes, _ = self.diff({'launch_credential': 'L'}, {'launch_credential'}, launch='L', extra=extra)
        self.assertEqual(len(changes), 1)

    def test_no_current_credential_is_an_add(self):
        changes, warnings = self.diff({'admin_credential': 'A'}, {'admin_credential'})
        self.assertEqual({(c.kind, c.op) for c in changes}, {(ud.KIND_GRAPH, ud.OP_ADD)})
        self.assertEqual(warnings, [])

    def test_not_written_means_not_compared(self):
        self.assertEqual(self.diff({'admin_credential': 'B'}, set(), admin='A'), ([], []))

    def test_unresolved_reference_is_a_warning(self):
        changes, warnings = self.diff({'admin_credential': None}, {'admin_credential'}, admin='A')
        self.assertEqual(changes, [])
        self.assertIn('could not be resolved', warnings[0])

    def test_autofill_and_sftp_references_live_in_the_record(self):
        conn = {'httpCredentialsUid': 'H1', 'sftp': {'sftpResourceUid': 'S1'}}
        resolved = {'http_credentials': 'H2', 'sftp_resource': 'S1', 'sftp_user': 'U1'}
        changes, _ = self.diff(resolved, set(resolved), conn)
        self.assertEqual({(c.op, c.path, c.new) for c in changes},
                         {(ud.OP_CHANGE, 'pamSettings.connection.httpCredentialsUid', 'H2'),
                          (ud.OP_ADD, 'pamSettings.connection.sftp.sftpUserUid', 'U1')})

    def test_edges_of_other_resources_and_non_acl_edges_are_ignored(self):
        extra = [{'tail': 'Z', 'head': 'OTHER', 'edge_type': 'acl', 'contents': {'is_admin': True}},
                 {'tail': 'Y', 'head': self.RES, 'edge_type': 'link', 'contents': {'is_admin': True}}]
        holders = uc.acl_holders(extra, self.RES)
        self.assertEqual(holders, {'admin': [], 'launch': []})


if __name__ == '__main__':
    unittest.main()
