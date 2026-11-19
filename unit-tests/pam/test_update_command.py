"""`update_report` and the `pam project update` command: options, output formats, confirmation (no server)."""
import io
import json
import logging
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))

import keepercommander.commands.record  # noqa: F401,E402

from keepercommander.commands.pam_import import update as upd  # noqa: E402
from keepercommander.commands.pam_import import update_diff as ud  # noqa: E402
from keepercommander.commands.pam_import import update_plan as up  # noqa: E402
from keepercommander.commands.pam_import import update_report as rep  # noqa: E402
from keepercommander.commands.pam_import.import_items import load_items  # noqa: E402
from keepercommander.error import CommandError  # noqa: E402

import test_update_plan as tp  # noqa: E402


def make_plan(changed=True, password_diff=False, errors=(), **plan_kw):
    raw = tp.machine_json(operating_system='windows' if changed else 'linux')
    items, _ = load_items({'resources': [raw]}, tp.CFG)
    user = tp.vault_user('OLD' if password_diff else 'pw')
    plan = up.build_plan(items, tp.index(), tp.state(user=user), config_uid=tp.CFG,
                         scope_records=TestReport.SCOPE, **plan_kw)
    plan.errors.extend(errors)
    return plan


class Quiet(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)


class TestReport(Quiet):
    SCOPE = [(tp.M1, 'M1', 'pamMachine', ''), (tp.U1, 'admin1', 'pamUser', 'root'), ('X' * 22, 'Other', 'pamMachine', '')]

    def test_brief_table_summary_and_tip(self):
        text = rep.format_text(make_plan())
        self.assertIn('Record', text.splitlines()[0])
        self.assertIn('~ M1', text)
        self.assertIn('1 of 2 records would change (record 1, graph 0); 1 identical.', text)
        self.assertIn('Not in the JSON (kept as is): 1.', text)
        self.assertTrue(text.rstrip().endswith(rep.TIP))

    def test_verbose_lists_changes_and_identical_records_and_has_no_tip(self):
        text = rep.format_text(make_plan(), verbose=True)
        self.assertIn('~ M1  (pamMachine, uid', text)
        self.assertIn('record  ~ text "operatingSystem": linux -> windows', text)
        self.assertIn('= admin1  (identical)', text)
        self.assertNotIn('Tip:', text)

    def test_nothing_to_do_prints_the_summary_only(self):
        text = rep.format_text(make_plan(changed=False))
        self.assertIn('0 of 2 records would change', text)
        self.assertNotIn('~ M1', text)

    def test_errors_are_listed_first(self):
        text = rep.format_text(make_plan(errors=['record "Z" not found in the vault']))
        self.assertTrue(text.startswith('1 error(s) - nothing would be written:'))
        self.assertIn('ERROR: record "Z" not found in the vault', text)

    def test_the_brief_table_is_capped(self):
        plan = make_plan()
        template = plan.results[0]
        plan.results = [template] * 60
        text = rep.format_text(plan)
        self.assertIn('... and 10 more (use --format json for all)', text)
        self.assertEqual(text.count('~ M1'), 50)

    def test_passwords_are_never_printed_and_the_warnings_follow_the_flag(self):
        off = rep.format_text(make_plan(password_diff=True), verbose=True)
        self.assertIn('1 password(s) in the JSON differ from the vault and were skipped', off)
        on = make_plan(password_diff=True, include_passwords=True)
        text = rep.format_text(on, verbose=True)
        self.assertIn('WARNING: --include-passwords IS ON - 1 PASSWORD(S) WILL BE REPLACED', text)
        self.assertIn('1 OF THEM ON USERS WITH ROTATION ENABLED', text)
        self.assertIn('<hidden>', text)
        for output in (off, text, json.dumps(rep.to_dict(on, verbose=True))):
            self.assertNotIn('OLD', output)
            self.assertNotIn('"pw"', output)
        self.assertIn('0 PASSWORD(S)', rep.password_summary(make_plan(include_passwords=True))[0])

    def test_json_shape(self):
        data = rep.to_dict(make_plan(), verbose=False)
        self.assertEqual(sorted(data), ['changes', 'errors', 'skipped', 'summary', 'warnings'])
        self.assertEqual(data['summary']['changed'], 1)
        self.assertEqual(data['changes'], [{'record_title': 'M1', 'uid': tp.M1, 'type': 'pamMachine',
                                            'record_changes': 1, 'graph_changes': 0}])
        self.assertEqual(data['skipped'][0]['reason'], 'not in the JSON')
        detailed = rep.to_dict(make_plan(), verbose=True)
        self.assertEqual(len(detailed['changes']), 2)          # identical records are listed with -v
        self.assertEqual(detailed['changes'][0]['details'][0]['path'], 'text "operatingSystem"')

    def test_estimate_json_has_the_summary_only(self):
        data = rep.to_dict(make_plan(), estimate=True)
        self.assertEqual(sorted(data), ['errors', 'summary', 'warnings'])
        self.assertEqual(rep.estimate_line(make_plan()), '1 of 2 records differ and need updating; 1 identical; Not in the JSON: 1.')


def run_command(kwargs, plan=None, tty=True, service_mode=False, answer=None):
    cmd = upd.PAMProjectUpdateCommand()
    params = SimpleNamespace(service_mode=service_mode)
    base = {'config': 'C', 'file_name': 'f.json', 'output_format': 'text', 'dry_run': False, 'verbose': False,
            'yes': False, 'mode': 'merge', 'include_passwords': False, 'skip_attachments': False,
            'estimate': False, 'syntax_help': False}
    base.update(kwargs)
    out = io.StringIO()
    stdin = SimpleNamespace(isatty=lambda: tty)
    with patch.object(upd.PAMProjectUpdateCommand, 'build_plan', return_value=plan), \
            patch.object(upd.sys, 'stdin', stdin), \
            patch('builtins.input', side_effect=[answer] if answer is not None else AssertionError('no prompt expected')), \
            redirect_stdout(out):
        result = cmd.execute(params, **base)
    return result, out.getvalue()


class TestOptions(Quiet):
    def test_syntax_help_is_exclusive(self):
        result, out = run_command({'syntax_help': True, 'config': None, 'file_name': None})
        self.assertIsNone(result)
        self.assertIn('MODES (--mode)', out)
        self.assertIn('ONLY when the', out)           # the overwrite rules are part of the help
        for other in ({'dry_run': True}, {'mode': 'overwrite'}, {'config': 'C'}, {'yes': True}):
            with self.assertRaises(CommandError) as ctx:
                run_command({'syntax_help': True, 'config': None, 'file_name': None, **other})
            self.assertIn('cannot be combined', str(ctx.exception))

    def test_config_and_filename_are_required_without_syntax_help(self):
        with self.assertRaises(CommandError):
            run_command({'config': None})
        with self.assertRaises(CommandError):
            run_command({'file_name': ''})

    def test_format_json_needs_yes_dry_run_or_estimate(self):
        with self.assertRaises(CommandError) as ctx:
            run_command({'output_format': 'json'}, plan=make_plan())
        self.assertIn('--format json needs -y, -d or --estimate', str(ctx.exception))

    def test_a_write_run_needs_yes_in_service_mode_and_without_a_terminal(self):
        for kw in ({'service_mode': True}, {'tty': False}):
            with self.assertRaises(CommandError) as ctx:
                run_command({}, plan=make_plan(), **kw)
            self.assertIn('needs -y (or -d)', str(ctx.exception))
        # a dry run is always fine
        run_command({'dry_run': True}, plan=make_plan(), tty=False, service_mode=True)
        run_command({'estimate': True}, plan=make_plan(), tty=False, service_mode=True)


class TestRun(Quiet):
    def test_dry_run_prints_the_report_and_writes_nothing(self):
        result, out = run_command({'dry_run': True}, plan=make_plan())
        self.assertIsNone(result)
        self.assertIn('~ M1', out)
        self.assertIn('[DRY RUN COMPLETE]', out)

    def test_estimate_prints_the_count_only(self):
        _, out = run_command({'estimate': True, 'verbose': True}, plan=make_plan())
        self.assertIn('1 of 2 records differ and need updating', out)
        self.assertNotIn('~ M1', out)

    def test_json_is_returned_not_printed(self):
        result, out = run_command({'dry_run': True, 'output_format': 'json'}, plan=make_plan())
        self.assertEqual(out, '')
        self.assertEqual(json.loads(result)['summary']['changed'], 1)

    def test_plan_errors_are_returned_in_json_but_raised_in_text(self):
        plan = make_plan(errors=['record "Z" not found in the vault'])
        result, _ = run_command({'dry_run': True, 'output_format': 'json'}, plan=plan)
        self.assertEqual(json.loads(result)['errors'], ['record "Z" not found in the vault'])
        with self.assertRaises(CommandError) as ctx:
            run_command({'dry_run': True}, plan=plan)
        self.assertIn('1 error(s); nothing was written', str(ctx.exception))

    def test_a_write_run_with_errors_never_asks_and_never_writes(self):
        with self.assertRaises(CommandError):
            run_command({}, plan=make_plan(errors=['x']))

    def test_nothing_to_update(self):
        _, out = run_command({'yes': True}, plan=make_plan(changed=False))
        self.assertIn('Nothing to update', out)

    def test_declining_the_prompt_cancels(self):
        _, out = run_command({}, plan=make_plan(), answer='n')
        self.assertIn('Cancelled; nothing was written.', out)

    def test_overwrite_prompt_warns_that_it_removes_keys(self):
        from keepercommander.commands.pam_import.update_apply import ApplyReport
        with patch.object(upd.PAMProjectUpdateCommand, 'apply', return_value=ApplyReport()) as apply:
            _, out = run_command({'mode': 'overwrite'}, plan=make_plan(), answer='y')
        self.assertIn('REMOVES keys', out)
        apply.assert_called_once()

    def test_yes_skips_the_prompt_and_reaches_apply(self):
        from keepercommander.commands.pam_import.update_apply import ApplyReport
        with patch.object(upd.PAMProjectUpdateCommand, 'apply', return_value=ApplyReport()) as apply:
            run_command({'yes': True}, plan=make_plan())
        apply.assert_called_once()

    def test_a_write_run_prints_what_was_written_and_raises_on_apply_errors(self):
        from keepercommander.commands.pam_import.update_apply import ApplyReport
        ok = ApplyReport(applied=['M1: record fields (2)'], not_applied=['admin1: rotation changes are not applied yet'])
        with patch.object(upd.PAMProjectUpdateCommand, 'apply', return_value=ok):
            _, out = run_command({'yes': True}, plan=make_plan())
        self.assertIn('Written (1):', out)
        self.assertIn('M1: record fields (2)', out)
        self.assertIn('NOT WRITTEN YET (1)', out)
        self.assertIn('Done: 1 written, 0 error(s), 1 not written yet.', out)
        bad = ApplyReport(applied=[], errors=['M1: record fields were not written: boom'])
        with patch.object(upd.PAMProjectUpdateCommand, 'apply', return_value=bad):
            with self.assertRaises(CommandError) as ctx:
                run_command({'yes': True}, plan=make_plan())
        self.assertIn('1 error(s) while writing', str(ctx.exception))

    def test_a_json_write_run_returns_the_result_with_the_apply_section_and_does_not_raise(self):
        from keepercommander.commands.pam_import.update_apply import ApplyReport
        bad = ApplyReport(applied=['a'], errors=['M1: record fields were not written: boom'], warnings=['w'])
        with patch.object(upd.PAMProjectUpdateCommand, 'apply', return_value=bad):
            result, _ = run_command({'yes': True, 'output_format': 'json'}, plan=make_plan())
        data = json.loads(result)
        self.assertEqual((data['summary']['applied'], data['summary']['failed']), (1, 1))
        self.assertEqual(data['apply']['errors'], ['M1: record fields were not written: boom'])
        self.assertEqual(data['apply']['warnings'], ['w'])


class TestJsonInput(Quiet):
    def test_file_and_inline_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'x.json')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('{"pam_data": {"users": []}}')
            self.assertEqual(upd.load_import_json(path), {'pam_data': {'users': []}})
        self.assertEqual(upd.load_import_json('{"pam_data": {}}'), {'pam_data': {}})

    def test_bad_input_is_an_error(self):
        for bad in ('no-such-file.json', '[1, 2]'):
            with self.assertRaises(CommandError):
                upd.load_import_json(bad)

    def test_the_command_is_registered_under_pam_project(self):
        from keepercommander.commands.pam_import.commands import PAMProjectCommand
        self.assertIn('update', PAMProjectCommand().subcommands)


class FakeScope:
    folders = {}

    def match_records(self):
        return tp.index().records()

    def record_tuples(self):
        return TestReport.SCOPE

    def describe_location(self, uid):
        return 'a folder'

    def folder_label(self, uid):
        return uid

    def nsf_warnings(self, ignored=True):
        return ['WARNING: NSF "x" is not shared to the KSM app']


class TestBuildPlanGlue(Quiet):
    """The I/O side of the command with every server call replaced: the wiring between the modules."""

    def run_build(self, pam_json, state=None, config=True):
        cfg = SimpleNamespace(record_uid=tp.CFG, version=6)
        params = SimpleNamespace(record_cache={tp.M1: {}, tp.U1: {}})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'in.json')
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(pam_json, fh)
            with patch.object(upd.api, 'sync_down'), \
                    patch.object(upd, 'find_pam_configuration', return_value=cfg if config else None), \
                    patch.object(upd.vault, 'TypedRecord', SimpleNamespace), \
                    patch.object(upd, '_find_ksm_app', return_value=('APP', None, None)), \
                    patch.object(upd, 'get_ksm_app_folders', return_value=[{'uid': 'F', 'name': 'F'}]), \
                    patch.object(upd, 'collect_ksm_scope', return_value=FakeScope()), \
                    patch.object(upd.api, 'resolve_record_write_path', return_value={'shared_folder_uid': 'F'}), \
                    patch.object(upd, 'read_vault_state', return_value=state or tp.state()) as reader:
                plan = upd.PAMProjectUpdateCommand().build_plan(
                    params, {'config': 'C', 'file_name': path}, ud.MODE_MERGE, False)
        return plan, reader

    def test_end_to_end_plan(self):
        plan, reader = self.run_build({'pam_data': {'resources': [tp.machine_json(operating_system='windows')]}})
        self.assertEqual(plan.errors, [])
        self.assertEqual([r.title for r in plan.changed], ['M1'])
        self.assertTrue(any('NSF "x"' in w for w in plan.warnings))        # scope warnings reach the report
        self.assertEqual(sorted(reader.call_args.args[2]), sorted([tp.M1, tp.U1]))   # only matched records are read
        self.assertEqual(reader.call_args.kwargs['workflow_uids'], [])

    def test_a_missing_record_is_a_plan_error_and_is_not_read(self):
        plan, reader = self.run_build({'pam_data': {'resources': [tp.machine_json(title='Nope', users=[])]}})
        self.assertFalse(plan.ok)
        self.assertEqual(reader.call_args.args[2], [])
        self.assertTrue(any('pam project extend' in e for e in plan.errors))

    def test_workflow_is_read_only_for_resources_that_have_a_section(self):
        raw = tp.machine_json()
        raw['pam_settings']['options']['workflow'] = {'approvals_needed': 1}
        _, reader = self.run_build({'pam_data': {'resources': [raw]}})
        self.assertEqual(reader.call_args.kwargs['workflow_uids'], [tp.M1])

    def test_a_user_with_a_rotation_in_another_configuration_is_a_plan_error(self):
        params_cache = {tp.U1: {'configuration_uid': 'OTHER' + 'A' * 17}}
        with patch.object(upd, '_config_of', wraps=upd._config_of) as hook:
            cfg = SimpleNamespace(record_uid=tp.CFG, version=6)
            params = SimpleNamespace(record_cache={tp.M1: {}, tp.U1: {}}, record_rotation_cache=params_cache)
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, 'in.json')
                with open(path, 'w', encoding='utf-8') as fh:
                    json.dump({'pam_data': {'resources': [tp.machine_json()]}}, fh)
                with patch.object(upd.api, 'sync_down'), \
                        patch.object(upd, 'find_pam_configuration', return_value=cfg), \
                        patch.object(upd.vault, 'TypedRecord', SimpleNamespace), \
                        patch.object(upd, '_find_ksm_app', return_value=('APP', None, None)), \
                        patch.object(upd, 'get_ksm_app_folders', return_value=[{'uid': 'F', 'name': 'F'}]), \
                        patch.object(upd, 'collect_ksm_scope', return_value=FakeScope()), \
                        patch.object(upd.api, 'resolve_record_write_path', return_value={'x': 1}), \
                        patch.object(upd, 'read_vault_state', return_value=tp.state()):
                    plan = upd.PAMProjectUpdateCommand().build_plan(params, {'config': 'C', 'file_name': path},
                                                                    ud.MODE_MERGE, False)
        hook.assert_called()
        self.assertTrue(any('belongs to configuration ' + 'OTHER' + 'A' * 17 in e for e in plan.errors))

    def test_an_unknown_workflow_approver_is_a_plan_warning(self):
        raw = tp.machine_json()
        raw['pam_settings']['options']['workflow'] = {
            'approvals_needed': 1, 'approvers': [{'principal': {'type': 'user', 'email': 'nobody@example.com'}}]}
        with patch.object(upd, 'approver_warnings', return_value=['Resource "M1": workflow approver '
                                                                  '"nobody@example.com" was not found among the users of your enterprise']) as check:
            plan, _ = self.run_build({'pam_data': {'resources': [raw]}})
        check.assert_called_once()
        self.assertEqual(len(check.call_args.args[1]), 1)           # only the resource with a workflow section
        self.assertTrue(any('was not found among the users of your enterprise' in w for w in plan.warnings))

    def test_the_configuration_must_exist(self):
        with self.assertRaises(CommandError) as ctx:
            self.run_build({'pam_data': {'resources': [tp.machine_json()]}}, config=False)
        self.assertIn('PAM configuration not found', str(ctx.exception))

    def test_an_empty_pam_data_is_an_error(self):
        with self.assertRaises(CommandError) as ctx:
            self.run_build({'pam_data': {}})
        self.assertIn('PAM data missing', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
