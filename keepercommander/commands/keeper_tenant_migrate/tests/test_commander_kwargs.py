"""Static kwarg-validation against Commander's real argparse destinations.

Every method on the Commander*Client classes forwards kwargs to a
Commander Command's .execute(). This test set extracts the `dest` names
from each Command's argparse parser and asserts that every kwarg we pass
corresponds to a real dest. Prevents the class of silent-failure bug where
we call `set_role_enforcement_simple` with `enforcement=...` when the parser
actually expects `enforcements=...` (plural).

If a new kwarg is ever added to commander_clients.py that doesn't match
a real dest, these tests will fail at CI time — long before a live run.
"""

import inspect
import unittest
from unittest import mock

from keepercommander.commands.enterprise import (
    EnterpriseNodeCommand,
    EnterpriseRoleCommand,
    EnterpriseTeamCommand,
    EnterpriseUserCommand,
)
from keepercommander.commands.record_edit import (
    RecordDownloadAttachmentCommand,
    RecordUploadAttachmentCommand,
)
from keepercommander.commands.register import ShareRecordCommand
from keepercommander.importer.commands import (
    ApplyMembershipCommand,
    LoadRecordTypeCommand,
)

from keepercommander.commands.keeper_tenant_migrate.commander_clients import (
    CommanderAttachmentClient,
    CommanderShareClient,
    CommanderStructureClient,
    CommanderUserClient,
)


def _parser_dests(cmd_cls):
    """Pull the dest names out of a Commander Command's argparse parser."""
    parser = cmd_cls().get_parser()
    return {a.dest for a in parser._actions if a.dest and a.dest != 'help'}


class _CapturingParams:
    """Fake KeeperParams used only to capture whatever execute() would have
    received. We monkey-patch every Command.execute() to stash kwargs before
    the real logic can fail on empty enterprise data.
    """

    def __init__(self):
        self.enterprise = {'users': [], 'nodes': [], 'teams': [], 'roles': []}


class CaptureHelper:
    """Invoke a client method, capturing the kwargs sent to Commander."""

    def __init__(self, cmd_cls):
        self.captured = {}
        self.cmd_cls = cmd_cls

    def __enter__(self):
        self._patcher = mock.patch.object(
            self.cmd_cls, 'execute',
            side_effect=lambda params, **kwargs: self.captured.update(kwargs) or None,
        )
        self._patcher.start()
        return self

    def __exit__(self, *_):
        self._patcher.stop()


# Map each client method to:
#   (Commander class backing it, how to invoke it with dummy args)
# The kwargs the method forwards get captured + compared to parser dests.

CASES = [
    # Structure client
    ('CommanderStructureClient.load_record_types',
     LoadRecordTypeCommand,
     lambda c: c.load_record_types('/tmp/x.json')),
    ('CommanderStructureClient.create_node',
     EnterpriseNodeCommand,
     lambda c: c.create_node('N', 'P')),
    ('CommanderStructureClient.toggle_node_isolated',
     EnterpriseNodeCommand,
     lambda c: c.toggle_node_isolated('N')),
    ('CommanderStructureClient.create_team',
     EnterpriseTeamCommand,
     lambda c: c.create_team('T', 'N', 'on', 'off', 'on')),
    ('CommanderStructureClient.create_role',
     EnterpriseRoleCommand,
     lambda c: c.create_role('R', 'N', 'on')),
    ('CommanderStructureClient.add_role_managed_node',
     EnterpriseRoleCommand,
     lambda c: c.add_role_managed_node('R', 'N', 'on')),
    ('CommanderStructureClient.add_role_privilege',
     EnterpriseRoleCommand,
     lambda c: c.add_role_privilege('R', 'MANAGE_USER', 'N')),
    ('CommanderStructureClient.set_role_enforcement_simple',
     EnterpriseRoleCommand,
     lambda c: c.set_role_enforcement_simple('R', 'k', 'v')),
    ('CommanderStructureClient.set_role_enforcement_file',
     EnterpriseRoleCommand,
     lambda c: c.set_role_enforcement_file('R', 'k', '/tmp/v.json')),
    ('CommanderStructureClient.assign_user_to_node',
     EnterpriseUserCommand,
     lambda c: c.assign_user_to_node('a@x', 'N')),
    ('CommanderStructureClient.add_user_to_team',
     EnterpriseUserCommand,
     lambda c: c.add_user_to_team('a@x', 'T')),
    ('CommanderStructureClient.add_user_to_role',
     EnterpriseRoleCommand,
     lambda c: c.add_user_to_role('R', 'a@x')),
    ('CommanderStructureClient.add_team_to_role',
     EnterpriseRoleCommand,
     lambda c: c.add_team_to_role('R', 'T')),
    ('CommanderStructureClient.apply_membership',
     ApplyMembershipCommand,
     lambda c: c.apply_membership('/tmp/m.json')),
]

USER_CASES = [
    ('CommanderUserClient.invite_user',
     EnterpriseUserCommand,
     lambda c: c.invite_user('a@x', 'Alice', 'N', 'Engineer')),
    ('CommanderUserClient.extend_user_invite',
     EnterpriseUserCommand,
     lambda c: c.extend_user_invite('a@x')),
    ('CommanderUserClient.set_user_job_title',
     EnterpriseUserCommand,
     lambda c: c.set_user_job_title('a@x', 'Manager')),
    ('CommanderUserClient.add_user_alias',
     EnterpriseUserCommand,
     lambda c: c.add_user_alias('a@x', 'alt@x')),
    ('CommanderUserClient.add_user_team',
     EnterpriseUserCommand,
     lambda c: c.add_user_team('a@x', 'T', hsf_on=True)),
    ('CommanderUserClient.add_user_role',
     EnterpriseRoleCommand,
     lambda c: c.add_user_role('a@x', 'R')),
]

ATTACHMENT_CASES = [
    ('CommanderAttachmentClient.download_attachments',
     RecordDownloadAttachmentCommand,
     lambda c: c.download_attachments('srcuid', '/tmp/x')),
    ('CommanderAttachmentClient.upload_attachment',
     RecordUploadAttachmentCommand,
     lambda c: c.upload_attachment('tgtuid', '/tmp/x/a.txt')),
]

SHARE_CASES = [
    ('CommanderShareClient.share_record',
     ShareRecordCommand,
     lambda c: c.share_record('tgtuid', 'a@x', editable=True, shareable=True)),
]


def _run_case(test, client_cls, client_init_args, cmd_cls, invoke):
    client = client_cls(*client_init_args)
    with CaptureHelper(cmd_cls) as cap:
        try:
            invoke(client)
        except Exception:
            # download_attachments also calls os.listdir — swallow any
            # post-execute side-effect errors; we only care about the kwargs.
            pass
    dests = _parser_dests(cmd_cls)
    sent = set(cap.captured.keys())
    unknown = sent - dests
    test.assertEqual(
        unknown, set(),
        f'{cmd_cls.__name__}: unknown kwargs {unknown}. '
        f'Valid dests: {sorted(dests)}',
    )
    return cap.captured


class StructureClientKwargsTests(unittest.TestCase):
    def test_all_structure_cases(self):
        for label, cmd_cls, invoke in CASES:
            with self.subTest(label=label):
                _run_case(self, CommanderStructureClient,
                          (_CapturingParams(),), cmd_cls, invoke)


class UserClientKwargsTests(unittest.TestCase):
    def test_all_user_cases(self):
        for label, cmd_cls, invoke in USER_CASES:
            with self.subTest(label=label):
                _run_case(self, CommanderUserClient,
                          (_CapturingParams(),), cmd_cls, invoke)


class AttachmentClientKwargsTests(unittest.TestCase):
    def test_all_attachment_cases(self):
        for label, cmd_cls, invoke in ATTACHMENT_CASES:
            with self.subTest(label=label):
                _run_case(self, CommanderAttachmentClient,
                          (_CapturingParams(),), cmd_cls, invoke)


class ShareClientKwargsTests(unittest.TestCase):
    def test_share_record_kwargs(self):
        for label, cmd_cls, invoke in SHARE_CASES:
            with self.subTest(label=label):
                _run_case(self, CommanderShareClient,
                          (_CapturingParams(), _CapturingParams()),
                          cmd_cls, invoke)


class RecordImportKwargsTests(unittest.TestCase):
    """Regression for RecordsImportCommand → RecordImportCommand."""

    def test_class_import_resolves(self):
        from keepercommander.importer.commands import RecordImportCommand
        # Parser has the dests we're going to pass
        parser = RecordImportCommand().get_parser()
        dests = {a.dest for a in parser._actions}
        for k in ('format', 'name', 'shared', 'record_type', 'dry_run'):
            self.assertIn(k, dests, f'RecordImportCommand parser missing dest: {k}')


class SpecificKwargRegressionTests(unittest.TestCase):
    """Pin the fixes that took manual inspection of Commander sources.

    These prevent silent regressions to the old (wrong) kwarg names.
    """

    def test_invite_user_passes_displayname_not_name(self):
        client = CommanderUserClient(_CapturingParams())
        with CaptureHelper(EnterpriseUserCommand) as cap:
            client.invite_user('a@x', 'Alice', 'N', 'Eng')
        self.assertIn('displayname', cap.captured)
        self.assertNotIn('name', cap.captured)
        self.assertIn('jobtitle', cap.captured)
        self.assertNotIn('job_title', cap.captured)

    def test_enforcement_kwarg_is_plural(self):
        client = CommanderStructureClient(_CapturingParams())
        with CaptureHelper(EnterpriseRoleCommand) as cap:
            client.set_role_enforcement_simple('R', 'two_factor_required', 'true')
        self.assertIn('enforcements', cap.captured)
        self.assertNotIn('enforcement', cap.captured)

    def test_add_user_alias_is_string_not_list(self):
        client = CommanderUserClient(_CapturingParams())
        with CaptureHelper(EnterpriseUserCommand) as cap:
            client.add_user_alias('a@x', 'alt@x')
        self.assertEqual(cap.captured['add_alias'], 'alt@x')
        self.assertNotIsInstance(cap.captured['add_alias'], list)

    def test_share_record_uses_can_edit_can_share(self):
        client = CommanderShareClient(_CapturingParams(), _CapturingParams())
        with CaptureHelper(ShareRecordCommand) as cap:
            client.share_record('uid', 'a@x', editable=True, shareable=True)
        self.assertTrue(cap.captured.get('can_edit'))
        self.assertTrue(cap.captured.get('can_share'))
        self.assertNotIn('write', cap.captured)
        self.assertNotIn('share', cap.captured)

    def test_share_record_target_uid_is_str_not_list(self):
        client = CommanderShareClient(_CapturingParams(), _CapturingParams())
        with CaptureHelper(ShareRecordCommand) as cap:
            client.share_record('target-uid', 'a@x', editable=False, shareable=False)
        self.assertEqual(cap.captured['record'], 'target-uid')
        self.assertNotIsInstance(cap.captured['record'], list)


if __name__ == '__main__':
    unittest.main()
