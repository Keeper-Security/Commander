from unittest import TestCase
from html import unescape
import os
import shutil
import tempfile

import shlex

from keepercommander.service.util.verified_command import Verifycommand


def _tokens(command: str):
    """Same normalization CommandExecutor uses before policy checks."""
    command = unescape(command)
    try:
        return shlex.split(command.replace('\\', '\\\\'))
    except ValueError:
        return command.split()


class TestServiceModeCommandPolicy(TestCase):
    """Service Mode bans must use the same tokenize path as CommandExecutor."""

    def test_pam_tunnel_blocked_except_edit(self):
        for cmd in (
            'pam tunnel start uid --run id',
            'pam tunnel list',
            'pam tunnel stop uid',
            'pam tunnel diagnose',
            'pam tunnel',  # defaults to list
            'pam t s uid',
            'pam t l',
            'pam t x uid',
            'pam t d',
        ):
            with self.subTest(cmd=cmd):
                err = Verifycommand.validate_service_mode_restrictions(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn('pam tunnel', err)

        self.assertIsNone(
            Verifycommand.validate_service_mode_restrictions(
                _tokens('pam tunnel edit SOME_UID --enable-tunneling')
            )
        )
        self.assertIsNone(
            Verifycommand.validate_service_mode_restrictions(_tokens('pam t e SOME_UID'))
        )

    def test_pam_tunnel_bypass_vectors_normalized(self):
        """Double space / case / HTML entities must still block after executor-style parse."""
        for raw in (
            'pam  tunnel start uid --run id',
            'pam TUNNEL start uid --run id',
            'pam tunne&#108; start uid --run id',
            'pam t START uid --run id',
        ):
            with self.subTest(raw=raw):
                err = Verifycommand.validate_service_mode_restrictions(_tokens(raw))
                self.assertIsNotNone(err, msg=f'should block: {raw!r} -> {_tokens(raw)}')

    def test_attachment_commands_blocked_for_remote_api(self):
        check = Verifycommand.validate_service_mode_restrictions
        self.assertIsNotNone(check(_tokens('download-attachment SOME_UID')))
        self.assertIsNotNone(check(_tokens('da SOME_UID')))
        self.assertIsNotNone(check(_tokens('upload-attachment /tmp/x --record SOME_UID')))
        self.assertIsNotNone(check(_tokens('ua /tmp/x --record SOME_UID')))
        self.assertIsNotNone(
            check(_tokens('record-add --title t -rt login "file=@/tmp/x"'))
        )
        self.assertIsNotNone(
            check(_tokens(
                "record-update --force --record UID --title t "
                "--record-type=login f.file='/tmp/service_config.json'"
            ))
        )
        self.assertIsNotNone(
            check(_tokens('record-add --title t -rt login file.Label=/etc/passwd'))
        )
        # Aliases checked before cli expansion
        self.assertIsNotNone(
            check(_tokens('ra --title t -rt login file=@/etc/passwd'))
        )
        self.assertIsNotNone(
            check(_tokens('ru --force --record UID f.file=/etc/shadow'))
        )
        # Labeled f./c. file fields (parse_field type == file)
        self.assertIsNotNone(
            check(_tokens('record-add --title t -rt login f.file.doc=@/etc/passwd'))
        )
        self.assertIsNotNone(
            check(_tokens('record-add --title t -rt login c.file.doc=@/etc/passwd'))
        )
        self.assertIsNone(check(_tokens('record-add --title t -rt login login=user')))

    def test_host_filesystem_commands_blocked(self):
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'
        for cmd in (
            'run-batch --dry-run /etc/passwd',
            'run --dry-run ~/.keeper/config.json',
            'export --format=json /tmp/out.json',
            'download-membership --source=keeper /tmp/m.json',
            'download-record-types --source=keeper /tmp/rt.json',
            'apply-membership /tmp/m.json',
            'load-record-types /tmp/rt.json',
        ):
            with self.subTest(cmd=cmd):
                err = check(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn(ban, err)

    def test_host_path_output_args_blocked(self):
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'
        for cmd in (
            'audit-report --format=json --output=/tmp/report.json',
            'share-report --format=csv --output=out.csv',
            'generate --output /tmp/passwords.txt',
            'generate -o /tmp/passwords.txt',
            'pam project export --project-uid UID -o /tmp/proj.json',
            'ls --format=pdf --output=/tmp/x.pdf',
            'audit-report --format=pdf --output=report.pdf',
        ):
            with self.subTest(cmd=cmd):
                err = check(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn(ban, err)

        # Non-path --output modes remain allowed
        self.assertIsNone(check(_tokens('clipboard-copy UID --output=stdout')))
        self.assertIsNone(check(_tokens('credential-provision --config-base64 dGVzdA== --output json')))
        self.assertIsNone(check(_tokens('audit-report --format=json')))

    def test_filename_allows_temp_filedata_paths_only(self):
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'
        self.assertIsNotNone(check(_tokens('pam project import --filename=/etc/passwd')))
        self.assertIsNotNone(check(_tokens('pam project import -f /etc/passwd')))
        # Use a path outside any OS temp dir -- on Linux, tempfile.gettempdir()
        # often *is* /tmp, so a literal /tmp path would be misclassified as safe.
        self.assertIn(ban, check(_tokens('import --format=json /etc/vault.json')))

        request_temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, request_temp_dir, ignore_errors=True)
        temp_path = os.path.join(request_temp_dir, 'service_filedata_test.json')

        self.assertIsNone(
            check(_tokens(f'pam project import --filename={temp_path}'), request_temp_dir)
        )
        self.assertIsNone(check(_tokens(f'pam project import -f {temp_path}'), request_temp_dir))
        self.assertIsNone(check(_tokens(f'import --format=json {temp_path}'), request_temp_dir))
        self.assertIsNone(
            check(_tokens(f'enterprise-push {temp_path} --email user@example.com'), request_temp_dir)
        )
        # PAM --config is a vault UID, not a host path
        self.assertIsNone(
            check(_tokens('pam project extend --config=SOME_UID -f ' + temp_path), request_temp_dir)
        )

    def test_command_aliases_do_not_bypass_host_path_checks(self):
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'
        for cmd in (
            'gen -o /tmp/passwords.txt',
            'gen --output /tmp/passwords.txt',
            'pam p x --project-uid UID -o /tmp/proj.json',
            'pam p i -f /etc/passwd',
            'pam p i --filename=/etc/passwd',
            'pam p e -f /etc/passwd',
        ):
            with self.subTest(cmd=cmd):
                err = check(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn(ban, err)

        # Aliased forms of the safe cases (non-path --output, temp-path filename) stay allowed.
        request_temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, request_temp_dir, ignore_errors=True)
        temp_path = os.path.join(request_temp_dir, 'service_filedata_alias_test.json')
        self.assertIsNone(check(_tokens('gen --output stdout')))
        self.assertIsNone(check(_tokens(f'pam p i -f {temp_path}'), request_temp_dir))
        self.assertIsNone(check(_tokens(f'pam p e --filename={temp_path}'), request_temp_dir))

    def test_non_request_temp_path_still_rejected(self):
        """A path under a DIFFERENT request's temp dir is not automatically safe,
        even though it's still somewhere under the shared OS temp root."""
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'

        request_temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, request_temp_dir, ignore_errors=True)
        other_request_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other_request_dir, ignore_errors=True)
        other_path = os.path.join(other_request_dir, 'someone_elses_file.json')

        self.assertIn(
            ban, check(_tokens(f'pam project import -f {other_path}'), request_temp_dir)
        )
        # No request_temp_dir at all (e.g. a request with no FILEDATA) trusts nothing.
        self.assertIn(
            ban, check(_tokens(f'pam project import -f {other_path}'))
        )

    def test_flag_abbreviations_do_not_bypass_host_path_checks(self):
        """argparse's default allow_abbrev means '--out' really does mean
        '--output' to the real command -- our checker has to agree."""
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'
        for cmd in (
            'generate --out /etc/evil',
            'audit-report --form pdf --out /etc/evil.pdf',
            'pam project import --filenam=/etc/passwd',
            'pam project import --fil /etc/passwd',
        ):
            with self.subTest(cmd=cmd):
                err = check(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn(ban, err)

        # A complete, distinct flag must not be misread as an abbreviation of
        # a different one just because it's a literal prefix of it.
        self.assertIsNone(check(_tokens('clipboard-copy UID --output=stdout')))

    def test_import_bare_name_positional_requires_format_awareness(self):
        """A plain filename with no slash/extension must still be checked --
        unless the format means `name` isn't a file at all (account/URL)."""
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'

        # 'data' has no slash and no known extension, but json/csv always
        # read it as a local file -- must not slip through on shape alone.
        self.assertIn(ban, check(_tokens('import --format=json data')))
        self.assertIn(ban, check(_tokens('import --format=csv data')))

        # lastpass/manageengine/thycotic/cyberark/cyberark_portal treat `name`
        # as an account/URL, not a file -- must stay allowed even though it's
        # a bare, non-path-looking value.
        self.assertIsNone(check(_tokens('import --format=lastpass my-lastpass-account')))
        self.assertIsNone(check(_tokens('import --format=manageengine https://me.example.com')))
        self.assertIsNone(check(_tokens('import --format=thycotic https://thycotic.example.com')))
        self.assertIsNone(check(_tokens('import --format=cyberark pvwa.example.com')))
        self.assertIsNone(check(_tokens('import --format=cyberark_portal example-tenant')))

        # A real per-request temp path still works normally for file-based formats.
        request_temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, request_temp_dir, ignore_errors=True)
        temp_path = os.path.join(request_temp_dir, 'import_data.json')
        self.assertIsNone(check(_tokens(f'import --format=json {temp_path}'), request_temp_dir))

    def test_filedata_substitution_happens_before_validation(self):
        """process_file_data must run before validate_service_mode_restrictions,
        so --filename=FILEDATA resolves to a real per-request temp path by the
        time the host-path checks run (see CommandExecutor.execute ordering)."""
        from keepercommander.service.util.request_validation import RequestValidator

        request_data = {'filedata': {'some': 'data'}}
        command = 'pam project import --filename=FILEDATA'
        processed_command, temp_files = RequestValidator.process_file_data(request_data, command)
        self.addCleanup(RequestValidator.cleanup_temp_files, temp_files)

        self.assertTrue(temp_files, 'expected a temp file to be created')
        self.assertNotIn('FILEDATA', processed_command)

        request_temp_dir = os.path.dirname(temp_files[0])
        tokens = _tokens(processed_command)
        self.assertIsNone(
            Verifycommand.validate_service_mode_restrictions(tokens, request_temp_dir)
        )

    def test_option_values_yields_dash_leading_values(self):
        is_file = Verifycommand._option_values
        self.assertEqual(list(is_file(['generate', '--output', '-'], '--output')), ['-'])
        self.assertEqual(
            list(is_file(['pam', 'project', 'import', '-f', '-etc/passwd'], '-f')),
            ['-etc/passwd'],
        )

        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Local filesystem access'
        self.assertIn(ban, check(_tokens('pam project import -f -etc/passwd')))
        self.assertIn(ban, check(_tokens('pam project import --filename -etc/passwd')))

    def test_config_file_blocked_config_base64_allowed(self):
        check = Verifycommand.validate_service_mode_restrictions
        self.assertIsNotNone(
            check(_tokens('credential-provision --config=/tmp/cfg.yaml -c PAMUID'))
        )
        self.assertIsNone(
            check(_tokens('credential-provision --config-base64 dGVzdA== -c PAMUID'))
        )

    def test_legacy_commands_blocked_regardless_of_command_list(self):
        """rotate/connect/ssh/etc. must be denied unconditionally -- this is not
        an allow-list check, so it isn't affected by what an API key's
        command_list permits."""
        check = Verifycommand.validate_service_mode_restrictions
        ban = 'Legacy commands'
        for cmd in (
            'rotate --match ".*" --force --plugin ssh --host 1.2.3.4 --port 22',
            'rotate RECORD_UID',
            'connect RECORD_UID',
            'ssh RECORD_UID',
            'ssh-agent list',
            'rdp RECORD_UID',
            'rsync',
            'set var value',
            'echo hello',
            'mysql RECORD_UID',
            'postgresql RECORD_UID',
            'run-as -r RECORD_UID --application cmd.exe',
            'supershell',
            'ss',
        ):
            with self.subTest(cmd=cmd):
                err = check(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn(ban, err)

        # Aliases checked before cli expansion (r -> rotate, pg -> postgresql).
        self.assertIn(ban, check(_tokens('r --match ".*" --force --host 1.2.3.4 --port 22')))
        self.assertIn(ban, check(_tokens('pg RECORD_UID')))

        # Unrelated commands remain unaffected.
        self.assertIsNone(check(_tokens('get RECORD_UID')))
        self.assertIsNone(check(_tokens('record-add --title t -rt login login=user')))

    def test_double_dash_blocked_everywhere(self):
        """'--' used to desync position-based checks (pam tunnel verb, pam project path)."""
        check = Verifycommand.validate_service_mode_restrictions
        ban = "'--'"
        for cmd in (
            'pam -- tunnel start uid --run id',
            'pam -- tunnel stop uid',
            'pam -- tunnel list',
            'pam -- t s uid',
            'pam -- project export -o /etc/passwd',
            'pam -- project import -f -etc/passwd',
            'get -- RECORD_UID',
        ):
            with self.subTest(cmd=cmd):
                err = check(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn(ban, err)

        # Unrelated commands without a bare '--' token remain unaffected.
        self.assertIsNone(check(_tokens('pam tunnel edit uid')))
        self.assertIsNone(check(_tokens('get RECORD_UID')))

    def test_env_var_expansion_blocked_everywhere(self):
        """expand_cmd_args substitutes ${VARNAME} after this check runs, so it must be banned outright."""
        check = Verifycommand.validate_service_mode_restrictions
        ban = "'${VARNAME}'"
        for cmd in (
            "record-add --folder FOLDER_UID '${PAYLOAD}'",
            "record-add --field=${PAYLOAD}",
            "get ${last_record_uid}",
            "share-folder ${LAST_FOLDER_UID} -e a@b.com",
        ):
            with self.subTest(cmd=cmd):
                err = check(_tokens(cmd))
                self.assertIsNotNone(err)
                self.assertIn(ban, err)

        # Unrelated commands without ${...} syntax remain unaffected.
        self.assertIsNone(check(_tokens('get RECORD_UID')))
        self.assertIsNone(check(_tokens('record-add --title=x login=user')))
        # A single literal '$' or unmatched braces are not the ${VARNAME} pattern.
        self.assertIsNone(check(_tokens('record-add --field=$5.00')))

    def test_temp_path_leaf_symlink_is_not_containment(self):
        """A symlink planted at the temp-dir leaf must not escape containment."""
        request_temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, request_temp_dir, ignore_errors=True)
        outside_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside_dir, ignore_errors=True)

        link_path = os.path.join(request_temp_dir, 'escape.json')
        try:
            os.symlink(outside_dir, link_path)
        except OSError:
            self.skipTest('symlinks not supported in this environment')

        self.assertFalse(Verifycommand._is_service_temp_path(link_path, request_temp_dir))

    def test_is_record_file_attachment_arg(self):
        is_file = Verifycommand._is_record_file_attachment_arg
        self.assertTrue(is_file('file=@/tmp/x'))
        self.assertTrue(is_file("f.file='/path/service_config.json'"))
        self.assertTrue(is_file('file.MyDoc=/tmp/x'))
        self.assertTrue(is_file('f.file.doc=@/etc/passwd'))
        self.assertTrue(is_file('c.file.doc=@/etc/passwd'))
        self.assertFalse(is_file('login=user'))
        self.assertFalse(is_file('--title'))
        self.assertFalse(is_file('profile=x'))
        self.assertFalse(is_file('my.file=x'))  # not a file-type field after parse_field


class TestProtectedServiceConfigRecords(TestCase):
    """No Service Mode command may touch Service Mode's own config records by literal title or UID -- checked
    unconditionally for every command (not a curated list) so no current or future command can slip through."""

    PROTECTED_TITLE = 'Commander Service Mode Config'
    PROTECTED_UID = 'PROTECTED_UID_1234'

    def _check(self, cmd, protected_uids=None):
        return Verifycommand.validate_service_mode_protected_record_command(
            _tokens(cmd), protected_uids or {self.PROTECTED_UID}
        )

    def test_blocks_by_title_across_classic_commands(self):
        for cmd in (
            f'get "{self.PROTECTED_TITLE}"',
            f'g "{self.PROTECTED_TITLE}"',
            f'list "{self.PROTECTED_TITLE}"',
            f'l "{self.PROTECTED_TITLE}"',
            f'search "{self.PROTECTED_TITLE}"',
            f's "{self.PROTECTED_TITLE}"',
            f'record-update --record "{self.PROTECTED_TITLE}" title=x',
            f'ru --record "{self.PROTECTED_TITLE}" title=x',
            f'share-record "{self.PROTECTED_TITLE}" --email a@b.com',
            f'sr "{self.PROTECTED_TITLE}" --email a@b.com',
            f'rm "{self.PROTECTED_TITLE}"',
            f'share-folder --record "{self.PROTECTED_TITLE}" -e a@b.com',
            f'record-history "{self.PROTECTED_TITLE}"',
            f'clipboard-copy "{self.PROTECTED_TITLE}"',
            f'totp "{self.PROTECTED_TITLE}"',
            f'one-time-share "{self.PROTECTED_TITLE}"',
            f'ls "{self.PROTECTED_TITLE}"',
            f'tree "{self.PROTECTED_TITLE}"',
        ):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(self._check(cmd))

    def test_blocks_by_title_across_nsf_commands(self):
        for cmd in (
            f'nsf-get "{self.PROTECTED_TITLE}"',
            f'nsf-share-record "{self.PROTECTED_TITLE}" --email a@b.com',
            f'nsf-record-update --record "{self.PROTECTED_TITLE}" title=x',
            f'nsf-transfer-record "{self.PROTECTED_TITLE}" a@b.com',
            f'nsf-record-details "{self.PROTECTED_TITLE}"',
            f'nsf-rm "{self.PROTECTED_TITLE}"',
            f'nsf-move "{self.PROTECTED_TITLE}" root',
            f'nsf-ln "{self.PROTECTED_TITLE}" SomeFolder',
            f'nsf-shortcut keep "{self.PROTECTED_TITLE}"',
        ):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(self._check(cmd))

    def test_blocks_by_title_case_insensitive(self):
        self.assertIsNotNone(self._check('get "COMMANDER service MODE config"'))

    def test_blocks_by_uid_regardless_of_command(self):
        for cmd in (
            f'get {self.PROTECTED_UID}',
            f'list {self.PROTECTED_UID}',
            f'search {self.PROTECTED_UID}',
            f'record-update --record {self.PROTECTED_UID} title=x',
            f'share-record {self.PROTECTED_UID} --email a@b.com',
            f'share-folder --record {self.PROTECTED_UID} -e a@b.com',
            f'rm {self.PROTECTED_UID}',
            f'nsf-get {self.PROTECTED_UID}',
            f'nsf-transfer-record {self.PROTECTED_UID} a@b.com',
            # A command with no known relationship to records at all -- still
            # caught, since the check is unconditional, not command-specific.
            f'keep-alive {self.PROTECTED_UID}',
        ):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(self._check(cmd))

    def test_uid_match_is_case_sensitive(self):
        self.assertIsNone(self._check(f'get {self.PROTECTED_UID.lower()}'))

    def test_unrelated_title_and_uid_are_allowed(self):
        self.assertIsNone(self._check('get "My Normal Record"'))
        self.assertIsNone(self._check('rm SOME_OTHER_UID'))
        self.assertIsNone(self._check('record-add --title "My Normal Record"'))

    def test_no_protected_uids_still_blocks_by_title(self):
        err = Verifycommand.validate_service_mode_protected_record_command(
            _tokens(f'get "{self.PROTECTED_TITLE}"'), None
        )
        self.assertIsNotNone(err)

    def test_empty_tokens_returns_none(self):
        self.assertIsNone(Verifycommand.validate_service_mode_protected_record_command([]))

    def test_blocks_equals_form_uid(self):
        for cmd in (
            f'record-update --record={self.PROTECTED_UID} title=x',
            f'get --record-uid={self.PROTECTED_UID}',
            f'share-folder --record={self.PROTECTED_UID} -e a@b.com',
            f'share-folder -r={self.PROTECTED_UID} -e a@b.com',
        ):
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(self._check(cmd))

    def test_blocks_equals_form_title(self):
        self.assertIsNotNone(
            self._check(f'record-update --record="{self.PROTECTED_TITLE}" title=x')
        )

    def test_equals_form_unrelated_value_is_allowed(self):
        self.assertIsNone(self._check('record-update --record=SOME_OTHER_UID title=x'))
        self.assertIsNone(self._check('record-update --title="My Normal Record" x=y'))

    def test_equals_form_with_no_value_does_not_crash(self):
        self.assertIsNone(self._check('get --record-uid='))
