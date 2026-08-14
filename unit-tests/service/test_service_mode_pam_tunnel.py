from unittest import TestCase
from html import unescape

import shlex

from keepercommander.service.util.verified_command import Verifycommand


def _tokens(command: str):
    """Same normalization CommandExecutor uses before policy checks."""
    command = unescape(command)
    try:
        return shlex.split(command)
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
