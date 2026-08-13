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
