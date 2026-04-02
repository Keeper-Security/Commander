#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

"""
Unit tests for password generator minimum-length enforcement.

Verifies that generate_password() clamps short lengths to 8 and warns,
while leaving valid lengths and other algorithms unchanged.
"""

import logging
import unittest

from keepercommander.commands.record_edit import RecordEditMixin


class TestPasswordGeneratorMinimumLength(unittest.TestCase):
    """Test the minimum password length clamp introduced for rand algorithm."""

    def test_rand_below_minimum_clamps_to_8(self):
        """$GEN:rand,4 should produce a password of length 8, not 4."""
        pw = RecordEditMixin.generate_password(['rand', '4'])
        self.assertEqual(len(pw), 8)

    def test_rand_below_minimum_warns(self):
        """$GEN:rand,6 should emit a warning about clamping to 8."""
        with self.assertLogs(level=logging.WARNING) as cm:
            RecordEditMixin.generate_password(['rand', '6'])
        self.assertTrue(any('below minimum 8' in msg for msg in cm.output))

    def test_rand_at_minimum_no_warning(self):
        """$GEN:rand,8 should not warn."""
        with self.assertRaises(AssertionError):
            # assertLogs fails if no log is emitted — that's what we want
            with self.assertLogs(level=logging.WARNING):
                RecordEditMixin.generate_password(['rand', '8'])

    def test_rand_at_minimum_length(self):
        """$GEN:rand,8 should produce exactly 8 characters."""
        pw = RecordEditMixin.generate_password(['rand', '8'])
        self.assertEqual(len(pw), 8)

    def test_rand_above_minimum(self):
        """$GEN:rand,24 should produce exactly 24 characters."""
        pw = RecordEditMixin.generate_password(['rand', '24'])
        self.assertEqual(len(pw), 24)

    def test_rand_default_length(self):
        """$GEN (no params) should produce default length (20)."""
        pw = RecordEditMixin.generate_password(None)
        self.assertEqual(len(pw), 20)

    def test_rand_default_with_algorithm_only(self):
        """$GEN:rand (no length) should produce default length (20)."""
        pw = RecordEditMixin.generate_password(['rand'])
        self.assertEqual(len(pw), 20)

    def test_dice_unchanged(self):
        """$GEN:dice,5 should still work — dice uses word count, not char length."""
        pw = RecordEditMixin.generate_password(['dice', '5'])
        # Diceware produces space-separated words; just verify it runs
        self.assertIsInstance(pw, str)
        self.assertGreater(len(pw), 0)

    def test_crypto_unchanged(self):
        """$GEN:crypto should still work without errors."""
        pw = RecordEditMixin.generate_password(['crypto'])
        self.assertIsInstance(pw, str)
        self.assertGreater(len(pw), 0)

    def test_rand_zero_length_clamps_to_8(self):
        """$GEN:rand,0 should clamp to 8 with warning."""
        with self.assertLogs(level=logging.WARNING) as cm:
            pw = RecordEditMixin.generate_password(['rand', '0'])
        self.assertEqual(len(pw), 8)
        self.assertTrue(any('below minimum' in msg for msg in cm.output))

    def test_rand_above_200_clamps_to_200(self):
        """$GEN:rand,300 should clamp to 200 with warning."""
        with self.assertLogs(level=logging.WARNING) as cm:
            pw = RecordEditMixin.generate_password(['rand', '300'])
        self.assertEqual(len(pw), 200)
        self.assertTrue(any('exceeds maximum' in msg for msg in cm.output))

    def test_rand_at_200_no_warning(self):
        """$GEN:rand,200 should produce length 200 without warning."""
        with self.assertRaises(AssertionError):
            with self.assertLogs(level=logging.WARNING):
                RecordEditMixin.generate_password(['rand', '200'])


if __name__ == '__main__':
    unittest.main()
