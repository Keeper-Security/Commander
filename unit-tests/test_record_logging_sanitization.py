#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration tests verifying that sensitive record data is masked in actual logging paths.
Tests cover sanitize_command_fields and end-to-end logging for all affected record types.
"""

import unittest
from keepercommander.service.decorators.logging import sanitize_command_fields, sanitize_debug_data


class TestCommandFieldSanitization(unittest.TestCase):
    """Test sanitization of command fields in all supported formats."""

    def test_bare_licensenumber_masked(self):
        """Test bare licenseNumber field is masked."""
        command = "record-add -rt softwareLicense licenseNumber=LICENSE_SECRET --force"
        result = sanitize_command_fields(command)
        self.assertNotIn("LICENSE_SECRET", result)
        self.assertIn("licenseNumber=***", result)

    def test_bare_encryptednote_masked(self):
        """Test bare encryptedNote field is masked."""
        command = "record-add -rt encryptedNotes encryptedNote=NOTE_SECRET --force"
        result = sanitize_command_fields(command)
        self.assertNotIn("NOTE_SECRET", result)
        self.assertIn("encryptedNote=***", result)

    def test_notes_option_masked(self):
        """Test --notes option is masked."""
        command = "record-add --title MyRecord --notes=NOTE_OPTION_SECRET --force"
        result = sanitize_command_fields(command)
        self.assertNotIn("NOTE_OPTION_SECRET", result)
        self.assertIn("--notes=***", result)

    def test_notes_option_with_quotes_masked(self):
        """Test --notes option with quoted value is masked."""
        command = 'record-add --title MyRecord --notes "NOTE_QUOTED_SECRET" --force'
        result = sanitize_command_fields(command)
        self.assertNotIn("NOTE_QUOTED_SECRET", result)
        self.assertIn("--notes ***", result)

    def test_prefixed_bankaccount_fields_masked(self):
        """Test prefixed bankAccount fields are masked."""
        command = "record-add -rt bankAccount f.bankAccount.routingNumber=123456789 f.bankAccount.accountNumber=9876543210"
        result = sanitize_command_fields(command)
        self.assertNotIn("123456789", result)
        self.assertNotIn("9876543210", result)
        self.assertIn("f.bankAccount.routingNumber=***", result)
        self.assertIn("f.bankAccount.accountNumber=***", result)

    def test_prefixed_paymentcard_fields_masked(self):
        """Test prefixed paymentCard fields are masked."""
        command = "record-add -rt paymentCard f.paymentCard.cardNumber=4111111111111111 f.paymentCard.cardSecurityCode=123"
        result = sanitize_command_fields(command)
        self.assertNotIn("4111111111111111", result)
        self.assertNotIn("123", result)
        self.assertIn("f.paymentCard.cardNumber=***", result)
        self.assertIn("f.paymentCard.cardSecurityCode=***", result)

    def test_prefixed_keypair_fields_masked(self):
        """Test prefixed keyPair fields are masked."""
        command = "record-add -rt sshKeys f.keyPair.privateKey=SECRET_PRIVATE_KEY f.keyPair.publicKey=SECRET_PUBLIC_KEY"
        result = sanitize_command_fields(command)
        self.assertNotIn("SECRET_PRIVATE_KEY", result)
        self.assertNotIn("SECRET_PUBLIC_KEY", result)
        self.assertIn("f.keyPair.privateKey=***", result)
        self.assertIn("f.keyPair.publicKey=***", result)

    def test_custom_field_licenseNumber_masked(self):
        """Test custom field with licenseNumber type is masked."""
        command = "record-add -rt login c.licenseNumber.MyLicense=LICENSE_CUSTOM_SECRET"
        result = sanitize_command_fields(command)
        self.assertNotIn("LICENSE_CUSTOM_SECRET", result)
        self.assertIn("c.licenseNumber.MyLicense=***", result)

    def test_custom_field_encryptedNote_masked(self):
        """Test custom field with encryptedNote type is masked."""
        command = "record-add -rt login c.encryptedNote.MyNote=NOTE_CUSTOM_SECRET"
        result = sanitize_command_fields(command)
        self.assertNotIn("NOTE_CUSTOM_SECRET", result)
        self.assertIn("c.encryptedNote.MyNote=***", result)

    def test_custom_field_password_label_masked(self):
        """Test custom field password with label is masked."""
        command = "record-add f.password.DBPassword=SECRET_DB_PASS"
        result = sanitize_command_fields(command)
        self.assertNotIn("SECRET_DB_PASS", result)
        self.assertIn("f.password.DBPassword=***", result)

    def test_custom_field_secret_label_masked(self):
        """Test custom field secret with label is masked."""
        command = "record-add c.secret.APIKey=SECRET_API_KEY_VALUE"
        result = sanitize_command_fields(command)
        self.assertNotIn("SECRET_API_KEY_VALUE", result)
        self.assertIn("c.secret.APIKey=***", result)

    def test_bare_bankaccount_field_masked(self):
        """Test bare bankAccount field is masked."""
        command = "record-add bankAccount=SECRET_DATA"
        result = sanitize_command_fields(command)
        self.assertNotIn("SECRET_DATA", result)
        self.assertIn("bankAccount=***", result)

    def test_bare_paymentcard_field_masked(self):
        """Test bare paymentCard field is masked."""
        command = "record-add paymentCard=SECRET_DATA"
        result = sanitize_command_fields(command)
        self.assertNotIn("SECRET_DATA", result)
        self.assertIn("paymentCard=***", result)

    def test_bare_keypair_field_masked(self):
        """Test bare keyPair field is masked."""
        command = "record-add keyPair=SECRET_DATA"
        result = sanitize_command_fields(command)
        self.assertNotIn("SECRET_DATA", result)
        self.assertIn("keyPair=***", result)

    def test_mixed_command_all_masked(self):
        """Test mixed command with multiple sensitive fields all masked."""
        command = "record-add -rt softwareLicense --title MyLicense --notes=MY_NOTES licenseNumber=LICENSE_NUM f.encryptedNote=NOTE_DATA"
        result = sanitize_command_fields(command)
        self.assertNotIn("MY_NOTES", result)
        self.assertNotIn("LICENSE_NUM", result)
        self.assertNotIn("NOTE_DATA", result)
        self.assertIn("--notes=***", result)
        self.assertIn("licenseNumber=***", result)
        self.assertIn("f.encryptedNote=***", result)

    def test_mixed_case_field_names(self):
        """Test that mixed-case field names are handled correctly."""
        commands = [
            "record-add EncryptedNote=CASE_SECRET",
            "record-add LicenseNumber=CASE_SECRET",
            "record-add BankAccount=CASE_SECRET",
            "record-add f.Password.Label=CASE_SECRET",
            "record-add c.Secret.Label=CASE_SECRET",
        ]
        for cmd in commands:
            result = sanitize_command_fields(cmd)
            self.assertNotIn("CASE_SECRET", result, f"Failed for: {cmd}")
            self.assertIn("***", result, f"Not sanitized for: {cmd}")

    def test_non_sensitive_fields_preserved(self):
        """Test that non-sensitive fields and options are preserved."""
        command = "record-add -rt bankAccount --title MyBank --folder MyFolder f.name=John"
        result = sanitize_command_fields(command)
        self.assertIn("--title", result)
        self.assertIn("MyBank", result)
        self.assertIn("--folder", result)
        self.assertIn("MyFolder", result)
        self.assertIn("f.name=John", result)


class TestDebugDataSanitization(unittest.TestCase):
    """Test sanitize_debug_data for JSON and other formats."""

    def test_sanitize_licensenumber_in_json(self):
        """Test licenseNumber in JSON is masked."""
        json_str = '{"licenseNumber": "LICENSE_SECRET_123"}'
        result = sanitize_debug_data(json_str)
        self.assertNotIn("LICENSE_SECRET_123", result)

    def test_sanitize_encryptednote_in_json(self):
        """Test encryptedNote in JSON is masked."""
        json_str = '{"encryptedNote": "NOTE_SECRET_456"}'
        result = sanitize_debug_data(json_str)
        self.assertNotIn("NOTE_SECRET_456", result)

    def test_sanitize_note_in_json(self):
        """Test note field in JSON is masked."""
        json_str = '{"note": "SENSITIVE_NOTE_789"}'
        result = sanitize_debug_data(json_str)
        self.assertNotIn("SENSITIVE_NOTE_789", result)

    def test_bare_licensing_command_in_debug(self):
        """Test bare licenseNumber command is masked in debug output."""
        debug_str = "Executing: record-add licenseNumber=LICENSE_DEBUG_SECRET"
        result = sanitize_debug_data(debug_str)
        self.assertNotIn("LICENSE_DEBUG_SECRET", result)

    def test_bare_encryptednote_command_in_debug(self):
        """Test bare encryptedNote command is masked in debug output."""
        debug_str = "Executing: record-add encryptedNote=NOTE_DEBUG_SECRET"
        result = sanitize_debug_data(debug_str)
        self.assertNotIn("NOTE_DEBUG_SECRET", result)


class TestRecordTypes(unittest.TestCase):
    """End-to-end tests for each sensitive record type."""

    def test_bankaccount_all_formats(self):
        """Test bankAccount in all command formats."""
        commands = [
            "record-add -rt bankAccount f.bankAccount.routingNumber=123456789 f.bankAccount.accountNumber=9876543210",
            "record-add bankAccount=DATA_SECRET",
            "record-update REC_UID bankAccount=DATA_SECRET",
        ]
        for cmd in commands:
            result = sanitize_command_fields(cmd)
            self.assertNotIn("123456789", result, f"Failed for: {cmd}")
            self.assertNotIn("9876543210", result, f"Failed for: {cmd}")
            self.assertNotIn("DATA_SECRET", result, f"Failed for: {cmd}")

    def test_paymentcard_all_formats(self):
        """Test paymentCard in all command formats."""
        commands = [
            "record-add -rt paymentCard f.paymentCard.cardNumber=4111111111111111 f.paymentCard.cardSecurityCode=123",
            "record-add paymentCard=DATA_SECRET",
            "record-update REC_UID paymentCard=DATA_SECRET",
        ]
        for cmd in commands:
            result = sanitize_command_fields(cmd)
            self.assertNotIn("4111111111111111", result, f"Failed for: {cmd}")
            self.assertNotIn("123", result, f"Failed for: {cmd}")
            self.assertNotIn("DATA_SECRET", result, f"Failed for: {cmd}")

    def test_sshkeys_all_formats(self):
        """Test sshKeys (keyPair) in all command formats."""
        commands = [
            "record-add -rt sshKeys f.keyPair.privateKey=PRIVATE_SECRET f.keyPair.publicKey=PUBLIC_SECRET",
            "record-add keyPair=DATA_SECRET",
            "record-update REC_UID keyPair=DATA_SECRET",
        ]
        for cmd in commands:
            result = sanitize_command_fields(cmd)
            self.assertNotIn("PRIVATE_SECRET", result, f"Failed for: {cmd}")
            self.assertNotIn("PUBLIC_SECRET", result, f"Failed for: {cmd}")
            self.assertNotIn("DATA_SECRET", result, f"Failed for: {cmd}")

    def test_softwarelicense_all_formats(self):
        """Test softwareLicense in all command formats."""
        commands = [
            "record-add -rt softwareLicense licenseNumber=LICENSE_SECRET",
            "record-add -rt softwareLicense f.licenseNumber=LICENSE_SECRET",
            "record-add licenseNumber=LICENSE_SECRET",
            "record-update REC_UID licenseNumber=LICENSE_SECRET",
        ]
        for cmd in commands:
            result = sanitize_command_fields(cmd)
            self.assertNotIn("LICENSE_SECRET", result, f"Failed for: {cmd}")

    def test_encryptednotes_all_formats(self):
        """Test encryptedNotes in all command formats."""
        commands = [
            "record-add -rt encryptedNotes encryptedNote=NOTE_SECRET",
            "record-add -rt encryptedNotes f.encryptedNote=NOTE_SECRET",
            "record-add encryptedNote=NOTE_SECRET",
            "record-update REC_UID encryptedNote=NOTE_SECRET",
            "record-add --notes=NOTE_SECRET",
            "record-update REC_UID --notes=NOTE_SECRET",
        ]
        for cmd in commands:
            result = sanitize_command_fields(cmd)
            self.assertNotIn("NOTE_SECRET", result, f"Failed for: {cmd}")


if __name__ == '__main__':
    unittest.main()
