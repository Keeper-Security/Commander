#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration test to verify that sensitive record data is not exposed in logs
during record-add and record-update operations.

This test addresses the security issue where sensitive data from bankAccount,
bankCard, sshKeys, softwareLicense, and encryptedNotes record types was being
logged in Docker logs.
"""

import unittest
import logging
import json
from io import StringIO
from unittest.mock import Mock, patch, MagicMock
from keepercommander import api, params as keeper_params


class TestRecordLoggingSanitization(unittest.TestCase):
    """Test that sensitive record data is sanitized in logs during API communication."""

    def setUp(self):
        """Set up test fixtures."""
        self.log_stream = StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        self.handler.setFormatter(formatter)

        self.logger = logging.getLogger()
        self.original_level = self.logger.level
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)

    def tearDown(self):
        """Clean up test fixtures."""
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.original_level)
        self.log_stream.close()

    def _get_log_contents(self):
        """Get the accumulated log contents."""
        return self.log_stream.getvalue()

    def test_bankaccount_record_sanitized_in_logs(self):
        """Verify bankAccount sensitive fields are not logged."""
        request_data = {
            "records": [{
                "recordUid": "test_bank_uid",
                "data": {
                    "type": "bankAccount",
                    "value": {
                        "accountType": "Checking",
                        "routingNumber": "123456789",
                        "accountNumber": "98765432109876",
                        "otherType": ""
                    }
                }
            }]
        }

        json_str = json.dumps(request_data)
        sanitized = api._sanitize_protobuf_json(json_str)

        # Verify sensitive fields are masked in output
        self.assertNotIn("123456789", sanitized)  # routingNumber
        self.assertNotIn("98765432109876", sanitized)  # accountNumber
        self.assertIn("***", sanitized)

    def test_bankcard_record_sanitized_in_logs(self):
        """Verify bankCard (paymentCard) sensitive fields are not logged."""
        request_data = {
            "records": [{
                "recordUid": "test_card_uid",
                "data": {
                    "type": "paymentCard",
                    "value": {
                        "cardNumber": "4111111111111111",
                        "cardExpirationDate": "05/2025",
                        "cardSecurityCode": "123"
                    }
                }
            }]
        }

        json_str = json.dumps(request_data)
        sanitized = api._sanitize_protobuf_json(json_str)

        # Verify sensitive fields are masked in output
        self.assertNotIn("4111111111111111", sanitized)  # cardNumber
        self.assertNotIn("123", sanitized)  # cardSecurityCode
        self.assertIn("***", sanitized)

    def test_sshkeys_record_sanitized_in_logs(self):
        """Verify sshKeys (keyPair) sensitive fields are not logged."""
        private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDU5Z8P2Z9q\n-----END PRIVATE KEY-----"
        public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1OWfD9mfagMCACEA\n-----END PUBLIC KEY-----"

        request_data = {
            "records": [{
                "recordUid": "test_key_uid",
                "data": {
                    "type": "keyPair",
                    "value": {
                        "privateKey": private_key,
                        "publicKey": public_key
                    }
                }
            }]
        }

        json_str = json.dumps(request_data)
        sanitized = api._sanitize_protobuf_json(json_str)

        # Verify sensitive key material is not in the output
        self.assertNotIn("PRIVATE KEY", sanitized)
        self.assertNotIn("PUBLIC KEY", sanitized)
        self.assertNotIn("BEGIN", sanitized)
        self.assertIn("***", sanitized)

    def test_softwarelicense_record_sanitized_in_logs(self):
        """Verify softwareLicense sensitive fields are not logged."""
        request_data = {
            "records": [{
                "recordUid": "test_license_uid",
                "fields": [{
                    "type": "licenseNumber",
                    "value": ["LICENSE-2024-CONFIDENTIAL-NUMBER"]
                }]
            }]
        }

        json_str = json.dumps(request_data)
        sanitized = api._sanitize_protobuf_json(json_str)

        # Verify sensitive license number is not in the output
        self.assertNotIn("LICENSE-2024-CONFIDENTIAL-NUMBER", sanitized)
        self.assertIn("***", sanitized)

    def test_mixed_sensitive_records_sanitized(self):
        """Verify multiple sensitive record types are all properly sanitized."""
        request_data = {
            "records": [
                {
                    "recordUid": "bank_uid",
                    "data": {
                        "type": "bankAccount",
                        "value": {
                            "accountNumber": "SECRET_ACCOUNT_123",
                            "routingNumber": "SECRET_ROUTING_456"
                        }
                    }
                },
                {
                    "recordUid": "card_uid",
                    "data": {
                        "type": "paymentCard",
                        "value": {
                            "cardNumber": "SECRET_CARD_789"
                        }
                    }
                },
                {
                    "recordUid": "key_uid",
                    "data": {
                        "type": "keyPair",
                        "value": {
                            "privateKey": "SECRET_PRIVATE_KEY"
                        }
                    }
                }
            ]
        }

        json_str = json.dumps(request_data)
        sanitized = api._sanitize_protobuf_json(json_str)

        # Verify all sensitive values are masked
        self.assertNotIn("SECRET_ACCOUNT_123", sanitized)
        self.assertNotIn("SECRET_ROUTING_456", sanitized)
        self.assertNotIn("SECRET_CARD_789", sanitized)
        self.assertNotIn("SECRET_PRIVATE_KEY", sanitized)

    def test_non_sensitive_fields_preserved(self):
        """Verify non-sensitive fields are preserved during sanitization."""
        request_data = {
            "records": [{
                "recordUid": "test_uid_123",
                "title": "My Bank Account",
                "notes": "Primary checking account",
                "data": {
                    "type": "bankAccount",
                    "value": {
                        "accountNumber": "SECRET123"
                    }
                }
            }]
        }

        json_str = json.dumps(request_data)
        sanitized = api._sanitize_protobuf_json(json_str)
        result = json.loads(sanitized)

        # Verify non-sensitive fields are preserved
        self.assertEqual(result["records"][0]["recordUid"], "test_uid_123")
        self.assertEqual(result["records"][0]["title"], "My Bank Account")
        self.assertEqual(result["records"][0]["notes"], "Primary checking account")

        # Verify sensitive field is masked
        self.assertNotIn("SECRET123", sanitized)

    def test_case_insensitive_field_type_matching(self):
        """Verify field type matching is case-insensitive."""
        test_cases = [
            ("paymentcard", "4111111111111111"),
            ("PaymentCard", "4111111111111111"),
            ("PAYMENTCARD", "4111111111111111"),
            ("bankaccount", "SECRET_ACCOUNT"),
            ("BankAccount", "SECRET_ACCOUNT"),
            ("BANKACCOUNT", "SECRET_ACCOUNT"),
        ]

        for field_type, sensitive_value in test_cases:
            request_data = {
                "data": {
                    "type": field_type,
                    "value": {"testField": sensitive_value}
                }
            }
            json_str = json.dumps(request_data)
            sanitized = api._sanitize_protobuf_json(json_str)

            # All should be sanitized regardless of case
            self.assertNotIn(sensitive_value, sanitized,
                           f"Failed for field type: {field_type}")
            self.assertIn("***", sanitized,
                        f"Sanitization failed for field type: {field_type}")


if __name__ == '__main__':
    unittest.main()
