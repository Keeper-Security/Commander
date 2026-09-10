#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import json
import logging
from keepercommander import api

class TestAPISanitization(unittest.TestCase):
    """Test cases for sensitive data sanitization in API logging."""

    def test_sanitize_protobuf_json_with_payment_card(self):
        """Test sanitization of paymentCard data."""
        json_data = {
            "records": [{
                "recordUid": "test123",
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
        json_str = json.dumps(json_data)
        sanitized = api._sanitize_protobuf_json(json_str)
        result = json.loads(sanitized)

        # Verify sensitive fields are masked
        self.assertEqual(result["records"][0]["data"]["value"]["cardNumber"], "***")
        self.assertEqual(result["records"][0]["data"]["value"]["cardExpirationDate"], "***")
        self.assertEqual(result["records"][0]["data"]["value"]["cardSecurityCode"], "***")

    def test_sanitize_protobuf_json_with_bank_account(self):
        """Test sanitization of bankAccount data."""
        json_data = {
            "records": [{
                "recordUid": "test456",
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
        json_str = json.dumps(json_data)
        sanitized = api._sanitize_protobuf_json(json_str)
        result = json.loads(sanitized)

        # Verify sensitive fields are masked
        self.assertEqual(result["records"][0]["data"]["value"]["routingNumber"], "***")
        self.assertEqual(result["records"][0]["data"]["value"]["accountNumber"], "***")

    def test_sanitize_protobuf_json_with_ssh_keys(self):
        """Test sanitization of sshKeys (keyPair) data."""
        private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDU5Z8P2Z9q\n-----END PRIVATE KEY-----"
        public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1OWfD9mfagMCACEA\n-----END PUBLIC KEY-----"

        json_data = {
            "records": [{
                "recordUid": "test789",
                "data": {
                    "type": "keyPair",
                    "value": {
                        "privateKey": private_key,
                        "publicKey": public_key
                    }
                }
            }]
        }
        json_str = json.dumps(json_data)
        sanitized = api._sanitize_protobuf_json(json_str)
        result = json.loads(sanitized)

        # Verify sensitive fields are masked
        self.assertEqual(result["records"][0]["data"]["value"]["privateKey"], "***")
        self.assertEqual(result["records"][0]["data"]["value"]["publicKey"], "***")

    def test_sanitize_protobuf_json_with_software_license(self):
        """Test sanitization of softwareLicense data."""
        json_data = {
            "records": [{
                "recordUid": "test101",
                "fields": [{
                    "type": "licenseNumber",
                    "value": ["LICENSE-2024-0123456789"]
                }]
            }]
        }
        json_str = json.dumps(json_data)
        sanitized = api._sanitize_protobuf_json(json_str)
        result = json.loads(sanitized)

        # Verify sensitive field is masked
        self.assertEqual(result["records"][0]["fields"][0]["value"], ["***"])

    def test_sanitize_preserves_non_sensitive_data(self):
        """Test that non-sensitive data is preserved."""
        json_data = {
            "records": [{
                "recordUid": "test202",
                "title": "Test Record",
                "notes": "Some notes"
            }]
        }
        json_str = json.dumps(json_data)
        sanitized = api._sanitize_protobuf_json(json_str)
        result = json.loads(sanitized)

        # Verify non-sensitive data is preserved
        self.assertEqual(result["records"][0]["recordUid"], "test202")
        self.assertEqual(result["records"][0]["title"], "Test Record")
        self.assertEqual(result["records"][0]["notes"], "Some notes")

    def test_mask_field_value_with_dict(self):
        """Test masking of dict values."""
        value = {"key1": "value1", "key2": "value2"}
        masked = api._mask_field_value(value)
        self.assertEqual(masked, {"key1": "***", "key2": "***"})

    def test_mask_field_value_with_list(self):
        """Test masking of list values."""
        value = ["value1", "value2", "value3"]
        masked = api._mask_field_value(value)
        self.assertEqual(masked, ["***", "***", "***"])

    def test_mask_field_value_with_string(self):
        """Test masking of string values."""
        value = "sensitive_data"
        masked = api._mask_field_value(value)
        self.assertEqual(masked, "***")

    def test_sanitize_invalid_json(self):
        """Test sanitization with invalid JSON returns the original string."""
        invalid_json = "not valid json"
        result = api._sanitize_protobuf_json(invalid_json)
        self.assertEqual(result, invalid_json)

    def test_sanitize_nested_list_of_records(self):
        """Test sanitization of nested list structures."""
        json_data = {
            "records": [
                {
                    "recordUid": "uid1",
                    "data": {
                        "type": "bankAccount",
                        "value": {
                            "accountNumber": "1234567890",
                            "routingNumber": "0987654321"
                        }
                    }
                },
                {
                    "recordUid": "uid2",
                    "data": {
                        "type": "paymentCard",
                        "value": {
                            "cardNumber": "4111111111111111"
                        }
                    }
                }
            ]
        }
        json_str = json.dumps(json_data)
        sanitized = api._sanitize_protobuf_json(json_str)
        result = json.loads(sanitized)

        # Verify all sensitive data in list is masked
        self.assertEqual(result["records"][0]["data"]["value"]["accountNumber"], "***")
        self.assertEqual(result["records"][0]["data"]["value"]["routingNumber"], "***")
        self.assertEqual(result["records"][1]["data"]["value"]["cardNumber"], "***")


if __name__ == '__main__':
    unittest.main()
