"""
Unit tests for the database connection protocols recognized by `pam project import` /
`pam project extend` (step 2): mariadb, oracle, mongodb, redis, elasticsearch,
clickhouse, dynamodb — added alongside the pre-existing mysql/postgresql/sql-server.

Verifies the import model round-trips each protocol: protocol string -> connection class
-> record dict, that pamDatabase validation passes, and that is_database_protocol agrees.
"""

import unittest

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.pam_import.base import (
        PamSettingsFieldData,
        validate_pam_connection,
        is_database_protocol,
        ConnectionProtocol,
        ConnectionSettingsMariaDB,
        ConnectionSettingsOracle,
        ConnectionSettingsMongoDB,
        ConnectionSettingsRedis,
        ConnectionSettingsElasticsearch,
        ConnectionSettingsClickHouse,
        ConnectionSettingsDynamoDB,
    )
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import pam_import.base: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestPamImportNewDbProtocols(unittest.TestCase):
    # (wire value, expected connection class)
    NEW_PROTOCOLS = [
        ('mariadb', 'ConnectionSettingsMariaDB'),
        ('oracle', 'ConnectionSettingsOracle'),
        ('mongodb', 'ConnectionSettingsMongoDB'),
        ('redis', 'ConnectionSettingsRedis'),
        ('elasticsearch', 'ConnectionSettingsElasticsearch'),
        ('clickhouse', 'ConnectionSettingsClickHouse'),
        ('dynamodb', 'ConnectionSettingsDynamoDB'),
    ]

    def test_enum_values_present(self):
        self.assertEqual(ConnectionProtocol.MARIADB.value, 'mariadb')
        self.assertEqual(ConnectionProtocol.ORACLE.value, 'oracle')
        self.assertEqual(ConnectionProtocol.MONGODB.value, 'mongodb')
        self.assertEqual(ConnectionProtocol.REDIS.value, 'redis')
        self.assertEqual(ConnectionProtocol.ELASTICSEARCH.value, 'elasticsearch')
        self.assertEqual(ConnectionProtocol.CLICKHOUSE.value, 'clickhouse')
        self.assertEqual(ConnectionProtocol.DYNAMODB.value, 'dynamodb')

    def test_registered_in_connection_classes(self):
        registered = set(PamSettingsFieldData.pam_connection_classes)
        for cls in (ConnectionSettingsMariaDB, ConnectionSettingsOracle, ConnectionSettingsMongoDB,
                    ConnectionSettingsRedis, ConnectionSettingsElasticsearch,
                    ConnectionSettingsClickHouse, ConnectionSettingsDynamoDB):
            self.assertIn(cls, registered)

    def test_get_connection_class_resolves(self):
        for proto, cls_name in self.NEW_PROTOCOLS:
            with self.subTest(protocol=proto):
                obj = PamSettingsFieldData.get_connection_class({'protocol': proto})
                self.assertIsNotNone(obj)
                self.assertEqual(type(obj).__name__, cls_name)

    def test_round_trip_protocol_and_database(self):
        for proto, _ in self.NEW_PROTOCOLS:
            with self.subTest(protocol=proto):
                obj = PamSettingsFieldData.get_connection_class(
                    {'protocol': proto, 'default_database': 'db1', 'port': '1234'})
                rd = obj.to_record_dict()
                self.assertEqual(rd.get('protocol'), proto)
                self.assertEqual(rd.get('database'), 'db1')
                self.assertEqual(rd.get('port'), '1234')

    def test_validate_pam_connection_passes_for_pam_database(self):
        for proto, _ in self.NEW_PROTOCOLS:
            with self.subTest(protocol=proto):
                obj = PamSettingsFieldData.get_connection_class({'protocol': proto})
                self.assertFalse(validate_pam_connection(obj, 'pamDatabase'))

    def test_is_database_protocol(self):
        for proto, _ in self.NEW_PROTOCOLS:
            with self.subTest(protocol=proto):
                self.assertTrue(is_database_protocol(proto))


if __name__ == '__main__':
    unittest.main()
