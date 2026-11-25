"""Tests for the database terminal / KeeperDB / sql-server / WoL options of `pam project import/extend`."""
import logging
import unittest

from keepercommander.commands.pam_import.base import PamDatabaseObject, PamSettingsFieldData

CLI_CAPABLE = ("mysql", "postgresql", "sql-server")
KEEPERDB_ONLY = ("mariadb", "oracle", "mongodb", "redis", "elasticsearch", "clickhouse", "dynamodb")


def _record(protocol, **extra):
    conn = {"protocol": protocol, "port": "1", **extra}
    psfd = PamSettingsFieldData.load({"connection": conn})
    return psfd.connection.to_record_dict()


class TestDbTier1Terminal(unittest.TestCase):
    def test_font_name_and_read_only_for_cli_capable(self):
        for proto in CLI_CAPABLE:
            got = _record(proto, font_name="Menlo", read_only=True)
            self.assertEqual(got.get("fontName"), "Menlo", proto)
            self.assertEqual(got.get("readOnly"), True, proto)

    def test_not_for_keeperdb_only(self):
        for proto in KEEPERDB_ONLY:
            got = _record(proto, font_name="Menlo", read_only=True)
            self.assertNotIn("fontName", got, proto)
            self.assertNotIn("readOnly", got, proto)

    def test_existing_options_unchanged(self):
        got = _record("mysql", default_database="db1", disable_csv_export=True, disable_csv_import=False,
                      color_scheme="gray-black", font_size=14, scrollback=300, clipboard_buffer_size="50mb")
        self.assertEqual(got, {
            "protocol": "mysql", "port": "1", "database": "db1", "disableCsvExport": True, "disableCsvImport": False,
            "colorScheme": "gray-black", "fontSize": "14", "scrollback": 300, "clipboardBufferSize": 50 * 1024 * 1024,
        })


class TestDbConnectionMethod(unittest.TestCase):
    def test_cli_capable_written_as_given_canonical_case(self):
        for proto in CLI_CAPABLE:
            for given, expected in (("cli", "cli"), ("KEEPERDB", "keeperDB"), ("Both", "both")):
                self.assertEqual(_record(proto, db_connection_method=given).get("dbConnectionMethod"), expected)

    def test_cli_capable_omitted_not_written(self):
        for proto in CLI_CAPABLE:
            self.assertNotIn("dbConnectionMethod", _record(proto))

    def test_cli_capable_invalid_skipped_with_warning(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            self.assertNotIn("dbConnectionMethod", _record("mysql", db_connection_method="direct"))
        self.assertIn("db_connection_method", "\n".join(cm.output))

    def test_keeperdb_only_always_keeperdb_omitted_no_warning(self):
        for proto in KEEPERDB_ONLY:
            with self.assertNoLogs(level=logging.WARNING):
                self.assertEqual(_record(proto).get("dbConnectionMethod"), "keeperDB", proto)
            with self.assertNoLogs(level=logging.WARNING):
                self.assertEqual(_record(proto, db_connection_method="keeperDB").get("dbConnectionMethod"), "keeperDB", proto)

    def test_keeperdb_only_other_value_replaced_with_warning(self):
        for given in ("cli", "both", "bogus"):
            with self.assertLogs(level=logging.WARNING) as cm:
                got = _record("oracle", db_connection_method=given)
            self.assertEqual(got.get("dbConnectionMethod"), "keeperDB")
            text = "\n".join(cm.output)
            self.assertIn("replaced with the required 'keeperDB'", text)
            self.assertIn("oracle", text)
            self.assertIn(repr(given), text)


class TestDbSessionPersistence(unittest.TestCase):
    def test_written_nested(self):
        for val in ("none", "user", "resource"):
            got = _record("oracle", session_persistence=val.upper())
            self.assertEqual(got.get("rbiSettings"), {"sessionPersistence": val})
        got = _record("mysql", db_connection_method="both", session_persistence="user")
        self.assertEqual(got.get("rbiSettings"), {"sessionPersistence": "user"})

    def test_warns_without_keeperdb_but_still_written(self):
        for kwargs in ({}, {"db_connection_method": "cli"}):
            with self.assertLogs(level=logging.WARNING) as cm:
                got = _record("postgresql", session_persistence="user", **kwargs)
            self.assertEqual(got.get("rbiSettings"), {"sessionPersistence": "user"})
            self.assertIn("only applies to KeeperDB sessions", "\n".join(cm.output))
        with self.assertNoLogs(level=logging.WARNING):
            _record("postgresql", session_persistence="user", db_connection_method="keeperDB")

    def test_invalid_skipped(self):
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("rbiSettings", _record("mongodb", session_persistence="forever"))


class TestSqlServerTier2(unittest.TestCase):
    def test_options(self):
        got = _record("sql-server", protocol_version="7.2", force_encryption=True, disable_cert_hostname_verification=False,
                      ca_certificate=["-----BEGIN CERTIFICATE-----", "abc", "-----END CERTIFICATE-----"])
        self.assertEqual(got["protocolVersion"], "7.2")
        self.assertEqual(got["forceEncryption"], True)
        self.assertEqual(got["disableCertHostnameVerification"], False)
        self.assertIn("BEGIN CERTIFICATE", got["caCertificate"])

    def test_protocol_version_values(self):
        for v in ("7.0", "7.1", "7.2", "7.3", "7.4", "8.0"):
            self.assertEqual(_record("sql-server", protocol_version=v).get("protocolVersion"), v)
        self.assertEqual(_record("sql-server", protocol_version=8).get("protocolVersion"), "8.0")
        self.assertEqual(_record("sql-server", protocol_version=7.4).get("protocolVersion"), "7.4")
        with self.assertLogs(level=logging.WARNING):
            self.assertNotIn("protocolVersion", _record("sql-server", protocol_version="9.0"))

    def test_sql_server_options_not_for_other_protocols(self):
        got = _record("mysql", protocol_version="7.4", force_encryption=True, ca_certificate="x")
        self.assertEqual(got, {"protocol": "mysql", "port": "1"})


class TestDbWolAndRecording(unittest.TestCase):
    def test_cli_capable_tier2(self):
        got = _record("mysql", wol_send_packet=True, wol_mac_addr="00:11:22:33:44:55", wol_udp_port=9, wol_wait_time=3,
                      recording_exclude_output=True, recording_exclude_mouse=False)
        self.assertEqual(got, {
            "protocol": "mysql", "port": "1", "wolSendPacket": True, "wolMacAddr": "00:11:22:33:44:55",
            "wolUdpPort": 9, "wolWaitTime": 3, "recordingExcludeOutput": True, "recordingExcludeMouse": False,
        })

    def test_not_declared_options_ignored(self):
        got = _record("postgresql", recording_include_clipboard=True, recording_exclude_touch=True, unix_socket="/tmp/x")
        self.assertEqual(got, {"protocol": "postgresql", "port": "1"})
        # KeeperDB-only protocols do not use guacd arguments at all
        got = _record("oracle", wol_send_packet=True, recording_exclude_output=True)
        self.assertNotIn("wolSendPacket", got)
        self.assertNotIn("recordingExcludeOutput", got)


class TestKeeperDbOnlyWithoutConnection(unittest.TestCase):
    @staticmethod
    def _load(database_type, **extra):
        data = {"type": "pamDatabase", "title": "Db1", "database_type": database_type, "host": "h", "port": "1",
                "users": [{"type": "pamUser", "login": "u", "password": "p"}], **extra}
        return PamDatabaseObject.load(data)

    def test_warns_with_expected_import_json_for_every_keeperdb_only_type(self):
        for dbtype, proto in (("mariadb", "mariadb"), ("mariadb-flexible", "mariadb"), ("oracle", "oracle"),
                              ("mongodb", "mongodb"), ("redis", "redis"), ("elasticsearch", "elasticsearch"),
                              ("clickhouse", "clickhouse"), ("dynamodb", "dynamodb")):
            with self.assertLogs(level=logging.WARNING) as cm:
                self._load(dbtype)
            text = "\n".join(cm.output)
            self.assertIn(f'PAM Database "Db1" ({proto}) has no pam_settings.connection', text, dbtype)
            self.assertIn('"pam_settings": { "connection": { "protocol": "%s", "db_connection_method": "keeperDB" } }' % proto, text, dbtype)

    def test_warns_when_pam_settings_has_no_connection(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            self._load("oracle", pam_settings={"options": {"rotation": "on"}})
        self.assertIn("has no pam_settings.connection", "\n".join(cm.output))

    def test_no_warning_with_connection_or_for_cli_capable_types(self):
        with self.assertNoLogs(level=logging.WARNING):
            self._load("oracle", pam_settings={"connection": {"protocol": "oracle", "db_connection_method": "keeperDB"}})
        for dbtype in ("mysql", "mysql-flexible", "postgresql", "postgresql-flexible", "mssql"):
            with self.assertNoLogs(level=logging.WARNING):
                self._load(dbtype)


class TestDatabaseTypeMessages(unittest.TestCase):
    """database_type values outside the Web Vault Database Type list, and conflicts with connection.protocol."""
    VAULT_LIST = "postgresql, postgresql-flexible, mysql, mysql-flexible, mariadb, mariadb-flexible, mssql, oracle, mongodb"

    @staticmethod
    def _load(database_type, title="Db1", **extra):
        data = {"type": "pamDatabase", "title": title, "database_type": database_type, "host": "h", "port": "1",
                "users": [{"type": "pamUser", "login": "u", "password": "p"}], **extra}
        return PamDatabaseObject.load(data)

    def test_gateway_accepted_types_are_a_warning_with_the_protocol_snippet(self):
        for dbtype in ("redis", "elasticsearch", "clickhouse", "dynamodb"):
            with self.assertLogs(level=logging.WARNING) as cm:
                obj = self._load(dbtype, title="Redis1", pam_settings={"connection": {"protocol": dbtype, "db_connection_method": "keeperDB"}})
            self.assertEqual([r.levelno for r in cm.records], [logging.WARNING], dbtype)
            text = cm.records[0].getMessage()
            self.assertIn(f'PAM Database "Redis1": database_type \'{dbtype}\' is not in the Web Vault\'s Database Type list ({self.VAULT_LIST})', text)
            self.assertIn("written as given. The Gateway accepts it but the Web Vault cannot display it.", text)
            self.assertIn(f'For {dbtype} leave database_type out and set the connection protocol instead: '
                          f'"pam_settings": {{ "connection": {{ "protocol": "{dbtype}", "db_connection_method": "keeperDB" }} }}', text)
            self.assertEqual(obj.databaseType, dbtype)  # still written as given

    def test_other_unknown_types_stay_an_error(self):
        with self.assertLogs(level=logging.ERROR) as cm:
            obj = self._load("db2", title="Db2Box")
        text = cm.records[0].getMessage()
        self.assertEqual(cm.records[0].levelno, logging.ERROR)
        self.assertEqual(
            text, f'PAM Database "Db2Box": unknown database_type \'db2\' - written as given, but it is not in the Web Vault\'s '
                  f'Database Type list ({self.VAULT_LIST}) and the Gateway may not recognize it')
        self.assertEqual(obj.databaseType, "db2")

    def test_listed_types_log_nothing_about_the_type(self):
        for dbtype in ("postgresql", "postgresql-flexible", "mysql", "mysql-flexible", "mariadb", "mariadb-flexible",
                       "mssql", "oracle", "mongodb"):
            with self.assertNoLogs(level=logging.ERROR):
                self._load(dbtype)

    def test_conflict_between_database_type_and_connection_protocol(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            self._load("mysql", title="Redis1", pam_settings={"connection": {"protocol": "redis", "db_connection_method": "keeperDB"}})
        texts = [r.getMessage() for r in cm.records]
        self.assertIn(
            'PAM Database "Redis1": database_type \'mysql\' (protocol mysql) conflicts with pam_settings.connection.protocol '
            "'redis' - the Gateway uses database_type first, so this resource will be handled as mysql. "
            "Remove database_type or make them match.", texts)

    def test_matching_or_absent_values_do_not_conflict(self):
        cases = (("mysql", "mysql"), ("mysql-flexible", "mysql"), ("postgresql-flexible", "postgresql"),
                 ("mssql", "sql-server"), ("mariadb-flexible", "mariadb"), ("oracle", "oracle"), ("mongodb", "mongodb"))
        for dbtype, proto in cases:
            conn = {"protocol": proto, "db_connection_method": "keeperDB"}
            with self.assertNoLogs(level=logging.WARNING):
                self._load(dbtype, pam_settings={"connection": conn})
        # database_type left out: the Gateway falls back to connection.protocol - nothing to warn about
        data = {"type": "pamDatabase", "title": "Redis1", "host": "h", "port": "1",
                "users": [{"type": "pamUser", "login": "u", "password": "p"}],
                "pam_settings": {"connection": {"protocol": "redis", "db_connection_method": "keeperDB"}}}
        with self.assertNoLogs(level=logging.WARNING):
            PamDatabaseObject.load(data)

    def test_mariadb_type_with_mysql_protocol_conflicts(self):
        with self.assertLogs(level=logging.WARNING) as cm:
            self._load("mariadb", pam_settings={"connection": {"protocol": "mysql"}})
        self.assertTrue(any("conflicts with pam_settings.connection.protocol 'mysql'" in r.getMessage() for r in cm.records))


if __name__ == "__main__":
    unittest.main()
