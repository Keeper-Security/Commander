"""
Unit tests for the `pam project import --sample-data` ("Discovery Playground")
generator in keepercommander.commands.pam_import.playground.

Covers the pure (no-vault) pieces: credential generation (no static secrets,
MSSQL complexity, SSH round-trip), the embedded seccomp profile (base64 round-trip
+ canonical SHA256), the docker-compose builder (parses, 11 depends_on, creds in
env, network name), and file output (cwd -> temp fallback, compose collision
suffixes, seccomp skip-if-present, two-line output).
"""

import hashlib
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

skip_tests = False
skip_reason = ""
try:
    import yaml
    from keepercommander.commands.pam_import import playground as pg
except ImportError as e:  # pragma: no cover
    skip_tests = True
    skip_reason = f"Cannot import pam_import.playground / pyyaml: {e}"

# Canonical docker-seccomp.json (KeeperPAM main == discovery-playground).
SECCOMP_SHA256 = "268fe62ef534293fb1af851cea3da0f1a5ce386e772fd3cb4aaa1c7a4f88aa6b"
SECCOMP_SIZE = 12710

# Full Keeper password special set (PW_SPECIAL_CHARACTERS).
PW_SPECIAL_CHARACTERS = "!@#$%^?();',.=+[]<>{}-_/\\*&:\"`~|"


def _compose_effective(yaml_value):
    """Model docker-compose interpolation: a literal '$' is written '$$'."""
    return yaml_value.replace("$$", "$")


# db-mongo is intentionally disabled until the gateway supports the "mongodb"
# WebRTC ConversationType (see _create_mongodb_records in playground.py).
BACKEND_SERVICES = [
    "db-mysql-1", "db-postgres-1", "db-mariadb-1", "db-mssql",
    "server-ssh-with-pwd-1", "server-ssh-with-key-1", "server-vnc",
    "server-rdp", "server-telnet", "server-openldap-1",
]


@unittest.skipIf(skip_tests, skip_reason)
class TestSeccompEmbed(unittest.TestCase):
    def test_base64_roundtrip_matches_canonical(self):
        self.assertEqual(len(pg.SECCOMP_BYTES), SECCOMP_SIZE)
        self.assertEqual(hashlib.sha256(pg.SECCOMP_BYTES).hexdigest(), SECCOMP_SHA256)

    def test_seccomp_is_valid_json(self):
        import json
        doc = json.loads(pg.SECCOMP_BYTES.decode("utf-8"))
        self.assertIn("syscalls", doc)

    def test_seccomp_url(self):
        self.assertTrue(pg.SECCOMP_URL.endswith("gateway/docker-seccomp.json"))


@unittest.skipIf(skip_tests, skip_reason)
class TestCredentials(unittest.TestCase):
    def setUp(self):
        self.c = pg.PlaygroundCredentials()

    def test_no_static_password_literals(self):
        # Values that used to be hard-coded in edit.py must never appear.
        banned = {"alpine", "postgres", "z@ggz?y|w#I_NFCW!41", "maxpass",
                  "user1pwd", "rootpassword", "root_password", "password"}
        generated = [
            self.c.mysql_root_password, self.c.mysql_user_password,
            self.c.postgres_password, self.c.mariadb_root_password,
            self.c.mariadb_user_password, self.c.mssql_sa_password,
            self.c.mongo_root_password, self.c.mongo_user_password,
            self.c.ssh_password, self.c.vnc_password,
            self.c.rdp_user_password, self.c.rdp_root_password,
            self.c.telnet_password,
        ]
        for pw in generated:
            self.assertNotIn(pw, banned)

    def test_passwords_unique_and_length(self):
        pwds = [
            self.c.mysql_root_password, self.c.mysql_user_password,
            self.c.postgres_password, self.c.mariadb_root_password,
            self.c.mariadb_user_password, self.c.mssql_sa_password,
            self.c.mongo_root_password, self.c.mongo_user_password,
        ]
        self.assertEqual(len(pwds), len(set(pwds)), "generated passwords should differ")
        for pw in pwds:
            self.assertEqual(len(pw), 20)

    def test_passwords_use_only_safe_chars(self):
        import re
        # Only [A-Za-z0-9] plus the safe special set (-._); nothing that needs
        # escaping in cmd/bash/JSON/YAML, no spaces.
        safe_re = re.compile(r"^[A-Za-z0-9" + re.escape(pg.SAFE_SPECIAL_CHARACTERS) + r"]+$")
        for _ in range(25):
            pw = pg._generate_password()
            self.assertRegex(pw, safe_re, f"unsafe char in {pw!r}")

    def test_passwords_contain_a_special_char(self):
        # Enterprise complexity policy requires a special character.
        specials = set(pg.SAFE_SPECIAL_CHARACTERS)
        for _ in range(25):
            pw = pg._generate_password()
            self.assertTrue(specials.intersection(pw), f"no special char in {pw!r}")

    def test_mssql_complexity(self):
        # SQL Server: >= 3 of upper/lower/digit/symbol. Alphanumeric gen gives 3.
        pw = self.c.mssql_sa_password
        categories = sum([
            any(ch.isupper() for ch in pw),
            any(ch.islower() for ch in pw),
            any(ch.isdigit() for ch in pw),
        ])
        self.assertGreaterEqual(categories, 3)
        self.assertGreaterEqual(len(pw), 8)

    def test_ssh_keypair_roundtrip(self):
        from cryptography.hazmat.primitives import serialization
        self.assertTrue(self.c.ssh_private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"))
        self.assertTrue(self.c.ssh_public_key.startswith("ssh-rsa "))
        self.assertTrue(self.c.ssh_public_key.endswith("linuxuser@local"))
        # Private key parses and the derived public matches the emitted public line.
        key = serialization.load_ssh_private_key(self.c.ssh_private_key.encode(), password=None)
        self.assertEqual(key.key_size, 2048)
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode()
        self.assertEqual(self.c.ssh_public_key.split()[1], pub.split()[1])

    def test_fresh_instances_differ(self):
        other = pg.PlaygroundCredentials()
        self.assertNotEqual(self.c.mysql_root_password, other.mysql_root_password)
        self.assertNotEqual(self.c.ssh_private_key, other.ssh_private_key)


@unittest.skipIf(skip_tests, skip_reason)
class TestPasswordPolicyCompliance(unittest.TestCase):
    """Generated secrets must satisfy the enterprise generated_password_complexity policy.

    We satisfy the policy's *password* rules directly (like the Web Vault), rather
    than relying on the passphrase fallback.
    """

    class _FakeParams:
        def __init__(self, policy):
            self.enforcements = {"generated_password_complexity": policy}

    # Strict random-password policy whose special set excludes the safe chars -
    # this is the case that used to fall through to the passphrase check.
    STRICT_POLICY = {
        "length": 24,
        "lower-use": True, "lower-min": 3,
        "upper-use": True, "upper-min": 3,
        "digit-use": True, "digit-min": 3,
        "special-use": True, "special-min": 2, "special": "!@#$%^&*",
        "passphrase-allow": True, "passphrase-length": 5,
    }
    # Policy whose special set includes safe chars -> generator prefers safe.
    SAFE_ALLOWED_POLICY = {
        "length": 20,
        "special-use": True, "special-min": 2, "special": "-._!@#",
    }

    def _factory(self, policy):
        return pg._build_password_factory(self._FakeParams(policy))

    def test_strict_policy_generates_compliant_password(self):
        from keepercommander.enforcement import PasswordComplexityEnforcer
        creds = pg.PlaygroundCredentials(self._factory(self.STRICT_POLICY))
        for pw in (creds.mysql_root_password, creds.mssql_sa_password,
                   creds.postgres_password, creds.telnet_password):
            self.assertEqual(PasswordComplexityEnforcer.validate_password(pw, self.STRICT_POLICY), [])
            self.assertGreaterEqual(len(pw), 24)

    def test_strict_policy_password_roundtrips_through_compose(self):
        # The special set includes '$'; the compose value the container receives
        # (after docker-compose collapses '$$' -> '$') must equal the vault value.
        creds = pg.PlaygroundCredentials(self._factory(self.STRICT_POLICY))
        doc = yaml.safe_load(pg.build_compose(pg.compute_network_id("P"), "CFG==", creds))
        for svc, key, secret in [
            ("db-mysql-1", "MYSQL_ROOT_PASSWORD", creds.mysql_root_password),
            ("db-mssql", "MSSQL_SA_PASSWORD", creds.mssql_sa_password),
        ]:
            yaml_val = doc["services"][svc]["environment"][key]
            self.assertEqual(_compose_effective(yaml_val), secret)

    def test_safe_allowed_policy_prefers_safe_specials(self):
        from keepercommander.enforcement import PasswordComplexityEnforcer
        creds = pg.PlaygroundCredentials(self._factory(self.SAFE_ALLOWED_POLICY))
        pw = creds.mysql_root_password
        self.assertEqual(PasswordComplexityEnforcer.validate_password(pw, self.SAFE_ALLOWED_POLICY), [])
        self.assertTrue(pg._is_safe_secret(pw), f"expected safe specials, got {pw!r}")

    def test_no_policy_uses_safe_random_password(self):
        factory = self._factory(None)
        self.assertIs(factory, pg._generate_password)

    def test_suppress_expected_warnings_filters_only_expected_noise(self):
        import logging
        logger = logging.getLogger()
        records = []

        class _Capture(logging.Handler):
            def emit(self, r):
                records.append(r.getMessage())

        handler = _Capture()
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        prev_level = logger.level
        logger.setLevel(logging.INFO)  # ensure the INFO BreachWatch line is emitted
        try:
            with pg._suppress_expected_warnings():
                logging.warning("Passphrase must contain an allowed separator character. Allowed: -, ., _")
                logging.warning("Password does not meet enterprise complexity policy. Pass --force ...")
                logging.info("High-Risk password detected")  # BreachWatch (INFO level)
                logging.warning("some unrelated warning that must survive")
        finally:
            logger.setLevel(prev_level)
            logger.removeHandler(handler)
        self.assertIn("some unrelated warning that must survive", records)
        self.assertFalse(any("Passphrase must contain" in m for m in records))
        self.assertFalse(any("complexity policy" in m for m in records))
        self.assertFalse(any("High-Risk password detected" in m for m in records))


@unittest.skipIf(skip_tests, skip_reason)
class TestNetworkId(unittest.TestCase):
    def test_truncated_and_underscored(self):
        self.assertEqual(pg.compute_network_id("My Playground"), "My_Playgro")
        self.assertEqual(pg.compute_network_id("abc"), "abc")

    def test_empty_fallback(self):
        self.assertEqual(pg.compute_network_id(""), "pam-net")


@unittest.skipIf(skip_tests, skip_reason)
class TestComposeBuilder(unittest.TestCase):
    def setUp(self):
        self.c = pg.PlaygroundCredentials()
        self.nid = pg.compute_network_id("My Playground")
        self.yaml_text = pg.build_compose(self.nid, "GWCONFIGB64==", self.c)
        self.doc = yaml.safe_load(self.yaml_text)

    def test_depends_on_matches_backend_services(self):
        # db-mongo temporarily disabled -> 10 (was 11). depends_on must list every
        # generated backend service and nothing that isn't defined.
        self.assertEqual(len(pg.GATEWAY_DEPENDS_ON), 10)
        depends_on = self.doc["services"]["keeper-gateway"]["depends_on"]
        self.assertEqual(set(depends_on), set(BACKEND_SERVICES))
        self.assertNotIn("db-mongo", depends_on)

    def test_all_services_present(self):
        svcs = set(self.doc["services"].keys())
        self.assertEqual(svcs, {"keeper-gateway", *BACKEND_SERVICES})

    def test_compose_project_name_set(self):
        # Top-level `name:` sets the Compose project name (else it defaults to the
        # output directory, e.g. "tmp"); derived from --name, docker-sanitized.
        self.assertEqual(pg.compose_project_name("My Playground"), "my-playground")
        self.assertEqual(pg.compose_project_name("SampleData_Playground"), "sampledata_playground")
        self.assertEqual(pg.compose_project_name(""), "playground")
        doc = yaml.safe_load(pg.build_compose(self.nid, "CFG==", self.c, "My Playground"))
        self.assertEqual(doc["name"], "my-playground")

    def test_network_matches_network_id(self):
        self.assertIn(self.nid, self.doc["networks"])
        # Subnet is auto-assigned by Docker (no fixed ipam) to avoid pool overlaps.
        self.assertNotIn("ipam", self.doc["networks"][self.nid] or {})
        self.assertEqual(self.doc["services"]["keeper-gateway"]["networks"], [self.nid])

    def test_gateway_image_and_security_opt(self):
        gw = self.doc["services"]["keeper-gateway"]
        self.assertEqual(gw["image"], pg.GATEWAY_IMAGE)
        self.assertIn("seccomp:docker-seccomp.json", gw["security_opt"])
        self.assertIn("apparmor=unconfined", gw["security_opt"])
        self.assertEqual(gw["environment"]["GATEWAY_CONFIG"], "GWCONFIGB64==")

    def test_credentials_in_env(self):
        env = self.doc["services"]["db-mysql-1"]["environment"]
        self.assertEqual(env["MYSQL_ROOT_PASSWORD"], self.c.mysql_root_password)
        self.assertEqual(env["MYSQL_PASSWORD"], self.c.mysql_user_password)
        self.assertEqual(
            self.doc["services"]["server-ssh-with-key-1"]["environment"]["PUBLIC_KEY"],
            self.c.ssh_public_key)
        self.assertEqual(
            self.doc["services"]["db-mssql"]["environment"]["MSSQL_SA_PASSWORD"],
            self.c.mssql_sa_password)

    def test_no_auth_services_have_no_secrets(self):
        # telnet + openldap carry no env secrets in compose.
        self.assertNotIn("environment", self.doc["services"]["server-telnet"])
        self.assertNotIn("environment", self.doc["services"]["server-openldap-1"])

    def test_mariadb_published_port(self):
        ports = self.doc["services"]["db-mariadb-1"]["ports"]
        self.assertEqual(ports[0]["published"], 33306)

    def test_yq_roundtrips_all_special_chars(self):
        # Every special char (incl. ' $ \ " ` etc.) must survive YAML parsing
        # and docker-compose interpolation back to the original value.
        values = [
            PW_SPECIAL_CHARACTERS,
            "a$b$$c",              # bare + doubled dollars
            "quote'and$dollar",    # single quote next to dollar
            "trailing$",
            "back\\slash\"quote`tick",
        ]
        for val in values:
            loaded = yaml.safe_load("k: " + pg._yq(val))["k"]
            self.assertEqual(_compose_effective(loaded), val, f"roundtrip failed for {val!r}")


@unittest.skipIf(skip_tests, skip_reason)
class TestFileOutput(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def _run(self, yaml_text="services: {}\n"):
        buf = io.StringIO()
        with redirect_stdout(buf):
            path = pg.save_compose_and_seccomp(yaml_text)
        return path, buf.getvalue()

    def test_writes_compose_and_seccomp(self):
        path, out = self._run()
        self.assertTrue(os.path.isfile(path))
        seccomp = os.path.join(os.path.dirname(path), pg.SECCOMP_FILENAME)
        self.assertTrue(os.path.isfile(seccomp))
        with open(seccomp, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), SECCOMP_SHA256)

    def test_two_line_output(self):
        path, out = self._run()
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], os.path.abspath(path))
        self.assertEqual(lines[1], pg.SECCOMP_URL)

    def test_compose_collision_gets_suffix(self):
        p1, _ = self._run()
        self.assertEqual(os.path.basename(p1), pg.COMPOSE_FILENAME)
        p2, _ = self._run()
        self.assertNotEqual(p1, p2)
        self.assertTrue(os.path.basename(p2).startswith("docker-compose-"))

    def test_seccomp_skipped_when_present(self):
        p1, _ = self._run()
        seccomp = os.path.join(os.path.dirname(p1), pg.SECCOMP_FILENAME)
        os.utime(seccomp, (1, 1))  # mark
        before = os.stat(seccomp).st_mtime
        self._run()  # second run must not overwrite seccomp
        self.assertEqual(os.stat(seccomp).st_mtime, before)


if __name__ == "__main__":
    unittest.main()
