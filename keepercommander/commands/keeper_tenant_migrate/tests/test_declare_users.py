"""Phase 1.2 — users.drop / users.domain_remap with cross-ref propagation.

Cascade scope (per `overlay_v1.UserEdits`):
  - drop: cascades to shared_folders[*].users[*].username and
    records[*].direct_shares[*].username (both username-keyed dicts).
  - domain_remap: rewrites users[*].email/aliases/alias AND the same
    SF.users / records.direct_shares username refs.

Inventory user shape mirrors `inventory.py:136-149` (parse_users_csv):
  - email, aliases (list), alias (raw concat), teams, roles, status,
    transfer_status, node, 2fa_enabled, job_title.

SF.users / records.direct_shares are dicts with {'username': email, ...}
per Commander API shape passed through `inventory.py:174` and 304-309.
"""
import unittest

from keepercommander.commands.keeper_tenant_migrate.declare.overlay import apply_overlay
from keepercommander.commands.keeper_tenant_migrate.declare.schema.overlay_v1 import OverlayManifest


def _manifest(edits: dict) -> OverlayManifest:
    return OverlayManifest.model_validate(
        {"schema": "tenant-overlay.v1", "name": "t", "base": "b", "edits": edits}
    )


def _user(email, aliases=None, **extra):
    aliases = aliases or []
    extra_alias = extra.pop("alias", None)
    if extra_alias is None:
        # Mirror inventory.py:144-145: 'alias' is raw concat of primary+aliases,
        # 'aliases' excludes the primary (lower-case match).
        if aliases:
            extra_alias = "\n".join([email] + aliases)
        else:
            extra_alias = email
    return {
        "email": email,
        "aliases": list(aliases),
        "alias": extra_alias,
        "status": "Active",
        "transfer_status": "",
        "node": "Eng",
        "teams": [],
        "roles": [],
        **extra,
    }


def _inv(users, sfs=None, records=None, counts_users=None):
    inv = {
        "schema": "tenant-inventory.v1",
        "tenant_uid": "T1",
        "entities": {
            "users": list(users),
            "shared_folders": list(sfs or []),
            "records": list(records or []),
        },
        "counts": {},
    }
    if counts_users is not None:
        inv["counts"]["users"] = counts_users
    return inv


# ─── users.drop ──────────────────────────────────────────────────────────────


class TestUserDropExact(unittest.TestCase):

    def test_drops_user_by_exact_email(self):
        inv = _inv([_user("alice@acme.com"), _user("bob@acme.com")])
        m = _manifest({"users": {"drop": ["alice@acme.com"]}})
        out = apply_overlay(inv, m)
        emails = [u["email"] for u in out["entities"]["users"]]
        self.assertEqual(emails, ["bob@acme.com"])

    def test_does_not_match_non_matching_emails(self):
        inv = _inv([_user("alice@acme.com"), _user("bob@acme.com")])
        m = _manifest({"users": {"drop": ["alice@other.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(len(out["entities"]["users"]), 2)

    def test_decrements_users_count_when_present(self):
        inv = _inv([_user("a@x.com"), _user("b@x.com")], counts_users=2)
        m = _manifest({"users": {"drop": ["a@x.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["counts"]["users"], 1)

    def test_no_count_field_no_crash(self):
        inv = _inv([_user("a@x.com")])
        inv["counts"].pop("users", None)
        m = _manifest({"users": {"drop": ["a@x.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["users"], [])


class TestUserDropGlobs(unittest.TestCase):

    def test_wildcard_drops_whole_domain(self):
        inv = _inv([_user("a@old.com"), _user("b@old.com"), _user("c@new.com")])
        m = _manifest({"users": {"drop": ["*@old.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual([u["email"] for u in out["entities"]["users"]],
                         ["c@new.com"])

    def test_question_mark_glob(self):
        inv = _inv([_user("svc1@x.com"), _user("svc2@x.com"),
                    _user("svc10@x.com"), _user("alice@x.com")])
        m = _manifest({"users": {"drop": ["svc?@x.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(sorted(u["email"] for u in out["entities"]["users"]),
                         ["alice@x.com", "svc10@x.com"])

    def test_charset_glob(self):
        inv = _inv([_user("svc1@x.com"), _user("svc2@x.com"),
                    _user("svc3@x.com"), _user("svc9@x.com")])
        m = _manifest({"users": {"drop": ["svc[1-3]@x.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(sorted(u["email"] for u in out["entities"]["users"]),
                         ["svc9@x.com"])

    def test_multiple_patterns_union(self):
        inv = _inv([_user("a@x.com"), _user("b@y.com"), _user("c@z.com")])
        m = _manifest({"users": {"drop": ["a@x.com", "*@z.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual([u["email"] for u in out["entities"]["users"]],
                         ["b@y.com"])

    def test_empty_email_does_not_match_wildcard_implicitly(self):
        # A user with empty email shouldn't be dropped by '*@x.com' but
        # should be dropped by '*' if the operator really wants that.
        inv = _inv([_user(""), _user("a@x.com")])
        m = _manifest({"users": {"drop": ["*@x.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual([u["email"] for u in out["entities"]["users"]], [""])


class TestUserDropCascade(unittest.TestCase):

    def test_cascades_to_sf_users(self):
        inv = _inv(
            [_user("a@x.com"), _user("b@x.com")],
            sfs=[{"uid": "SF1", "name": "F1", "users": [
                {"username": "a@x.com", "manage_users": True},
                {"username": "b@x.com", "manage_users": False},
            ]}],
        )
        m = _manifest({"users": {"drop": ["a@x.com"]}})
        out = apply_overlay(inv, m)
        sf_users = out["entities"]["shared_folders"][0]["users"]
        self.assertEqual([u["username"] for u in sf_users], ["b@x.com"])

    def test_cascades_to_record_direct_shares(self):
        inv = _inv(
            [_user("a@x.com"), _user("b@x.com")],
            records=[{"uid": "R1", "title": "x", "direct_shares": [
                {"username": "a@x.com", "editable": True},
                {"username": "b@x.com", "editable": False},
            ]}],
        )
        m = _manifest({"users": {"drop": ["a@x.com"]}})
        out = apply_overlay(inv, m)
        ds = out["entities"]["records"][0]["direct_shares"]
        self.assertEqual([s["username"] for s in ds], ["b@x.com"])

    def test_glob_cascade_to_sf_and_records(self):
        inv = _inv(
            [_user("a@old.com"), _user("b@old.com"), _user("c@new.com")],
            sfs=[{"uid": "SF1", "users": [
                {"username": "a@old.com"},
                {"username": "b@old.com"},
                {"username": "c@new.com"},
            ]}],
            records=[{"uid": "R1", "direct_shares": [
                {"username": "a@old.com"},
                {"username": "c@new.com"},
            ]}],
        )
        m = _manifest({"users": {"drop": ["*@old.com"]}})
        out = apply_overlay(inv, m)
        self.assertEqual(
            [u["username"] for u in out["entities"]["shared_folders"][0]["users"]],
            ["c@new.com"],
        )
        self.assertEqual(
            [s["username"] for s in out["entities"]["records"][0]["direct_shares"]],
            ["c@new.com"],
        )

    def test_does_not_touch_non_dict_sf_user_entries(self):
        # Defensive: if a producer ever emits string entries, they pass through.
        inv = _inv(
            [_user("a@x.com")],
            sfs=[{"uid": "SF1", "users": ["a@x.com", {"username": "a@x.com"}]}],
        )
        m = _manifest({"users": {"drop": ["a@x.com"]}})
        out = apply_overlay(inv, m)
        # String entry survives (no shape match), dict entry is dropped.
        self.assertEqual(out["entities"]["shared_folders"][0]["users"], ["a@x.com"])


# ─── users.domain_remap ──────────────────────────────────────────────────────


class TestDomainRemap(unittest.TestCase):

    def test_rewrites_primary_email(self):
        inv = _inv([_user("alice@acme.com")])
        m = _manifest({"users": {"domain_remap": {"acme.com": "acme.io"}}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["users"][0]["email"], "alice@acme.io")

    def test_preserves_local_part_case(self):
        inv = _inv([_user("Admin@Acme.com")])
        m = _manifest({"users": {"domain_remap": {"acme.com": "acme.io"}}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["users"][0]["email"], "Admin@acme.io")

    def test_non_matching_domain_passes_through(self):
        inv = _inv([_user("alice@other.com")])
        m = _manifest({"users": {"domain_remap": {"acme.com": "acme.io"}}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["users"][0]["email"], "alice@other.com")

    def test_rewrites_aliases_list(self):
        inv = _inv([_user("alice@acme.com",
                          aliases=["alice@acme.com", "alice.smith@acme.com",
                                   "alice@other.com"])])
        m = _manifest({"users": {"domain_remap": {"acme.com": "acme.io"}}})
        out = apply_overlay(inv, m)
        u = out["entities"]["users"][0]
        self.assertEqual(u["email"], "alice@acme.io")
        self.assertEqual(u["aliases"],
                         ["alice@acme.io", "alice.smith@acme.io", "alice@other.com"])

    def test_rebuilds_raw_alias_field(self):
        # Raw 'alias' is the newline-joined concat: primary + extras
        # (extras = aliases minus primary, case-insensitive).
        inv = _inv([_user("alice@acme.com",
                          aliases=["alice@acme.com", "alice.smith@acme.com"])])
        m = _manifest({"users": {"domain_remap": {"acme.com": "acme.io"}}})
        out = apply_overlay(inv, m)
        u = out["entities"]["users"][0]
        self.assertEqual(u["alias"], "alice@acme.io\nalice.smith@acme.io")

    def test_multi_domain_mapping(self):
        inv = _inv([_user("a@x.com"), _user("b@y.com"), _user("c@z.com")])
        m = _manifest({"users": {"domain_remap": {"x.com": "X.io", "y.com": "Y.io"}}})
        out = apply_overlay(inv, m)
        emails = sorted(u["email"] for u in out["entities"]["users"])
        # remap_email lower-cases the new domain.
        self.assertEqual(emails, ["a@x.io", "b@y.io", "c@z.com"])

    def test_cascade_to_sf_users(self):
        inv = _inv(
            [_user("a@old.com")],
            sfs=[{"uid": "SF1", "users": [{"username": "a@old.com"}]}],
        )
        m = _manifest({"users": {"domain_remap": {"old.com": "new.com"}}})
        out = apply_overlay(inv, m)
        self.assertEqual(
            out["entities"]["shared_folders"][0]["users"][0]["username"],
            "a@new.com",
        )

    def test_cascade_to_record_direct_shares(self):
        inv = _inv(
            [_user("a@old.com")],
            records=[{"uid": "R1", "direct_shares": [{"username": "a@old.com"}]}],
        )
        m = _manifest({"users": {"domain_remap": {"old.com": "new.com"}}})
        out = apply_overlay(inv, m)
        self.assertEqual(
            out["entities"]["records"][0]["direct_shares"][0]["username"],
            "a@new.com",
        )

    def test_atomic_swap(self):
        # {"a.com": "b.com", "b.com": "a.com"} — captured map at entry,
        # so an entity is touched once with its CURRENT (= original) value.
        inv = _inv([_user("alice@a.com"), _user("bob@b.com")])
        m = _manifest({"users": {"domain_remap": {"a.com": "b.com", "b.com": "a.com"}}})
        out = apply_overlay(inv, m)
        emails = sorted(u["email"] for u in out["entities"]["users"])
        self.assertEqual(emails, ["alice@b.com", "bob@a.com"])

    def test_empty_mapping_is_pass_through(self):
        inv = _inv([_user("alice@acme.com")])
        m = _manifest({"users": {}})
        out = apply_overlay(inv, m)
        self.assertEqual(out["entities"]["users"][0]["email"], "alice@acme.com")


class TestDropAndRemapInteraction(unittest.TestCase):

    def test_drop_runs_before_remap(self):
        # alice@old.com is dropped; bob@old.com is remapped to bob@new.com.
        inv = _inv([_user("alice@old.com"), _user("bob@old.com")])
        m = _manifest({"users": {
            "drop": ["alice@old.com"],
            "domain_remap": {"old.com": "new.com"},
        }})
        out = apply_overlay(inv, m)
        emails = [u["email"] for u in out["entities"]["users"]]
        self.assertEqual(emails, ["bob@new.com"])

    def test_drop_pattern_uses_pre_remap_email(self):
        # Operator drops by old-domain glob; remap then runs on survivors.
        inv = _inv([_user("a@old.com"), _user("b@old.com"), _user("c@new.com")])
        m = _manifest({"users": {
            "drop": ["a@old.com"],
            "domain_remap": {"old.com": "new.com"},
        }})
        out = apply_overlay(inv, m)
        self.assertEqual(sorted(u["email"] for u in out["entities"]["users"]),
                         ["b@new.com", "c@new.com"])


class TestImmutability(unittest.TestCase):

    def test_base_inventory_not_mutated(self):
        u = _user("alice@acme.com", aliases=["alice@acme.com"])
        inv = _inv([u])
        m = _manifest({"users": {"domain_remap": {"acme.com": "acme.io"}}})
        _ = apply_overlay(inv, m)
        self.assertEqual(inv["entities"]["users"][0]["email"], "alice@acme.com")
        self.assertEqual(inv["entities"]["users"][0]["aliases"], ["alice@acme.com"])


if __name__ == "__main__":
    unittest.main()
