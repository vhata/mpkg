"""Private path metadata fixtures; no production paths or account changes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.observe_files import MAX_PATH_BYTES, MAX_RESOURCES, SystemIdentities, observe_files
from mpkg_manager.planning import build_report
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T12:00:00Z"
NOW = datetime(2026, 11, 2, 12, tzinfo=timezone.utc)


class Names:
    def user(self, uid):
        return "fixture_owner"

    def group(self, gid):
        return "fixture_group"


class FileObservationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.file = self.root / "SECRET_PATH.conf"
        self.file.write_bytes(b"SECRET_CONTENT_SENTINEL\n")
        self.file.chmod(0o640)
        self.directory = self.root / "data"
        self.directory.mkdir(mode=0o750)
        self.link = self.root / "private-link"
        self.link.symlink_to("SECRET_TARGET_MISSING")
        self.names = Names()

    def resource(self, path=None, *, kind="file", name="fixture", desired=None):
        return {"id": name, "kind": kind, "identity": {"path": str(self.file if path is None else path)},
                "desired": {} if desired is None else desired}

    def observe(self, resources=None, **kwargs):
        return observe_files([self.resource()] if resources is None else resources,
                             **({"host_id": HOST, "observed_at": WHEN, "identities": self.names} | kwargs))

    def facts(self, batch, name="fixture"):
        return {fact.property: fact for fact in batch.for_resource(name)}

    def declaration(self, resources):
        entries = []
        for resource in resources:
            desired = resource["desired"]
            fields = ','.join(key + '=' + json.dumps(value) for key, value in desired.items())
            entries.append(f'''[[resources]]
id={json.dumps(resource["id"])}
kind={json.dumps(resource["kind"])}
identity={{path={json.dumps(resource["identity"]["path"])}}}
manage={json.dumps(list(desired))}
desired={{{fields}}}
''')
        return load_declaration(('schema=1\ncomponents=[]\n' + ''.join(entries)).encode())

    def store(self):
        store = HostStore.create(self.root / "store", HOST, owner_uid=os.geteuid())
        self.addCleanup(store.close)
        return store

    def test_real_file_directory_and_dangling_link_metadata_without_content_reads(self):
        resources = [self.resource(), self.resource(self.directory, kind="directory", name="directory"),
                     self.resource(self.link, kind="symlink", name="link")]
        original = os.open
        flags = []
        def metadata_open(path, mode, *args, **kwargs):
            flags.append(mode)
            self.assertTrue(mode & os.O_PATH)
            self.assertTrue(mode & os.O_NOFOLLOW)
            return original(path, mode, *args, **kwargs)
        with patch("mpkg_manager.observe_files.os.open", metadata_open), \
             patch("os.read", side_effect=AssertionError("No content reads")), \
             patch("subprocess.Popen", side_effect=AssertionError("No processes")), \
             patch("os.listdir", side_effect=AssertionError("No directory enumeration")):
            batch = self.observe(resources)
        self.assertTrue(flags)
        self.assertEqual(batch.coverage, ("fixture", "directory", "link"))
        for name, mode in (("fixture", 0o640), ("directory", 0o750), ("link", 0o777)):
            facts = self.facts(batch, name)
            self.assertIs(facts["present"].value, True)
            self.assertEqual(facts["mode"].value, mode)
            self.assertEqual(facts["owner"].value, "fixture_owner")
            self.assertEqual(facts["group"].value, "fixture_group")
        self.assertEqual(self.facts(batch, "link")["target"].value, "SECRET_TARGET_MISSING")
        self.assertEqual(self.facts(batch)["content_input"].state, "unknown")

    def test_missing_leaf_and_ancestor_are_absent_with_verified_parent_chain(self):
        for path in (self.root / "missing", self.root / "missing" / "descendant"):
            facts = self.facts(self.observe([self.resource(path)]))
            self.assertIs(facts["present"].value, False)
            self.assertEqual(facts["present"].state, "known")
            self.assertEqual(facts["mode"].state, "absent")

    def test_parent_symlink_and_non_directory_never_imply_absence(self):
        alias = self.root / "alias"
        alias.symlink_to(self.directory)
        for path, reason in ((alias / "missing", "parent_symlink_not_followed"),
                             (self.file / "missing", "parent_not_directory")):
            facts = self.facts(self.observe([self.resource(path)]))
            self.assertEqual(facts["present"].state, "unknown")
            self.assertEqual(facts["present"].limitations, (reason,))

    def test_wrong_kind_and_special_files_are_unknown_without_opening_content(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path, kind in ((self.directory, "file"), (self.file, "directory"),
                           (self.link, "file"), (self.file, "symlink"), (fifo, "file")):
            facts = self.facts(self.observe([self.resource(path, kind=kind)]))
            self.assertEqual(facts["present"].state, "unknown")
            self.assertEqual(facts["present"].limitations, ("path_kind_mismatch",))

    def test_denied_leaf_and_parent_remain_unknown_with_fixed_diagnostics(self):
        original = os.stat
        for denied in (self.file.name, self.root.name):
            def denial(path, *args, **kwargs):
                if path == denied:
                    raise PermissionError("SECRET_DIAGNOSTIC")
                return original(path, *args, **kwargs)
            with patch("mpkg_manager.observe_files.os.stat", denial):
                batch = self.observe()
            self.assertEqual(self.facts(batch)["present"].limitations, ("path_permission_denied",))
            self.assertNotIn("SECRET_DIAGNOSTIC", json.dumps(batch.as_dict()))

    def test_leaf_replacement_during_name_lookup_invalidates_all_metadata(self):
        names = Names()
        def replace(uid):
            candidate = self.root / "replacement"
            candidate.write_bytes(b"different")
            candidate.replace(self.file)
            return "fixture_owner"
        names.user = replace
        facts = self.facts(self.observe(identities=names))
        self.assertEqual({fact.state for fact in facts.values()}, {"unknown"})
        self.assertEqual(facts["present"].limitations, ("path_changed",))

    def test_parent_replacement_during_name_lookup_invalidates_all_metadata(self):
        child = self.directory / "child"
        child.write_bytes(b"private")
        def replace(uid):
            self.directory.rename(self.root / "moved")
            self.directory.mkdir()
            return "fixture_owner"
        self.names.user = replace
        facts = self.facts(self.observe([self.resource(child)]))
        self.assertEqual(facts["present"].limitations, ("path_changed",))

    def test_missing_path_that_appears_before_confirmation_is_unknown(self):
        missing = self.root / "missing"
        original = os.stat
        def appears(path, *args, **kwargs):
            try:
                return original(path, *args, **kwargs)
            except FileNotFoundError:
                if path == missing.name:
                    missing.write_bytes(b"new")
                raise
        with patch("mpkg_manager.observe_files.os.stat", appears):
            facts = self.facts(self.observe([self.resource(missing)]))
        self.assertEqual(facts["present"].limitations, ("path_changed",))

    def test_ownership_lookup_failure_is_independent_from_other_metadata(self):
        for value in (None, "bad/name", "x" * 256, True):
            self.names.user = lambda uid: value
            facts = self.facts(self.observe())
            self.assertEqual(facts["owner"].state, "unknown")
            self.assertEqual(facts["owner"].limitations, ("identity_name_unavailable",))
            self.assertEqual(facts["group"].value, "fixture_group")
            self.assertIs(facts["present"].value, True)
        def missing(uid):
            raise KeyError("SECRET_DIAGNOSTIC")
        self.names.user = missing
        self.assertEqual(self.facts(self.observe())["owner"].state, "unknown")

    def test_native_resolver_requires_bounded_names_and_reverse_forward_agreement(self):
        uid, gid = self.file.stat().st_uid, self.file.stat().st_gid
        user = SimpleNamespace(pw_name="fixture_owner", pw_uid=uid)
        group = SimpleNamespace(gr_name="fixture_group", gr_gid=gid)
        with patch("mpkg_manager.observe_files.pwd.getpwuid", return_value=user) as reverse_user, \
             patch("mpkg_manager.observe_files.pwd.getpwnam", return_value=user) as forward_user, \
             patch("mpkg_manager.observe_files.grp.getgrgid", return_value=group) as reverse_group, \
             patch("mpkg_manager.observe_files.grp.getgrnam", return_value=group) as forward_group:
            self.assertEqual(self.facts(self.observe(identities=None))["owner"].value, user.pw_name)
            for query in (reverse_user, forward_user, reverse_group, forward_group):
                self.assertEqual(query.call_count, 1)
            forward_user.return_value = SimpleNamespace(pw_name="fixture_owner", pw_uid=uid + 1)
            self.assertEqual(self.facts(self.observe(identities=None))["owner"].state, "unknown")
            reverse_group.return_value = SimpleNamespace(gr_name="SECRET/bad", gr_gid=gid)
            self.assertEqual(self.facts(self.observe(identities=None))["group"].state, "unknown")

    def test_validate_all_target_identities_and_bounds_before_any_filesystem_reads(self):
        variants = [[self.resource(), self.resource(name="fixture")],
                    [self.resource(kind="volume")], [self.resource(self.root / ".." / "bad")],
                    [self.resource("/" + "x" * MAX_PATH_BYTES)],
                    [self.resource("/" + "/".join(["x"] * 129))],
                    [self.resource(name=str(index)) for index in range(MAX_RESOURCES + 1)],
                    [{**self.resource(), "identity": {"wrong": str(self.file)}}]]
        with patch("os.open", side_effect=AssertionError("Must not open")):
            for resources in variants:
                with self.assertRaisesRegex(ValueError, "^invalid_file_observation_request$"):
                    self.observe(resources)
        resource = self.resource()
        resource.update(input={"bundle": "external-context"}, checks=["elsewhere"],
                        desired={"content_input": "external-context"})
        self.assertIs(self.facts(self.observe([resource]))["present"].value, True)

    def test_interrupt_closes_all_descriptors_and_preserves_cancellation(self):
        original = os.open
        opened = []
        def tracked(*args, **kwargs):
            fd = original(*args, **kwargs)
            opened.append(fd)
            return fd
        def cancel(uid):
            raise KeyboardInterrupt
        self.names.user = cancel
        with patch("mpkg_manager.observe_files.os.open", tracked):
            with self.assertRaises(KeyboardInterrupt):
                self.observe()
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_real_store_and_planner_compare_metadata_redact_values_and_keep_authority(self):
        resources = [self.resource(desired={"present": True, "mode": 0o600, "owner": "fixture_owner"}),
                     self.resource(self.link, kind="symlink", name="link", desired={"target": "SECRET_TARGET_MISSING"})]
        declaration = self.declaration(resources)
        store = self.store()
        store.adopt(declaration, 0, ["fixture", "link"])
        batch = self.observe(declaration.model["resources"])
        before = store.history()
        report = build_report(declaration, store.current(), batch.as_dict(), host_id=HOST, now=NOW)
        self.assertEqual(store.history(), before)
        props = {row["resource_id"]: {item["property"]: item for item in row["properties"]}
                 for row in report.as_dict()["resources"]}
        self.assertEqual(props["fixture"]["present"]["comparison"], "agreement")
        self.assertEqual(props["fixture"]["mode"]["comparison"], "difference")
        self.assertEqual(props["link"]["target"]["comparison"], "agreement")
        self.assertTrue(props["fixture"]["mode"]["authority"])
        for secret in (str(self.root), "SECRET_PATH", "SECRET_TARGET", "SECRET_CONTENT", "fixture_owner"):
            self.assertNotIn(secret.encode(), report.canonical_bytes)
        self.assertFalse(report.as_dict()["executable"])
        self.assertIn("application_not_implemented", report.as_dict()["blockers"])
        renamed = self.declaration([self.resource(name="new", desired={"mode": 0o640})])
        result = build_report(renamed, store.current(), self.observe(renamed.model["resources"]).as_dict(),
                              host_id=HOST, now=NOW).as_dict()
        self.assertTrue(result["resources"][0]["properties"][0]["authority"])
        wrong_kind = self.declaration([self.resource(kind="directory", desired={"mode": 0o640})])
        result = build_report(wrong_kind, store.current(), self.observe(wrong_kind.model["resources"]).as_dict(),
                              host_id=HOST, now=NOW).as_dict()
        self.assertFalse(result["resources"][0]["properties"][0]["authority"])

    def test_planner_rejects_wrong_source_identity_host_and_stale_metadata(self):
        declaration = self.declaration([self.resource(desired={"present": True})])
        store = self.store()
        store.adopt(declaration, 0, ["fixture"])
        wire = self.observe().as_dict()
        variants = []
        for key, value in (("evidence_source", "future_filesystem_adapter"),
                           ("identity", {"path": str(self.directory)}), ("kind", "directory")):
            changed = deepcopy(wire)
            changed["facts"][0][key] = value
            variants.append((changed, NOW))
        other = deepcopy(wire)
        other["host_id"] = "22345678-1234-4234-8234-123456789abc"
        for fact in other["facts"]:
            fact["host_id"] = other["host_id"]
        variants += [(other, NOW), (wire, NOW + timedelta(seconds=61)), (wire, NOW - timedelta(seconds=1))]
        for evidence, now in variants:
            result = build_report(declaration, store.current(), evidence, host_id=HOST, now=now).as_dict()
            self.assertEqual(result["resources"][0]["properties"][0]["comparison"], "unknown")


if __name__ == "__main__":
    unittest.main()
