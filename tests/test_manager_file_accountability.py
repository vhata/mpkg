"""Private filesystem enumeration; no production paths or package tools."""
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.file_accountability import ScanLimits, ScanScope, scan_files


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T19:00:00Z"


def _toml(value):
    if type(value) is dict:
        return "{" + ",".join(json.dumps(key) + "=" + _toml(item) for key, item in value.items()) + "}"
    if type(value) is list:
        return "[" + ",".join(_toml(item) for item in value) + "]"
    return json.dumps(value)


class AccountabilityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.outer = Path(directory.name)
        self.root = self.outer / "PRIVATE_SCOPE_SENTINEL"
        self.root.mkdir()
        self.scope = ScanScope("fixture", str(self.root))

    def declaration(self, *, resources=(), rules=()):
        components = sorted({rule["component"] for rule in rules})
        model = {"schema": 1, "components": [dict(id=name, purpose="Fixture", resources=[])
                                             for name in components],
                 "resources": list(resources), "runtime_rules": list(rules)}
        source = "\n".join(key + "=" + _toml(value) for key, value in model.items())
        return load_declaration(source.encode())

    def resource(self, name, path, kind="file"):
        return {"id": name, "kind": kind, "identity": {"path": str(path)}}

    def rule(self, *, name="runtime", component="app", patterns=None, types=None, exceptions=()):
        return {"id": name, "component": component, "root": str(self.root),
                "patterns": ["**"] if patterns is None else patterns,
                "types": ["file", "directory", "symlink"] if types is None else types,
                "exceptions": [str(item) for item in exceptions]}

    def scan(self, declaration=None, **options):
        return scan_files(self.declaration() if declaration is None else declaration,
                          options.pop("scopes", [self.scope]),
                          **({"host_id": HOST, "observed_at": WHEN} | options))

    def entries(self, result):
        return {entry.relative_path: entry for entry in result.scopes[0].entries}

    def reasons(self, result, index=0):
        return {gap.reason for gap in result.scopes[index].gaps}

    def test_classification_preserves_configuration_unexplained_and_side_files(self):
        config = self.root / "configuration"
        config.write_text("SECRET_CONTENT_SENTINEL")
        (self.root / "runtime.log").write_text("private")
        (self.root / "unexpected").write_text("private")
        (self.root / "configuration.pacnew").write_text("private")
        (self.root / "configuration.pacsave").write_text("private")
        declaration = self.declaration(
            resources=[self.resource("root", self.root, "directory"), self.resource("config", config)],
            rules=[self.rule(patterns=["*.log", "*.pacnew", "*.pacsave"], exceptions=[config])])
        with patch("builtins.open", side_effect=AssertionError("No content reads")), \
             patch("os.read", side_effect=AssertionError("No descriptor content reads")), \
             patch("subprocess.Popen", side_effect=AssertionError("No processes")):
            result = self.scan(declaration)
        entries = self.entries(result)
        self.assertEqual(result.scopes[0].state, "complete")
        self.assertEqual(entries["."].classification, "declared_resource")
        self.assertEqual(entries["configuration"].classification, "declared_configuration")
        self.assertEqual(entries["configuration"].resource_ids, ("config",))
        self.assertEqual(entries["runtime.log"].classification, "runtime_rule_match")
        self.assertEqual(entries["unexpected"].classification, "unexplained")
        for name in ("configuration.pacnew", "configuration.pacsave"):
            self.assertEqual(entries[name].classification, "package_side_file")
        self.assertIn("metadata_not_content_or_package_baseline", result.limitations)

    def test_single_segment_patterns_do_not_cover_nested_paths(self):
        (self.root / "one.log").write_text("")
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "two.log").write_text("")
        entries = self.entries(self.scan(self.declaration(rules=[self.rule(patterns=["*.log"])])))
        self.assertEqual(entries["one.log"].classification, "runtime_rule_match")
        self.assertEqual(entries["nested/two.log"].classification, "unexplained")

    def test_recursive_patterns_and_exceptions_are_precise(self):
        for relative in ("one1.log", "oneq.log", "nested/one2.log", "nested/deep/one3.log"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        declaration = self.declaration(rules=[self.rule(patterns=["**/one[0-9].log"],
                                                       exceptions=[self.root / "nested/deep"])])
        entries = self.entries(self.scan(declaration))
        for relative in ("one1.log", "nested/one2.log"):
            self.assertEqual(entries[relative].classification, "runtime_rule_match")
        for relative in ("oneq.log", "nested/deep/one3.log"):
            self.assertEqual(entries[relative].classification, "unexplained")

    def test_overlapping_component_rules_are_unknown(self):
        (self.root / "data").write_text("")
        rules = [self.rule(), self.rule(name="other", component="other")]
        entry = self.entries(self.scan(self.declaration(rules=rules)))["data"]
        self.assertEqual(entry.classification, "unknown")
        self.assertEqual(entry.reason, "ambiguous_runtime_responsibility")
        self.assertEqual(entry.component_ids, ("app", "other"))
        rules[1]["component"] = "app"
        entry = self.entries(self.scan(self.declaration(rules=rules)))["data"]
        self.assertEqual(entry.classification, "runtime_rule_match")
        self.assertEqual(entry.rule_ids, ("other", "runtime"))

    def test_wrong_kind_declared_configuration_is_not_hidden_by_runtime_rule(self):
        config = self.root / "config"
        config.mkdir()
        declaration = self.declaration(resources=[self.resource("config", config)],
                                       rules=[self.rule(exceptions=[config])])
        entry = self.entries(self.scan(declaration))["config"]
        self.assertEqual(entry.classification, "unknown")
        self.assertEqual(entry.reason, "declared_kind_mismatch")

    def test_symlinks_and_special_files_never_open_targets_or_contents(self):
        outside = self.outer / "OUTSIDE_SECRET"
        outside.mkdir()
        (outside / "unseen").write_text("SECRET_CONTENT")
        (self.root / "outside").symlink_to(outside, target_is_directory=True)
        (self.root / "dangling").symlink_to("SECRET_TARGET")
        os.mkfifo(self.root / "fifo")
        original = os.open
        opened = []
        def guarded(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_PATH or flags & os.O_DIRECTORY)
            self.assertFalse(flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_WRONLY | os.O_RDWR))
            opened.append(path)
            return original(path, flags, *args, **kwargs)
        with patch("mpkg_manager.file_accountability.os.open", guarded), \
             patch("os.readlink", side_effect=AssertionError("Do not read link targets")):
            result = self.scan()
        entries = self.entries(result)
        self.assertEqual(set(entries), {".", "outside", "dangling", "fifo"})
        self.assertEqual(entries["outside"].kind, "symlink")
        self.assertEqual(entries["fifo"].kind, "special")
        self.assertNotIn("outside", opened)
        self.assertEqual(result.summary()["policy"]["symlinks"], "never_follow")

    def test_exclusion_reports_gap_without_enumerating_subtree(self):
        hidden = self.root / "hidden"
        hidden.mkdir()
        (hidden / "secret").write_text("")
        (self.root / "visible").write_text("")
        scope = ScanScope("fixture", str(self.root), [str(hidden)])
        original = os.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path, "hidden")
            return original(path, *args, **kwargs)
        with patch("mpkg_manager.file_accountability.os.open", guarded):
            result = self.scan(scopes=[scope])
        self.assertEqual(result.scopes[0].state, "partial")
        self.assertEqual(set(self.entries(result)), {".", "visible"})
        self.assertEqual(self.reasons(result), {"excluded"})
        with patch("os.open", side_effect=AssertionError("Excluded root is not opened")):
            result = self.scan(scopes=[ScanScope("fixture", str(self.root), [str(self.root)])])
        self.assertEqual(result.scopes[0].state, "unavailable")

    def test_missing_symlink_and_wrong_kind_roots_are_unavailable(self):
        (self.root / "file").write_text("")
        (self.outer / "alias").symlink_to(self.root, target_is_directory=True)
        for path in (self.root / "missing", self.root / "file", self.outer / "alias",
                     self.outer / "alias" / "child"):
            with self.subTest(path=path):
                result = self.scan(scopes=[ScanScope("fixture", str(path))])
                self.assertEqual(result.scopes[0].state, "unavailable")
                self.assertFalse(result.scopes[0].entries)

    def test_metadata_permission_denial_is_partial_and_redacted(self):
        (self.root / "denied").write_text("")
        (self.root / "visible").write_text("")
        original = os.stat
        def denied(path, *args, **kwargs):
            if path == "denied":
                raise PermissionError("PRIVATE_ERROR_SENTINEL")
            return original(path, *args, **kwargs)
        with patch("mpkg_manager.file_accountability.os.stat", denied):
            result = self.scan()
        self.assertEqual(result.scopes[0].state, "partial")
        self.assertIn("visible", self.entries(result))
        self.assertEqual(self.reasons(result), {"entry_permission_denied"})
        self.assertNotIn("PRIVATE_ERROR_SENTINEL", json.dumps(result.summary()))

    def test_unreadable_directory_never_becomes_complete(self):
        (self.root / "denied").mkdir()
        original = os.open
        def denied(path, *args, **kwargs):
            if path == "denied":
                raise PermissionError("PRIVATE_ERROR_SENTINEL")
            return original(path, *args, **kwargs)
        with patch("mpkg_manager.file_accountability.os.open", denied):
            result = self.scan()
        self.assertEqual(result.scopes[0].state, "partial")
        self.assertEqual(self.reasons(result), {"directory_permission_denied"})

    def test_device_boundary_has_metadata_but_no_descendant_coverage(self):
        mounted = self.root / "mounted"
        mounted.mkdir()
        (mounted / "hidden").write_text("")
        original = os.stat
        def device(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == "mounted":
                values = {name: getattr(result, name) for name in
                          ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                           "st_size", "st_mtime_ns", "st_ctime_ns")}
                values["st_dev"] += 1
                return SimpleNamespace(**values)
            return result
        with patch("mpkg_manager.file_accountability.os.stat", device):
            result = self.scan()
        self.assertEqual(result.scopes[0].state, "partial")
        self.assertIn("mounted", self.entries(result))
        self.assertNotIn("mounted/hidden", self.entries(result))
        self.assertEqual(self.reasons(result), {"device_boundary"})
        self.assertIn("same_device_mount_aliases_may_be_traversed", result.limitations)

    def test_entry_directory_depth_and_path_budgets_report_gaps(self):
        child = self.root / "child"
        child.mkdir()
        (child / "nested").mkdir()
        (child / "nested" / "file").write_text("")
        (self.root / "file").write_text("")
        cases = [(ScanLimits(max_entries=1), "entry_limit"),
                 (ScanLimits(max_directories=1), "directory_limit"),
                 (ScanLimits(max_depth=1), "depth_limit"),
                 (ScanLimits(max_path_bytes=1), "path_bytes_limit")]
        for limits, reason in cases:
            with self.subTest(reason=reason):
                result = self.scan(limits=limits)
                self.assertEqual(result.scopes[0].state, "partial")
                self.assertIn(reason, self.reasons(result))
                self.assertNotIn("child/nested/file", self.entries(result))

    def test_nested_budget_stop_covers_unvisited_ancestor_siblings(self):
        nested = self.root / "a"
        nested.mkdir()
        (nested / "inside").write_text("")
        (self.root / "sibling").write_text("")
        original_scandir = os.scandir

        class Ordered:
            # Only this small fixture is sorted, to choose a deterministic
            # traversal order without relying on the filesystem's ordering.
            def __init__(self, fd):
                self.iterator = original_scandir(fd)
                self.items = iter(sorted(self.iterator, key=lambda item: item.name))

            def __next__(self):
                return next(self.items)

            def close(self):
                self.iterator.close()

        for limits, reason in ((ScanLimits(max_entries=2), "entry_limit"),
                               (ScanLimits(max_path_bytes=2), "path_bytes_limit")):
            with self.subTest(reason=reason), patch("mpkg_manager.file_accountability.os.scandir", Ordered):
                result = self.scan(limits=limits)
            self.assertEqual(result.scopes[0].state, "partial")
            self.assertEqual(set(self.entries(result)), {".", "a"})
            self.assertEqual([(gap.relative_path, gap.reason) for gap in result.scopes[0].gaps],
                             [(".", reason)])

    def test_nested_encoding_stop_covers_unvisited_ancestor_siblings(self):
        nested = self.root / "a"
        nested.mkdir()
        descriptor = os.open(os.fsencode(nested) + b"/bad-\xff", os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        (self.root / "sibling").write_text("")
        original_scandir = os.scandir

        class Ordered:
            def __init__(self, fd):
                self.iterator = original_scandir(fd)
                self.items = iter(sorted(self.iterator, key=lambda item: item.name))

            def __next__(self):
                return next(self.items)

            def close(self):
                self.iterator.close()

        with patch("mpkg_manager.file_accountability.os.scandir", Ordered):
            result = self.scan()
        self.assertEqual(set(self.entries(result)), {".", "a"})
        self.assertEqual([(gap.relative_path, gap.reason) for gap in result.scopes[0].gaps],
                         [(".", "path_encoding_unsupported")])

    def test_entry_budget_is_shared_across_scopes(self):
        other = self.outer / "other"
        other.mkdir()
        result = self.scan(scopes=[self.scope, ScanScope("other", str(other))],
                           limits=ScanLimits(max_entries=1))
        self.assertEqual(result.scopes[0].state, "complete")
        self.assertEqual(result.scopes[1].state, "unavailable")
        self.assertEqual(self.reasons(result, 1), {"entry_limit"})

    def test_directory_change_invalidates_whole_scope(self):
        (self.root / "item").write_text("")
        original = os.stat
        changed = False
        def racing(path, *args, **kwargs):
            nonlocal changed
            info = original(path, *args, **kwargs)
            if path == "item" and not changed:
                (self.root / "added").write_text("")
                changed = True
            return info
        with patch("mpkg_manager.file_accountability.os.stat", racing):
            result = self.scan()
        self.assertEqual(result.scopes[0].state, "unavailable")
        self.assertFalse(result.scopes[0].entries)
        self.assertEqual(self.reasons(result), {"path_changed"})

    def test_root_replacement_before_open_invalidates_classification(self):
        original_open = os.open
        for replacement in ("symlink", "file", "missing"):
            with self.subTest(replacement=replacement):
                def replaced(path, flags, *args, **kwargs):
                    if path == self.root.name and flags & os.O_DIRECTORY and not flags & os.O_PATH:
                        self.root.rmdir()
                        if replacement == "symlink":
                            self.root.symlink_to(self.outer / "unseen")
                        elif replacement == "file":
                            self.root.write_text("PRIVATE_CONTENT")
                    return original_open(path, flags, *args, **kwargs)
                try:
                    with patch("mpkg_manager.file_accountability.os.open", replaced):
                        result = self.scan()
                finally:
                    if self.root.is_symlink() or self.root.is_file():
                        self.root.unlink()
                    if not self.root.exists():
                        self.root.mkdir()
                self.assertEqual(result.scopes[0].state, "unavailable")
                self.assertFalse(result.scopes[0].entries)
                self.assertEqual(self.reasons(result), {"path_changed"})

    def test_root_open_permission_denial_stays_partial_without_replacement(self):
        original_open = os.open
        def denied(path, flags, *args, **kwargs):
            if path == self.root.name and flags & os.O_DIRECTORY and not flags & os.O_PATH:
                raise PermissionError("PRIVATE_ERROR_SENTINEL")
            return original_open(path, flags, *args, **kwargs)
        with patch("mpkg_manager.file_accountability.os.open", denied):
            result = self.scan()
        self.assertEqual(result.scopes[0].state, "partial")
        self.assertEqual(set(self.entries(result)), {"."})
        self.assertEqual(self.reasons(result), {"directory_permission_denied"})

    def test_root_replacement_invalidates_old_descriptor_results(self):
        (self.root / "item").write_text("")
        original = os.stat
        replaced = False
        def racing(path, *args, **kwargs):
            nonlocal replaced
            info = original(path, *args, **kwargs)
            if path == "item" and not replaced:
                self.root.rename(self.outer / "moved")
                self.root.mkdir()
                replaced = True
            return info
        with patch("mpkg_manager.file_accountability.os.stat", racing):
            result = self.scan()
        self.assertEqual(result.scopes[0].state, "unavailable")
        self.assertFalse(result.scopes[0].entries)

    def test_cancellation_closes_all_owned_descriptors(self):
        (self.root / "item").write_text("")
        original_open, original_stat = os.open, os.stat
        descriptors = []
        def opened(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            descriptors.append(fd)
            return fd
        def cancel(path, *args, **kwargs):
            if path == "item":
                raise KeyboardInterrupt
            return original_stat(path, *args, **kwargs)
        with patch("mpkg_manager.file_accountability.os.open", opened), \
             patch("mpkg_manager.file_accountability.os.stat", cancel), \
             self.assertRaises(KeyboardInterrupt):
            self.scan()
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_public_summary_and_repr_omit_private_paths_names_and_contents(self):
        (self.root / "PRIVATE_NAME_SENTINEL").write_text("PRIVATE_CONTENT_SENTINEL")
        result = self.scan()
        public = json.dumps(result.summary()) + repr(result) + repr(result.scopes[0])
        public += repr(result.scopes[0].entries)
        for value in (str(self.root), "PRIVATE_SCOPE_SENTINEL", "PRIVATE_NAME_SENTINEL", "PRIVATE_CONTENT_SENTINEL"):
            self.assertNotIn(value, public)
        first = result.summary()
        first["scopes"][0]["classifications"].clear()
        self.assertTrue(result.summary()["scopes"][0]["classifications"])
        with self.assertRaises(FrozenInstanceError):
            result.scopes[0].entries[0].kind = "file"
        self.assertEqual(result.observed_at, WHEN)
        self.assertEqual(result.host_id, HOST)

    def test_invalid_inputs_are_rejected_before_any_io(self):
        declaration = self.declaration()
        invalid_calls = [dict(scopes=[]), dict(scopes=[self.scope, {}]),
                         dict(scopes=[self.scope, self.scope]),
                         dict(scopes=[self.scope, ScanScope("nested", str(self.root / "child"))]),
                         dict(scopes=[self.scope], limits={}),
                         dict(scopes=[self.scope], host_id="invalid")]
        with patch("os.open", side_effect=AssertionError("No I/O before validation")):
            for options in invalid_calls:
                with self.subTest(options=options), self.assertRaises(ValueError):
                    self.scan(declaration, **options)
            with self.assertRaisesRegex(ValueError, "invalid_file_accountability_request"):
                self.scan(replace(declaration, canonical_bytes=b"{}"))
        for root in ("relative", "//root", "/tmp/../secret", "/tmp/", "/tmp/\udcff"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                ScanScope("fixture", root)
        for limit in (0, True, 4097):
            with self.assertRaises(ValueError):
                ScanLimits(max_entries=limit)

    def test_unsupported_patterns_are_rejected_before_any_io(self):
        patterns = ("a//b", "./x", "prefix**", "unterminated[", "[]", "[!]", "a\\b")
        with patch("os.open", side_effect=AssertionError("No I/O before validation")):
            for pattern in patterns:
                with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, "invalid_file_accountability_request"):
                    self.scan(self.declaration(rules=[self.rule(patterns=[pattern])]))

    def test_undecodable_names_leave_scope_incomplete(self):
        fd = os.open(os.fsencode(self.root) + b"/bad-\xff", os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        result = self.scan()
        self.assertEqual(result.scopes[0].state, "partial")
        self.assertEqual(self.reasons(result), {"path_encoding_unsupported"})


if __name__ == "__main__":
    unittest.main()
