"""Bounded policy/capture fixtures only; no production paths or host effects."""
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.host_policy import (MAX_POLICY_BYTES, HostPolicy, LoadedHostPolicy, PolicyError,
                                      load_host_policy, parse_host_policy)
from mpkg_manager.protected_capture import CaptureError, capture_protected
from mpkg_manager.store import HostStore, MAX_INPUT_BYTES


HOST = "12345678-1234-4234-8234-123456789abc"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


class ProtectedCaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "nested").mkdir()
        self.source = self.inputs / "nested" / "private.env"
        self.raw = b"PRIVATE_CAPTURE_SENTINEL=value\n"
        self.source.write_bytes(self.raw)
        self.policy_directory = self.root / "policy"
        self.policy_directory.mkdir(mode=0o700)
        self.policy_path = self.policy_directory / "host-policy.toml"
        self.policy_raw = (f'schema=1\nhost_id="{HOST}"\nengine_aliases={{local="engine-id"}}\n'
                           f'allowed_input_roots={json.dumps([str(self.inputs)])}\n').encode()
        self.policy_path.write_bytes(self.policy_raw)
        self.policy_path.chmod(0o600)

    def load(self):
        loaded = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(loaded.close)
        return loaded

    def capture(self, policy=None, **kwargs):
        return capture_protected(self.load() if policy is None else policy,
                                 **({"root": str(self.inputs), "relative_path": "nested/private.env",
                                     "name": "private-config", "purpose": "fixture configuration"} | kwargs))

    def assert_error(self, kind, code, callback):
        with self.assertRaises(kind) as error:
            callback()
        self.assertEqual(error.exception.code, code)
        self.assertEqual(str(error.exception), code)
        self.assertNotIn("PRIVATE", repr(error.exception))
        return error.exception

    def descriptors(self):
        return set(os.listdir("/proc/self/fd"))

    def mutate_after_read(self, action, callback):
        real_read = os.read
        changed = False
        def read(descriptor, maximum):
            nonlocal changed
            data = real_read(descriptor, maximum)
            if not changed:
                changed = True
                action()
            return data
        with patch("mpkg_manager.protected_capture.os.read", read):
            return callback()

    def test_policy_values_are_immutable_and_parsing_is_not_read_authority(self):
        parsed = parse_host_policy(self.policy_raw)
        self.assertIsInstance(parsed, HostPolicy)
        self.assertEqual(parsed.host_id, HOST)
        self.assertEqual(parsed.allowed_input_roots, (str(self.inputs),))
        aliases = parsed.engine_aliases
        aliases["local"] = "changed"
        self.assertEqual(parsed.engine_aliases, {"local": "engine-id"})
        with self.assertRaises(FrozenInstanceError):
            parsed.host_id = "changed"
        self.assertNotIn(str(self.inputs), repr(parsed))
        self.assert_error(CaptureError, "policy_unavailable", lambda: self.capture(parsed))
        self.assert_error(CaptureError, "policy_unavailable", lambda: self.capture(LoadedHostPolicy()))

    def test_policy_schema_rejects_unknown_unbounded_and_untyped_input(self):
        invalid = [self.policy_raw + b'tools={reader="/arbitrary"}\n',
                   self.policy_raw + b'environment={PRIVATE="value"}\n',
                   self.policy_raw.replace(b'"engine-id"', b'1'),
                   self.policy_raw.replace(HOST.encode(), b'PRIVATE-HOST'),
                   self.policy_raw.replace(json.dumps([str(self.inputs)]).encode(), b'["/"]'),
                   self.policy_raw.replace(json.dumps([str(self.inputs)]).encode(), b'["/tmp/../private"]'),
                   self.policy_raw.replace(json.dumps([str(self.inputs)]).encode(), b'[]'),
                   self.policy_raw.replace(b'schema=1', b'schema=' + b'9' * 6000),
                   b'PRIVATE="unterminated', b'\xff', b'x' * (MAX_POLICY_BYTES + 1), "PRIVATE"]
        for raw in invalid:
            with self.subTest(raw_type=type(raw).__name__):
                self.assert_error(PolicyError, "invalid_policy", lambda: parse_host_policy(raw))
        for schema in (b"2", b"true", b"1.0"):
            self.assert_error(PolicyError, "policy_schema_unsupported", lambda: parse_host_policy(
                self.policy_raw.replace(b"schema=1", b"schema=" + schema)))

    def test_loader_default_owner_and_invalid_paths_are_fixed_errors(self):
        with patch("mpkg_manager.host_policy.os.geteuid", return_value=12345):
            self.assert_error(PolicyError, "policy_owner_required", load_host_policy)
        for path in ("relative", "/", "/tmp/../private", "/tmp/private\0", "/tmp/\ud800", b"PRIVATE"):
            self.assert_error(PolicyError, "invalid_policy_path", lambda: load_host_policy(
                path=path, owner_uid=os.geteuid()))
        self.assert_error(PolicyError, "policy_unavailable", lambda: load_host_policy(
            path=self.policy_directory / "missing", owner_uid=os.geteuid()))

    def test_policy_private_modes_and_unsafe_ancestors_are_enforced(self):
        self.policy_path.chmod(0o644)
        self.assert_error(PolicyError, "policy_permissions", self.load)
        self.policy_path.chmod(0o600)
        self.policy_directory.chmod(0o755)
        self.assert_error(PolicyError, "policy_permissions", self.load)
        self.policy_directory.chmod(0o700)
        self.root.chmod(0o777)
        self.assert_error(PolicyError, "unsafe_policy_ancestor", self.load)
        self.root.chmod(0o700)

    def test_policy_wrong_owner_and_oversize_file_are_refused_before_read(self):
        real_stat = os.stat
        def wrong_owner(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path == "host-policy.toml":
                return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1,
                                       st_nlink=info.st_nlink, st_size=info.st_size)
            return info
        with patch("mpkg_manager.host_policy.os.stat", wrong_owner):
            self.assert_error(PolicyError, "policy_permissions", self.load)
        with self.policy_path.open("wb") as output:
            output.truncate(MAX_POLICY_BYTES + 1)
        with patch("mpkg_manager.host_policy.os.read", side_effect=AssertionError("must not read")):
            self.assert_error(PolicyError, "invalid_policy", self.load)

    def test_policy_change_during_loading_is_refused_and_closes_descriptors(self):
        before = self.descriptors()
        self.mutate_after_read(lambda: self.policy_path.write_bytes(self.policy_raw + b"# changed"),
                               lambda: self.assert_error(PolicyError, "policy_changed", self.load))
        self.assertEqual(self.descriptors(), before)

    def test_policy_symlinks_hardlinks_and_special_files_are_refused(self):
        actual = self.policy_path.with_name("actual")
        self.policy_path.rename(actual)
        self.policy_path.symlink_to(actual)
        self.assert_error(PolicyError, "policy_permissions", self.load)
        self.policy_path.unlink()
        os.link(actual, self.policy_path)
        self.assert_error(PolicyError, "policy_permissions", self.load)
        self.policy_path.unlink()
        os.mkfifo(self.policy_path, 0o600)
        self.assert_error(PolicyError, "policy_permissions", self.load)
        self.policy_path.unlink()
        actual.rename(self.policy_path)
        link = self.root / "policy-link"
        link.symlink_to(self.policy_directory, target_is_directory=True)
        self.assert_error(PolicyError, "policy_unavailable", lambda: load_host_policy(
            path=link / "host-policy.toml", owner_uid=os.geteuid()))

    def test_loaded_policy_changes_and_closed_handles_block_capture(self):
        loaded = self.load()
        self.policy_path.write_bytes(self.policy_raw + b"# changed\n")
        self.assert_error(CaptureError, "policy_unavailable", lambda: self.capture(loaded))
        loaded.close()
        self.assert_error(CaptureError, "policy_unavailable", lambda: self.capture(loaded))
        self.assert_error(PolicyError, "policy_closed", lambda: loaded.policy)

    def test_policy_file_and_parent_replacement_are_detected(self):
        loaded = self.load()
        self.policy_path.rename(self.policy_path.with_name("old"))
        self.policy_path.write_bytes(self.policy_raw)
        self.policy_path.chmod(0o600)
        self.assert_error(CaptureError, "policy_unavailable", lambda: self.capture(loaded))
        loaded = self.load()
        self.policy_directory.rename(self.root / "old-policy")
        self.policy_directory.mkdir(mode=0o700)
        self.policy_path.write_bytes(self.policy_raw)
        self.policy_path.chmod(0o600)
        self.assert_error(CaptureError, "policy_unavailable", lambda: self.capture(loaded))

    def test_capture_returns_exact_store_identity_without_exposing_content_in_repr(self):
        loaded = self.load()
        captured = self.capture(loaded)
        info = self.source.stat()
        self.assertEqual(captured.raw, self.raw)
        self.assertEqual(captured.source_identity, {
            "path": str(self.source), "device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns, "uid": info.st_uid,
            "gid": info.st_gid, "mode": info.st_mode, "links": 1})
        for value in (self.raw.decode(), str(self.source), "fixture configuration"):
            self.assertNotIn(value, repr(captured))
        self.assertNotIn(str(self.policy_path), repr(loaded))

    def test_capture_rejects_unapproved_roots_and_relative_path_escape(self):
        loaded = self.load()
        for relative in ("../outside", "nested/../private.env", "/etc/shadow", "./private", "", "nested//private", "private\0", "\ud800"):
            self.assert_error(CaptureError, "invalid_capture_request", lambda: self.capture(
                loaded, relative_path=relative))
        self.assert_error(CaptureError, "input_root_not_allowed", lambda: self.capture(loaded, root=str(self.root)))
        for name, purpose in (("invalid name", "fixture"), ("valid", ""), ("valid", "\ud800")):
            self.assert_error(CaptureError, "invalid_capture_request", lambda: self.capture(
                loaded, name=name, purpose=purpose))

    def test_capture_refuses_symlinks_hardlinks_directories_and_fifos(self):
        loaded = self.load()
        (self.inputs / "link").symlink_to(self.source)
        self.assert_error(CaptureError, "input_not_regular", lambda: self.capture(loaded, relative_path="link"))
        (self.inputs / "directory-link").symlink_to(self.source.parent, target_is_directory=True)
        self.assert_error(CaptureError, "input_unavailable", lambda: self.capture(
            loaded, relative_path="directory-link/private.env"))
        hardlink = self.inputs / "hardlink"
        os.link(self.source, hardlink)
        self.assert_error(CaptureError, "input_hardlinked", lambda: self.capture(loaded))
        hardlink.unlink()
        self.assert_error(CaptureError, "input_not_regular", lambda: self.capture(loaded, relative_path="nested"))
        os.mkfifo(self.inputs / "fifo", 0o600)
        self.assert_error(CaptureError, "input_not_regular", lambda: self.capture(loaded, relative_path="fifo"))

    def test_final_open_uses_nonblocking_and_nofollow_flags(self):
        loaded = self.load()
        real_open = os.open
        flags = []
        def record(path, options, *args, **kwargs):
            if path == "private.env":
                flags.append(options)
            return real_open(path, options, *args, **kwargs)
        with patch("mpkg_manager.protected_capture.os.open", record):
            self.capture(loaded)
        self.assertEqual(len(flags), 1)
        self.assertTrue(flags[0] & os.O_NONBLOCK)
        self.assertTrue(flags[0] & os.O_NOFOLLOW)

    def test_fifo_substitution_between_stat_and_open_does_not_block(self):
        loaded = self.load()
        real_open = os.open
        def replace(path, options, *args, **kwargs):
            if path == "private.env":
                self.source.unlink()
                os.mkfifo(self.source, 0o600)
            return real_open(path, options, *args, **kwargs)
        with patch("mpkg_manager.protected_capture.os.open", replace):
            self.assert_error(CaptureError, "input_not_regular", lambda: self.capture(loaded))

    def test_byte_limit_applies_before_and_during_read(self):
        loaded = self.load()
        with self.source.open("wb") as output:
            output.truncate(MAX_INPUT_BYTES + 1)
        with patch("mpkg_manager.protected_capture.os.read", side_effect=AssertionError("must not read")):
            self.assert_error(CaptureError, "input_too_large", lambda: self.capture(loaded))
        self.source.write_bytes(b"x")
        def grow():
            with self.source.open("ab") as output:
                output.write(b"x" * MAX_INPUT_BYTES)
        self.mutate_after_read(grow, lambda: self.assert_error(CaptureError, "input_too_large", lambda: self.capture(loaded)))

    def test_exact_byte_limit_is_accepted(self):
        loaded = self.load()
        with self.source.open("wb") as output:
            output.truncate(MAX_INPUT_BYTES)
        result = self.capture(loaded)
        self.assertEqual(len(result.raw), MAX_INPUT_BYTES)
        self.assertEqual(result.source_identity["size"], MAX_INPUT_BYTES)

    def test_same_size_write_with_restored_mtime_is_detected_by_ctime(self):
        loaded = self.load()
        original = self.source.stat()
        def rewrite():
            self.source.write_bytes(b"X" * len(self.raw))
            os.utime(self.source, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.mutate_after_read(rewrite, lambda: self.assert_error(CaptureError, "input_changed", lambda: self.capture(loaded)))

    def test_pre_epoch_source_time_is_refused_instead_of_returning_unrecordable_input(self):
        loaded = self.load()
        os.utime(self.source, ns=(-1_000_000_000, -1_000_000_000))
        self.assertEqual(self.source.stat().st_mtime_ns, -1_000_000_000)
        self.assert_error(CaptureError, "input_metadata_unsupported", lambda: self.capture(loaded))

    def test_persisted_metadata_matches_store_integer_bounds_without_clamping(self):
        loaded = self.load()
        real_stat = os.stat
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_uid", "st_gid", "st_mode", "st_nlink")
        original = self.source.stat()
        cases = [(field, invalid, "input_metadata_unsupported")
                 for field in ("st_ino", "st_mtime_ns", "st_uid", "st_gid")
                 for invalid in (-1, 2**63, True)]
        cases += [("st_dev", 2**63, "input_device_changed"),
                  ("st_size", -1, "input_metadata_unsupported"),
                  ("st_size", True, "input_metadata_unsupported"),
                  ("st_size", 2**63, "input_too_large"),
                  ("st_mode", original.st_mode | 2**63, "input_metadata_unsupported"),
                  ("st_nlink", True, "input_metadata_unsupported"),
                  ("st_nlink", 2**63, "input_hardlinked")]
        for field, invalid, code in cases:
            with self.subTest(field=field, invalid=invalid):
                def unsupported(path, *args, **kwargs):
                    info = real_stat(path, *args, **kwargs)
                    if path == "private.env":
                        values = {name: getattr(info, name) for name in fields}
                        values[field] = invalid
                        return SimpleNamespace(**values)
                    return info
                with patch("mpkg_manager.protected_capture.os.stat", unsupported):
                    self.assert_error(CaptureError, code, lambda: self.capture(loaded))
        self.assertEqual(self.source.stat().st_mtime_ns, original.st_mtime_ns)
        with HostStore.create(self.root / "store-boundary", HOST, owner_uid=os.geteuid()) as store:
            captured = self.capture(loaded)
            store.record_intent(EMPTY, 0, protected_inputs=[captured])
            self.assertEqual(store.compare_protected(1, captured.name, captured.raw, captured.source_identity), "same")

    def test_leaf_replacement_during_read_is_detected(self):
        loaded = self.load()
        def replace():
            self.source.rename(self.source.with_name("previous"))
            self.source.write_bytes(self.raw)
        self.mutate_after_read(replace, lambda: self.assert_error(CaptureError, "input_changed", lambda: self.capture(loaded)))

    def test_held_parent_and_allowed_root_replacement_are_detected(self):
        for root_replaced in (False, True):
            with self.subTest(root_replaced=root_replaced):
                loaded = self.load()
                directory = self.inputs if root_replaced else self.source.parent
                old = directory.with_name(directory.name + "-old")
                def replace():
                    directory.rename(old)
                    directory.mkdir()
                self.mutate_after_read(replace, lambda: self.assert_error(
                    CaptureError, "input_path_changed", lambda: self.capture(loaded)))
                directory.rmdir()
                old.rename(directory)

    def test_changed_policy_during_capture_rejects_captured_bytes(self):
        loaded = self.load()
        self.mutate_after_read(lambda: self.policy_path.write_bytes(self.policy_raw + b"# change"),
                               lambda: self.assert_error(CaptureError, "policy_unavailable", lambda: self.capture(loaded)))

    def test_cross_device_leaf_is_refused_with_safe_stat_injection(self):
        loaded = self.load()
        real_stat = os.stat
        def changed(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path == "private.env":
                return SimpleNamespace(st_dev=info.st_dev + 1, st_mode=info.st_mode,
                                       st_nlink=info.st_nlink, st_size=info.st_size)
            return info
        with patch("mpkg_manager.protected_capture.os.stat", changed):
            self.assert_error(CaptureError, "input_device_changed", lambda: self.capture(loaded))

    def test_cross_device_descendant_directory_is_refused_with_safe_injection(self):
        loaded = self.load()
        real_fstat = os.fstat
        inode = self.source.parent.stat().st_ino
        def changed(descriptor):
            info = real_fstat(descriptor)
            if stat.S_ISDIR(info.st_mode) and info.st_ino == inode:
                return SimpleNamespace(st_dev=info.st_dev + 1, st_mode=info.st_mode)
            return info
        with patch("mpkg_manager.protected_capture.os.fstat", changed):
            self.assert_error(CaptureError, "input_device_changed", lambda: self.capture(loaded))

    def test_capture_read_failure_and_cancellation_close_every_owned_descriptor(self):
        loaded = self.load()
        before = self.descriptors()
        with patch("mpkg_manager.protected_capture.os.read", side_effect=OSError("PRIVATE_READ_ERROR")):
            self.assert_error(CaptureError, "input_unavailable", lambda: self.capture(loaded))
        self.assertEqual(self.descriptors(), before)
        for interruption in (KeyboardInterrupt("fixture"), SystemExit("fixture")):
            with patch("mpkg_manager.protected_capture.os.read", side_effect=interruption):
                with self.assertRaises(type(interruption)) as error:
                    self.capture(loaded)
                self.assertIs(error.exception, interruption)
            self.assertEqual(self.descriptors(), before)
        self.assertEqual(self.capture(loaded).raw, self.raw)

    def test_policy_read_cancellation_closes_every_owned_descriptor(self):
        before = self.descriptors()
        interruption = KeyboardInterrupt("fixture")
        with patch("mpkg_manager.host_policy.os.read", side_effect=interruption):
            with self.assertRaises(KeyboardInterrupt) as error:
                self.load()
            self.assertIs(error.exception, interruption)
        self.assertEqual(self.descriptors(), before)

    def test_capture_integrates_with_private_store_freshness_and_sanitized_history(self):
        loaded = self.load()
        captured = self.capture(loaded)
        with HostStore.create(self.root / "store", HOST, engine_aliases=loaded.policy.engine_aliases,
                              owner_uid=os.geteuid()) as store:
            store.record_intent(EMPTY, 0, protected_inputs=[captured])
            same = self.capture(loaded)
            self.assertEqual(store.compare_protected(1, same.name, same.raw, same.source_identity), "same")
            self.source.write_bytes(b"changed-private-data")
            changed = self.capture(loaded)
            self.assertEqual(store.compare_protected(1, changed.name, changed.raw, changed.source_identity), "changed")
            self.assertEqual(store.compare_protected(1, changed.name, None, None), "unavailable")
            self.source.unlink()
            self.assert_error(CaptureError, "input_unavailable", lambda: self.capture(loaded))
            public = json.dumps({"current": store.current(), "history": store.history()})
            self.assertNotIn(self.raw.decode(), public)
            self.assertNotIn(str(self.source), public)
            reference, token = store._db.execute("SELECT id,token FROM protected_inputs").fetchone()
            self.assertNotIn(reference, public)
            self.assertNotIn(token.hex(), public)


if __name__ == "__main__":
    unittest.main()
