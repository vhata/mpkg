"""Owned configuration files and injected races; no host lifecycle operations."""
from dataclasses import FrozenInstanceError, replace
import errno
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import file_publication as publication
from mpkg_manager.host_policy import load_host_policy


SECRET = b"PRIVATE_CONFIGURATION_SENTINEL"
ORIGINAL = b"port=1234\nsecret=" + SECRET + b"\n"
CANDIDATE = ORIGINAL.replace(b"1234", b"4321")


class FilePublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "inputs"
        self.parent = self.root / "application"
        self.parent.mkdir(parents=True, mode=0o750)
        self.target = self.parent / "config"
        self.target.write_bytes(ORIGINAL)
        self.target.chmod(0o640)
        self.policy_path = self.base / "policy.toml"
        self.host = str(uuid.uuid4())
        self.policy_path.write_text(f'schema=1\nhost_id="{self.host}"\nengine_aliases={{}}\n'
                                    f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.calls = 0

    def capture(self):
        return publication.capture_publication_input(
            self.policy, root=str(self.root), relative_path="application/config")

    def binding(self, candidate=CANDIDATE):
        return publication.bind_publication(self.capture(), candidate,
            adapter="fixture_configuration_v1", input_reference=str(uuid.uuid4()))

    def ready(self, binding):
        self.calls += 1
        return publication.PublicationReadiness(binding.publication_id, True, True, True, True)

    def publish(self, binding=None, callback=None):
        return publication.publish_file(self.policy, binding or self.binding(),
                                        revalidate=callback or self.ready)

    def error(self, code, callback, *, outcome="not_published", cleanup=True):
        with self.assertRaises(publication.PublicationError) as caught:
            callback()
        value = caught.exception
        self.assertEqual(value.code, code)
        self.assertEqual(value.outcome, outcome)
        self.assertEqual(value.cleanup_complete, cleanup)
        self.assertEqual(str(value), code)
        self.assertNotIn(SECRET.decode(), json.dumps(value.as_dict()))
        self.assertNotIn(str(self.base), json.dumps(value.as_dict()))
        self.assertFalse(value.as_dict()["retry_authorized"])
        return value

    def temps(self):
        return list(self.parent.glob(".mpkg-publication-*"))

    def test_publishes_whole_candidate_and_preserves_supported_metadata(self):
        before = self.target.stat()
        binding = self.binding()
        result = self.publish(binding)
        after = self.target.stat()
        self.assertEqual(result.outcome, "published")
        self.assertEqual(self.target.read_bytes(), CANDIDATE)
        self.assertNotEqual(before.st_ino, after.st_ino)
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                         (before.st_uid, before.st_gid, 0o640))
        self.assertEqual(after.st_nlink, 1)
        self.assertEqual(self.calls, 4)
        self.assertEqual(self.temps(), [])
        self.assertEqual(result.as_dict(), {"publication_id": binding.publication_id,
            "outcome": "published", "application_verified": False, "apply_authorized": False})

    def test_capture_and_binding_are_private_immutable_values(self):
        binding = self.binding()
        self.assertEqual(binding.original.raw, ORIGINAL)
        self.assertEqual(binding.candidate, CANDIDATE)
        for private in (SECRET.decode(), str(self.target), binding.input_reference):
            self.assertNotIn(private, repr(binding) + repr(binding.original))
        with self.assertRaises(FrozenInstanceError):
            binding.candidate = b"changed"
        with self.assertRaises(FrozenInstanceError):
            binding.original.raw = b"changed"

    def test_capture_cleanup_failure_never_reports_completed_cleanup(self):
        original_close = publication._HeldPath.close

        def incomplete(path):
            original_close(path)
            return False

        with patch.object(publication._HeldPath, "close", incomplete):
            self.error("publication_cleanup_failed", self.capture, cleanup=False)

    def test_leaf_descriptor_close_failure_remains_visible_during_capture_and_publish(self):
        binding = self.binding()
        real_open, real_close = os.open, os.close
        for operation in (self.capture, lambda: self.publish(binding)):
            with self.subTest(operation=operation):
                target_fd, raised = None, False

                def opened(path, flags, *args, **kwargs):
                    nonlocal target_fd
                    fd = real_open(path, flags, *args, **kwargs)
                    if path == "config" and target_fd is None:
                        target_fd = fd
                    return fd

                def closed(fd):
                    nonlocal raised
                    real_close(fd)
                    if fd == target_fd and not raised:
                        raised = True
                        raise OSError("private target-close failure")

                with patch.object(publication.os, "open", side_effect=opened), \
                        patch.object(publication.os, "close", side_effect=closed):
                    self.error("publication_cleanup_failed", operation, cleanup=False)
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_unchanged_bytes_only_revalidate_without_temporary_file_or_rename(self):
        binding = self.binding(ORIGINAL)
        before = self.target.stat()
        with patch.object(publication.os, "replace", side_effect=AssertionError("rename")), \
                patch.object(publication.os, "write", side_effect=AssertionError("write")), \
                patch.object(publication.os, "fsync", side_effect=AssertionError("sync")):
            result = self.publish(binding)
        self.assertEqual(result.outcome, "unchanged")
        self.assertEqual(self.target.stat().st_ino, before.st_ino)
        self.assertEqual(self.calls, 2)
        self.assertEqual(self.temps(), [])

    def test_content_sync_precedes_rename_and_directory_sync_follows_it(self):
        binding = self.binding()
        events = []
        fsync, rename = os.fsync, os.replace

        def sync(fd):
            events.append("directory_sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file_sync")
            return fsync(fd)

        def publish(*args, **kwargs):
            events.append("rename")
            self.assertEqual(kwargs["src_dir_fd"], kwargs["dst_dir_fd"])
            self.assertEqual(args[1], "config")
            self.assertNotIn("/", args[0])
            return rename(*args, **kwargs)

        with patch.object(publication.os, "fsync", side_effect=sync), \
                patch.object(publication.os, "replace", side_effect=publish):
            self.publish(binding)
        self.assertEqual(events, ["file_sync", "rename", "directory_sync"])

    def test_short_writes_are_completed_without_truncating_the_candidate(self):
        binding = self.binding()
        original_write = os.write
        with patch.object(publication.os, "write", side_effect=lambda fd, raw: original_write(fd, raw[:3])):
            self.publish(binding)
        self.assertEqual(self.target.read_bytes(), CANDIDATE)

    def test_required_authority_input_and_writer_evidence_are_not_booleans(self):
        binding = self.binding()
        for returned in (True, None, {}, publication.PublicationReadiness(
                str(uuid.uuid4()), True, True, True, True)):
            with self.subTest(returned=returned):
                self.error("publication_authority_or_exclusion_unavailable",
                           lambda: self.publish(binding, lambda _: returned))
        for field in ("authority_current", "input_current", "identified_writers_stopped",
                      "maintenance_interval_active"):
            with self.subTest(field=field):
                evidence = replace(self.ready(binding), **{field: False})
                self.error("publication_authority_or_exclusion_unavailable",
                           lambda: self.publish(binding, lambda _: evidence))
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.temps(), [])

    def test_revalidation_refusal_at_every_boundary_preserves_actual_outcome(self):
        for reject_at in range(1, 5):
            with self.subTest(reject_at=reject_at):
                self.target.write_bytes(ORIGINAL)
                binding = self.binding()
                self.calls = 0

                def guard(value):
                    answer = self.ready(value)
                    return replace(answer, maintenance_interval_active=self.calls != reject_at)

                self.error("publication_authority_or_exclusion_unavailable",
                           lambda: self.publish(binding, guard),
                           outcome="unknown" if reject_at == 4 else "not_published")
                self.assertEqual(self.target.read_bytes(), CANDIDATE if reject_at == 4 else ORIGINAL)
                self.assertEqual(self.temps(), [])

    def test_revalidation_exception_is_private_at_every_boundary(self):
        for reject_at in range(1, 5):
            with self.subTest(reject_at=reject_at):
                self.target.write_bytes(ORIGINAL)
                binding = self.binding()
                self.calls = 0

                def guard(value):
                    answer = self.ready(value)
                    if self.calls == reject_at:
                        raise RuntimeError(SECRET.decode())
                    return answer

                self.error("publication_operation_failed", lambda: self.publish(binding, guard),
                           outcome="unknown" if reject_at == 4 else "not_published")

    def test_changed_original_bytes_and_identity_do_not_gain_authority(self):
        binding = self.binding()
        self.target.write_bytes(b"external edit")
        self.error("publication_input_changed", lambda: self.publish(binding))
        self.assertEqual(self.target.read_bytes(), b"external edit")
        self.target.unlink()
        self.target.write_bytes(ORIGINAL)
        self.target.chmod(0o640)
        self.error("publication_input_changed", lambda: self.publish(binding))
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_content_replacement_and_metadata_races_before_rename_are_refused(self):
        changes = (lambda: self.target.write_bytes(b"manual edit"),
                   lambda: self.target.chmod(0o600),
                   lambda: (self.target.unlink(), self.target.write_bytes(ORIGINAL)))
        for change in changes:
            with self.subTest(change=change):
                self.target.write_bytes(ORIGINAL)
                self.target.chmod(0o640)
                binding = self.binding()
                self.calls = 0

                def guard(value):
                    result = self.ready(value)
                    if self.calls == 3:
                        change()
                    return result

                self.error("publication_input_changed", lambda: self.publish(binding, guard))
                self.assertNotEqual(self.target.read_bytes(), CANDIDATE)
                self.assertEqual(self.temps(), [])

    def test_symlink_leaf_race_cannot_redirect_candidate_writes(self):
        binding = self.binding()
        other = self.base / "unrelated"
        other.write_bytes(b"unrelated")

        def guard(value):
            result = self.ready(value)
            if self.calls == 3:
                self.target.unlink()
                self.target.symlink_to(other)
            return result

        self.error("publication_operation_failed", lambda: self.publish(binding, guard))
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(other.read_bytes(), b"unrelated")
        self.assertEqual(self.temps(), [])

    def test_held_parent_replacement_is_detected_without_writing_new_parent(self):
        binding = self.binding()
        moved = self.root / "moved"

        def guard(value):
            result = self.ready(value)
            if self.calls == 3:
                self.parent.rename(moved)
                self.parent.mkdir(mode=0o750)
                self.target.write_bytes(b"replacement directory")
            return result

        self.error("publication_path_changed", lambda: self.publish(binding, guard))
        self.assertEqual(self.target.read_bytes(), b"replacement directory")
        self.assertEqual((moved / "config").read_bytes(), ORIGINAL)
        self.assertEqual(list(moved.glob(".mpkg-publication-*")), [])

    def test_ancestor_permission_change_invalidates_held_path(self):
        binding = self.binding()

        def guard(value):
            result = self.ready(value)
            if self.calls == 3:
                self.parent.chmod(0o700)
            return result

        self.error("publication_path_changed", lambda: self.publish(binding, guard))
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_same_device_target_mount_surprise_is_rejected(self):
        binding = self.binding()
        mount_id = publication._mount_id
        target_inode = self.target.stat().st_ino

        def mounted(fd):
            value = mount_id(fd)
            return value + 1 if self.calls >= 3 and os.fstat(fd).st_ino == target_inode else value

        with patch.object(publication, "_mount_id", side_effect=mounted):
            self.error("publication_mount_unsupported", lambda: self.publish(binding))
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_same_device_ancestor_mount_surprise_is_rejected(self):
        binding = self.binding()
        mount_id = publication._mount_id
        parent_inode = self.parent.stat().st_ino

        def mounted(fd):
            value = mount_id(fd)
            return value + 1 if self.calls >= 3 and os.fstat(fd).st_ino == parent_inode else value

        with patch.object(publication, "_mount_id", side_effect=mounted):
            self.error("publication_path_changed", lambda: self.publish(binding))
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_new_capture_refuses_nested_mount_even_on_same_device(self):
        original_mount = publication._mount_id
        parent_inode = self.parent.stat().st_ino
        with patch.object(publication, "_mount_id", side_effect=lambda fd:
                          original_mount(fd) + (1 if os.fstat(fd).st_ino == parent_inode else 0)):
            self.error("publication_mount_unsupported", self.capture)

    def test_mount_identity_unavailable_fails_closed(self):
        with patch.object(publication, "_mount_id", side_effect=OSError("private mount error")):
            self.error("publication_input_unavailable", self.capture)

    def test_hardlink_and_special_file_targets_are_refused(self):
        os.link(self.target, self.parent / "alias")
        self.error("publication_alias_or_type_unsupported", self.capture)
        (self.parent / "alias").unlink()
        self.target.unlink()
        os.mkfifo(self.target, 0o600)
        self.error("publication_alias_or_type_unsupported", self.capture)

    def test_hardlink_added_after_preparation_is_refused(self):
        binding = self.binding()

        def guard(value):
            result = self.ready(value)
            if self.calls == 3:
                os.link(self.target, self.parent / "alias")
            return result

        self.error("publication_alias_or_type_unsupported", lambda: self.publish(binding, guard))
        self.assertEqual((self.parent / "alias").read_bytes(), ORIGINAL)

    def test_acl_and_xattr_preservation_are_explicitly_unsupported(self):
        for attribute in ("system.posix_acl_access", "user.fixture"):
            with self.subTest(attribute=attribute), \
                    patch.object(publication.os, "listxattr", return_value=[attribute]):
                self.error("publication_access_metadata_unsupported", self.capture)

    def test_inherited_temporary_acl_is_refused_and_owned_temp_is_removed(self):
        binding = self.binding()
        original_inode = self.target.stat().st_ino
        with patch.object(publication.os, "listxattr", side_effect=lambda fd:
                          [] if os.fstat(fd).st_ino == original_inode else ["system.posix_acl_access"]):
            self.error("publication_access_metadata_unsupported", lambda: self.publish(binding))
        self.assertEqual(self.temps(), [])
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_setid_metadata_and_oversized_content_are_refused(self):
        self.target.chmod(0o4640)
        self.error("publication_metadata_unsupported", self.capture)
        self.target.chmod(0o640)
        with patch.object(publication, "MAX_BYTES", 4):
            self.error("publication_metadata_unsupported", self.capture)

    def test_file_sync_failure_leaves_original_and_cleans_candidate(self):
        binding = self.binding()
        real_sync = os.fsync

        def fail_file(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, SECRET.decode())
            real_sync(fd)

        with patch.object(publication.os, "fsync", side_effect=fail_file):
            self.error("publication_operation_failed", lambda: self.publish(binding))
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.temps(), [])

    def test_directory_sync_failure_after_rename_preserves_unknown_publication(self):
        binding = self.binding()
        real_sync = os.fsync

        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, SECRET.decode())
            real_sync(fd)

        with patch.object(publication.os, "fsync", side_effect=fail_directory):
            self.error("publication_operation_failed", lambda: self.publish(binding), outcome="unknown")
        self.assertEqual(self.target.read_bytes(), CANDIDATE)
        self.assertEqual(self.temps(), [])

    def test_rename_error_before_or_after_effect_is_always_unknown(self):
        real_replace = os.replace
        for did_replace in (False, True):
            with self.subTest(did_replace=did_replace):
                self.target.write_bytes(ORIGINAL)
                binding = self.binding()

                def ambiguous(*args, **kwargs):
                    if did_replace:
                        real_replace(*args, **kwargs)
                    raise OSError(errno.EIO, SECRET.decode())

                with patch.object(publication.os, "replace", side_effect=ambiguous) as replace_call:
                    self.error("publication_operation_failed", lambda: self.publish(binding), outcome="unknown")
                self.assertEqual(replace_call.call_count, 1)
                self.assertEqual(self.target.read_bytes(), CANDIDATE if did_replace else ORIGINAL)
                self.assertEqual(self.temps(), [])

    def test_cancellation_after_rename_is_sanitized_and_never_rolled_back(self):
        binding = self.binding()
        real_replace = os.replace

        def interrupted(*args, **kwargs):
            real_replace(*args, **kwargs)
            raise KeyboardInterrupt(SECRET.decode())

        with patch.object(publication.os, "replace", side_effect=interrupted):
            self.error("publication_operation_failed", lambda: self.publish(binding), outcome="unknown")
        self.assertEqual(self.target.read_bytes(), CANDIDATE)

    def test_post_rename_change_is_unknown_and_external_bytes_are_preserved(self):
        binding = self.binding()
        real_sync = os.fsync

        def external_edit(fd):
            real_sync(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                self.target.write_bytes(b"external post-rename edit")

        with patch.object(publication.os, "fsync", side_effect=external_edit):
            self.error("publication_result_changed", lambda: self.publish(binding), outcome="unknown")
        self.assertEqual(self.target.read_bytes(), b"external post-rename edit")

    def test_cleanup_failure_does_not_hide_original_prepublication_failure(self):
        binding = self.binding()
        with patch.object(publication.os, "write", side_effect=OSError("private write failure")), \
                patch.object(publication.os, "unlink", side_effect=OSError("private cleanup failure")):
            self.error("publication_operation_failed", lambda: self.publish(binding), cleanup=False)
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(len(self.temps()), 1)

    def test_replaced_temporary_entry_is_not_deleted_during_cleanup(self):
        binding = self.binding()

        def guard(value):
            result = self.ready(value)
            if self.calls == 3:
                temporary = self.temps()[0]
                temporary.unlink()
                temporary.write_bytes(b"foreign temporary entry")
            return result

        self.error("publication_temporary_changed", lambda: self.publish(binding, guard), cleanup=False)
        self.assertEqual(self.target.read_bytes(), ORIGINAL)
        self.assertEqual(self.temps()[0].read_bytes(), b"foreign temporary entry")

    def test_post_publication_descriptor_cleanup_failure_keeps_unknown_outcome(self):
        binding = self.binding()
        real_open, real_close = os.open, os.close
        temporary_fd = None
        raised = False

        def opened(path, flags, *args, **kwargs):
            nonlocal temporary_fd
            fd = real_open(path, flags, *args, **kwargs)
            if type(path) is str and path.startswith(".mpkg-publication-") and flags & os.O_CREAT:
                temporary_fd = fd
            return fd

        def closed(fd):
            nonlocal raised
            if fd == temporary_fd and not raised:
                raised = True
                real_close(fd)
                raise OSError("private descriptor cleanup failure")
            real_close(fd)

        with patch.object(publication.os, "open", side_effect=opened), \
                patch.object(publication.os, "close", side_effect=closed):
            self.error("publication_cleanup_failed", lambda: self.publish(binding),
                       outcome="unknown", cleanup=False)
        self.assertEqual(self.target.read_bytes(), CANDIDATE)

    def test_restrictive_umask_does_not_change_preserved_target_permissions(self):
        binding = self.binding()
        previous = os.umask(0o777)
        try:
            self.publish(binding)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)

    def test_changed_policy_and_cross_host_input_are_refused(self):
        binding = self.binding()
        cross_host = replace(binding, original=replace(binding.original, host_id=str(uuid.uuid4())))
        self.error("publication_root_not_allowed", lambda: self.publish(cross_host))
        self.policy_path.write_text(self.policy_path.read_text() + "\n# policy changed\n")
        self.error("publication_operation_failed", lambda: self.publish(binding))
        self.assertEqual(self.target.read_bytes(), ORIGINAL)

    def test_unsupported_bindings_and_relative_paths_are_rejected(self):
        original = self.capture()
        for candidate in (bytearray(b"x"), "text", None):
            with self.subTest(candidate=type(candidate)):
                self.error("invalid_publication_binding", lambda: publication.bind_publication(
                    original, candidate, adapter="fixture", input_reference=str(uuid.uuid4())))
        for relative in ("../outside", "/absolute", "application//config", "application/./config"):
            with self.subTest(relative=relative):
                self.error("invalid_publication_input", lambda: publication.capture_publication_input(
                    self.policy, root=str(self.root), relative_path=relative))

    def test_primitive_has_no_restart_rollback_or_external_command_path(self):
        binding = self.binding()
        with patch("subprocess.Popen", side_effect=AssertionError("external command")), \
                patch("socket.socket", side_effect=AssertionError("network")), \
                patch("os.system", side_effect=AssertionError("shell")):
            self.publish(binding)
        self.assertEqual(self.target.read_bytes(), CANDIDATE)


if __name__ == "__main__":
    unittest.main()
