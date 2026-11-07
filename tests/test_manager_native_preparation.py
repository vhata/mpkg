"""Copied fixture inputs and controlled bridge replies; no native operations."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import native_preparation as native
from mpkg_manager.query_process import QueryResult


class NativePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.installed = self.root / "installed"
        self.installed.mkdir(mode=0o700)
        self.write(self.installed / "ALPM_DB_VERSION", b"9\n")
        self.write(self.installed / "base-1/desc", b"installed base 1 explicit")
        self.keys = self.root / "keys"
        self.keys.mkdir(mode=0o700)
        self.write(self.keys / "pubring.gpg", b"synthetic trusted public keyring")
        self.write(self.keys / "trustdb.gpg", b"synthetic trust database")
        self.stages = self.root / "stages"
        self.stages.mkdir(mode=0o700)
        self.source = self.root / "inputs"
        self.source.mkdir(mode=0o700)
        database = self.write(self.source / "core.db", b"synthetic sync metadata")
        signature = self.write(self.source / "core.db.sig", b"synthetic database signature")
        self.repositories = (native.NativeRepository(
            "core", ("https://archive.example/dated/core",), database, self.digest(database),
            signature, self.digest(signature)),)
        self.artifacts = tuple(self.artifact(name, version) for name, version in
                               (("base", "2"), ("app", "1"), ("dep", "2"),
                                ("extra", "1"), ("new", "1"), ("other-provider", "2")))
        self.requests = (native.NativeRequest("app", "1"),)
        self.host = str(uuid.uuid4())
        self.seen = []

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def write(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def artifact(self, name, version):
        path = self.write(self.source / (name + ".pkg"), (name + version).encode())
        signature = self.write(self.source / (name + ".sig"), ("signature-" + name).encode())
        return native.NativeArtifact(name, version, "core", path, self.digest(path),
                                     signature, self.digest(signature))

    def add_row(self, name):
        item = next(item for item in self.artifacts if item.name == name)
        return "\t".join(("A", item.name, item.version, item.repository, item.sha256))

    def output(self, *, extra=(), omit=()):
        rows = ["V\t16.0.1", "I\tbase\t1\t0", self.add_row("base"),
                self.add_row("app"), self.add_row("dep"), "T\tapp\tapp\t1",
                "D\tapp\tvirtual>=2\tdep", "P\tdep\tvirtual=2",
                "Q\tprovider\tvirtual>=2\tdep", *extra]
        return ("\n".join(row for row in rows if row not in omit) + "\n").encode()

    def runner(self, stage):
        self.seen.append(stage)
        self.assertEqual((stage / "db/local/base-1/desc").read_bytes(),
                         b"installed base 1 explicit")
        self.assertEqual((stage / "db/sync/core.db").read_bytes(),
                         self.repositories[0].database.read_bytes())
        self.assertEqual((stage / "requests").read_text(), "app\t1\n")
        self.assertEqual((stage / "protocol").read_text(), "1\t16.0.1\tx86_64\n")
        return QueryResult("ok", self.output(), 0)

    def prepare(self, **changes):
        args = dict(host_id=self.host, installed_database=self.installed,
                    keyring=self.keys, repositories=self.repositories,
                    artifacts=self.artifacts, requests=self.requests,
                    staging_root=self.stages, runner=self.runner)
        args.update(changes)
        return native.prepare_native_transaction(**args)

    def refused(self, code, **changes):
        with self.assertRaises(native.NativePreparationError) as caught:
            self.prepare(**changes)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        self.assertNotIn(str(self.root), str(caught.exception))

    def test_exact_copied_scope_keeps_sources_reasons_and_native_choices(self):
        before = native._tree(self.installed)
        result = self.prepare()
        manifest = result.manifest
        self.assertEqual(manifest["libalpm_version"], "16.0.1")
        self.assertEqual(manifest["installed"], [{"name": "base", "version": "1",
                                                  "reason": "explicit"}])
        self.assertEqual({item["name"]: item["reason"] for item in manifest["add"]},
                         {"base": "explicit", "app": "explicit", "dep": "dependency"})
        self.assertEqual(manifest["choices"], [["provider", "virtual>=2", "dep"]])
        self.assertEqual(manifest["dependencies"], [["app", "virtual>=2", "dep"]])
        self.assertTrue(manifest["coordinated_upgrade"])
        self.assertEqual(manifest["native_flags"], 0)
        self.assertEqual(manifest["sources"][0]["package_signature"], "required_trusted")
        self.assertEqual(native._tree(self.installed), before)
        self.assertEqual((result.stage / "manifest.json").read_bytes(), result.scope_bytes)
        self.assertEqual(len(manifest["add"]), 3)  # Extra offered archives confer no scope.
        self.assertNotIn("extra", {item["name"] for item in manifest["add"]})

    def test_manifest_is_immutable_and_public_projection_has_no_private_inputs(self):
        result = self.prepare()
        original = result.scope_bytes
        projected = result.manifest
        projected["sources"][0]["servers"] = ["changed"]
        self.assertEqual(result.scope_bytes, original)
        with self.assertRaises(FrozenInstanceError):
            result.scope_bytes = b"changed"
        public = repr(result.as_dict()) + repr(result)
        for private in (str(self.root), self.repositories[0].sha256,
                        self.repositories[0].servers[0], "synthetic"):
            self.assertNotIn(private, public)
        self.assertFalse(result.as_dict()["apply_authorized"])

    def test_identical_preparation_has_same_scope_but_a_new_id(self):
        one, two = self.prepare(), self.prepare()
        self.assertNotEqual(one.preparation_id, two.preparation_id)
        self.assertNotEqual(one.stage, two.stage)
        native.require_same_native_scope(one, two)

    def test_widened_upgrade_and_provider_changes_require_new_scope(self):
        one = self.prepare()
        widened = self.prepare(runner=lambda _: QueryResult("ok", self.output(
            extra=(self.add_row("extra"),)), 0))
        with self.assertRaisesRegex(native.NativePreparationError, "native_prepared_scope_changed"):
            native.require_same_native_scope(one, widened)
        changed = self.output().replace(self.add_row("dep").encode(),
                                        self.add_row("other-provider").encode())
        changed = changed.replace(b"\tdep\n", b"\tother-provider\n")
        changed = changed.replace(b"P\tdep\t", b"P\tother-provider\t")
        provider = self.prepare(runner=lambda _: QueryResult("ok", changed, 0))
        with self.assertRaisesRegex(native.NativePreparationError, "native_prepared_scope_changed"):
            native.require_same_native_scope(one, provider)

    def test_signature_policy_and_source_order_are_bound(self):
        one = self.prepare()
        repo = replace(self.repositories[0], require_database_signature=False)
        two = self.prepare(repositories=(repo,))
        with self.assertRaisesRegex(native.NativePreparationError, "native_prepared_scope_changed"):
            native.require_same_native_scope(one, two)
        self.assertEqual(two.manifest["sources"][0]["database_signature"], "optional_trusted")

    def test_exact_unavailable_pin_is_not_downgraded_to_unrestricted(self):
        self.refused("native_pin_unavailable", requests=(native.NativeRequest("app", "0"),),
                     runner=lambda _: QueryResult("ok", self.output(), 0))
        self.refused("native_pin_unavailable",
                     runner=lambda _: QueryResult("ok", b"BLOCK\tpin\n", 0))
        result = self.prepare(requests=(native.NativeRequest("app"),),
                              runner=lambda _: QueryResult("ok", self.output(), 0))
        self.assertIsNone(result.manifest["requests"][0]["version"])

    def test_virtual_exact_request_uses_native_provider_satisfaction(self):
        raw = self.output().replace(b"T\tapp\tapp\t1", b"T\tvirtual\tdep\t2")
        raw = raw.replace(b"virtual=2", b"virtual=7")
        result = self.prepare(requests=(native.NativeRequest("virtual", "7"),),
                              runner=lambda _: QueryResult("ok", raw, 0))
        self.assertEqual(result.manifest["requests"],
                         [{"name": "virtual", "version": "7", "provider": "dep"}])

    def test_satisfied_exact_and_unrestricted_requests_have_no_archive_effect(self):
        raw = b"V\t16.0.1\nI\tapp\t1\t0\nT\tapp\tapp\t1\n"
        for version in ("1", None):
            with self.subTest(version=version):
                result = self.prepare(requests=(native.NativeRequest("app", version),),
                                      artifacts=(), runner=lambda _: QueryResult("ok", raw, 0))
                self.assertEqual(result.manifest["add"], [])
                self.assertEqual(result.manifest["remove"], [])
                self.assertEqual(result.manifest["reason_changes"], [])

    def test_requesting_existing_dependency_records_separate_reason_change(self):
        raw = b"V\t16.0.1\nI\tapp\t1\t1\nT\tapp\tapp\t1\n"
        result = self.prepare(artifacts=(), runner=lambda _: QueryResult("ok", raw, 0))
        self.assertEqual(result.manifest["add"], [])
        self.assertEqual(result.manifest["reason_changes"],
                         [{"name": "app", "from": "dependency", "to": "explicit"}])

    def test_native_replacement_binds_removed_version_reason_and_choice(self):
        raw = self.output(extra=("I\told\t1\t1", "R\told\t1\t1",
                                 self.add_row("new"), "Q\treplacement\told\tnew"))
        result = self.prepare(runner=lambda _: QueryResult("ok", raw, 0))
        self.assertEqual(result.manifest["remove"],
                         [{"name": "old", "version": "1", "reason": "dependency"}])
        self.refused("unexplained_native_removal", runner=lambda _: QueryResult(
            "ok", raw.replace(b"Q\treplacement\told\tnew\n", b""), 0))

    def test_preserves_independently_explicit_dependency_reason(self):
        result = self.prepare(runner=lambda _: QueryResult("ok", self.output(
            extra=("I\tdep\t1\t0",)), 0))
        self.assertEqual(next(item for item in result.manifest["add"]
                              if item["name"] == "dep")["reason"], "explicit")

    def test_incomplete_or_substituted_artifact_closure_is_rejected(self):
        self.refused("native_artifact_unavailable", artifacts=self.artifacts[:2])
        raw = self.output().replace(self.artifacts[0].sha256.encode(), b"0" * 64)
        self.refused("native_artifact_mismatch", runner=lambda _: QueryResult("ok", raw, 0))
        raw = self.output().replace(b"A\tbase\t2\tcore", b"A\tbase\t3\tcore")
        self.refused("native_artifact_mismatch", runner=lambda _: QueryResult("ok", raw, 0))

    def test_artifact_content_digest_and_required_signatures_are_checked(self):
        self.artifacts[0].path.write_bytes(b"substituted")
        self.refused("native_input_digest_mismatch")
        self.assertEqual(self.seen, [])
        self.refused("database_signature_missing", repositories=(replace(
            self.repositories[0], signature=None, signature_sha256=None),))

    def test_signature_invalid_native_response_cannot_create_preparation(self):
        self.refused("native_signature_unavailable",
                     runner=lambda _: QueryResult("ok", b"BLOCK\tsignature\n", 0))
        self.assertFalse(any(self.stages.glob("*/manifest.json")))

    def test_inventory_changes_during_copy_are_refused_before_native_resolution(self):
        original = native._copy_tree

        def changed(captured, destination):
            original(captured, destination)
            if destination.name == "local":
                (self.installed / "base-1/desc").write_bytes(b"changed inventory")

        with patch.object(native, "_copy_tree", side_effect=changed):
            self.refused("installed_snapshot_unstable")
        self.assertEqual(self.seen, [])

    def test_inventory_changes_during_native_resolution_are_refused(self):
        def changed(_):
            (self.installed / "base-1/desc").write_bytes(b"changed inventory")
            return QueryResult("ok", self.output(), 0)

        self.refused("installed_snapshot_unstable", runner=changed)

    def test_reason_only_inventory_change_requires_new_preparation(self):
        one = self.prepare()
        (self.installed / "base-1/desc").write_bytes(b"installed base 1 dependency")
        raw = self.output().replace(b"I\tbase\t1\t0", b"I\tbase\t1\t1")
        two = self.prepare(runner=lambda _: QueryResult("ok", raw, 0))
        with self.assertRaisesRegex(native.NativePreparationError, "native_prepared_scope_changed"):
            native.require_same_native_scope(one, two)

    def test_changed_staged_artifacts_or_database_cannot_use_old_native_reply(self):
        for relative in ("artifacts/0.pkg", "db/sync/core.db", "db/local/base-1/desc"):
            with self.subTest(relative=relative):
                def changed(stage):
                    (stage / relative).write_bytes(b"changed after verification")
                    return QueryResult("ok", self.output(), 0)

                self.refused("native_staged_input_changed", runner=changed)

    def test_keyring_change_and_executable_gpg_configuration_are_refused(self):
        def changed(_):
            (self.keys / "trustdb.gpg").write_bytes(b"different trust")
            return QueryResult("ok", self.output(), 0)

        self.refused("native_keyring_changed", runner=changed)
        self.write(self.keys / "gpg.conf", b"keyserver private.example")
        self.refused("unsupported_native_keyring")

    def test_changed_staged_trust_input_cannot_be_bound_to_original_keyring(self):
        for name in ("trustdb.gpg", "pubring.gpg"):
            with self.subTest(name=name):
                def changed(stage):
                    (stage / "gpg" / name).write_bytes(b"substituted native trust")
                    return QueryResult("ok", self.output(), 0)

                self.refused("native_staged_keyring_changed", runner=changed)
        self.assertFalse(any(self.stages.glob("*/manifest.json")))

    def test_symlinks_and_special_inputs_are_not_followed(self):
        original = self.artifacts[0]
        link = self.source / "linked"
        link.symlink_to(original.path)
        self.refused("native_preparation_unavailable", artifacts=(replace(original, path=link),
                                                                 *self.artifacts[1:]))
        fifo = self.source / "fifo"
        os.mkfifo(fifo, 0o600)
        self.refused("native_input_shape", artifacts=(replace(original, path=fifo),
                                                       *self.artifacts[1:]))
        linkdir = self.root / "linked-directory"
        linkdir.symlink_to(self.installed, target_is_directory=True)
        self.refused("native_preparation_unavailable", installed_database=linkdir)

    def test_regular_to_fifo_race_does_not_block_metadata_capture(self):
        original_open = os.open
        changed = False

        def race(path, flags, *args, **kwargs):
            nonlocal changed
            if path == "desc" and not changed:
                changed = True
                target = self.installed / "base-1/desc"
                target.unlink()
                os.mkfifo(target, 0o600)
                self.assertTrue(flags & os.O_NONBLOCK)
            return original_open(path, flags, *args, **kwargs)

        with patch.object(native.os, "open", side_effect=race):
            self.refused("native_input_changed")

    def test_artifact_fingerprint_streams_without_metadata_tree_budget(self):
        artifact_dir = self.root / "large-artifacts"
        artifact_dir.mkdir(mode=0o700)
        self.write(artifact_dir / "file", b"x" * 256)
        with self.assertRaisesRegex(native.NativePreparationError, "native_input_limit"):
            native._tree(artifact_dir, limit=128)
        entries, _, digest = native._tree(artifact_dir, capture=False, limit=512)
        self.assertEqual(entries, (("file", hashlib.sha256(b"x" * 256).hexdigest()),))
        self.assertEqual(digest, native._tree(artifact_dir)[2])

    def test_source_hardlinks_and_writable_inputs_are_rejected(self):
        os.link(self.artifacts[0].path, self.source / "hardlink")
        self.refused("native_input_shape")
        (self.source / "hardlink").unlink()
        self.artifacts[0].path.chmod(0o666)
        self.refused("native_input_shape")

    def test_staging_must_be_private_and_outside_live_inventory(self):
        self.stages.chmod(0o755)
        self.refused("native_staging_not_private")
        child = self.installed / "staging"
        child.mkdir(mode=0o700)
        self.refused("native_staging_overlap", staging_root=child)

    def test_default_runner_has_fixed_binary_environment_and_no_host_tool_fallback(self):
        with patch.object(native, "run_bounded", return_value=QueryResult("ok", self.output(), 0)) as run:
            self.prepare(runner=None)
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "/usr/lib/mpkg/native-prepare")
        self.assertEqual(len(args[0]), 2)
        self.assertTrue(Path(args[0][1]).is_relative_to(self.stages))
        self.assertEqual(kwargs["environment"], {"PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(kwargs["timeout"], 30)
        self.assertTrue(kwargs["require_empty_stderr"])

    def test_missing_native_bridge_never_falls_back_to_print_output(self):
        with patch.object(native, "run_bounded", return_value=QueryResult("tool_unavailable")) as run:
            self.refused("native_bridge_unavailable", runner=None)
        self.assertEqual(run.call_count, 1)

    def test_native_errors_and_raw_secret_output_are_sanitized(self):
        def failed(_):
            raise OSError("SECRET_SENTINEL private path and native stderr")

        self.refused("native_preparation_unavailable", runner=failed)
        self.refused("invalid_native_bridge_result", runner=lambda _: QueryResult(
            "ok", b"BLOCK\tSECRET_SENTINEL\n", 0))
        self.refused("native_bridge_unavailable", runner=lambda _: QueryResult("timeout"))

    def test_closed_protocol_rejects_malformed_missing_and_duplicate_scope(self):
        outputs = [self.output()[:-1], self.output() + b"V\t16.0.1\n",
                   self.output() + b"UNKNOWN\tfield\n", self.output() + b"\n",
                   self.output().replace(b"T\tapp\tapp\t1\n", b""),
                   self.output().replace(b"I\tbase\t1\t0", b"I\tbase\t1\t2"),
                   self.output().replace(b"D\tapp\tvirtual>=2\tdep", b"D\tapp\tvirtual>=2\tabsent")]
        for output in outputs:
            with self.subTest(output=output[-30:]):
                self.refused("invalid_native_bridge_result",
                             runner=lambda _, output=output: QueryResult("ok", output, 0))

    def test_abi_mismatch_has_no_successful_manifest(self):
        self.refused("native_abi_unavailable", runner=lambda _: QueryResult(
            "ok", self.output().replace(b"16.0.1", b"17.0.0"), 0))

    def test_invalid_requests_sources_and_architectures_do_not_open_inputs(self):
        invalid = [{"requests": (native.NativeRequest("app;sudo"),)},
                   {"requests": (native.NativeRequest("app", ">1"),)},
                   {"requests": (self.requests[0], self.requests[0])},
                   {"host_id": "not-a-host"}, {"architecture": "other"},
                   {"repositories": (replace(self.repositories[0],
                                              servers=("file:///private",)),)}]
        for change in invalid:
            with self.subTest(change=change), patch.object(native, "_open_directory") as open_dir:
                self.refused("invalid_native_preparation", **change)
                open_dir.assert_not_called()


if __name__ == "__main__":
    unittest.main()
