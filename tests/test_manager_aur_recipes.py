"""Pinned AUR acquisition with inert bytes; no package tools or live downloads."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from mpkg_manager import aur_recipes as aur


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = "PRIVATE_AUR_RECIPE_SENTINEL"
COMMIT = "1" * 40


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(name="app", *, runtime=(), build=(), checks=(), provides=(), pkgbuild=None,
            metadata_extra="", source_raw=b"source archive", packages=None):
    source_url = f"https://cpan.metacpan.org/{name}-1.0.tar.gz"
    metadata = f"pkgbase = {name}\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = any\n"
    for key, values in (("depends", runtime), ("makedepends", build), ("checkdepends", checks), ("provides", provides)):
        metadata += "".join(f"\t{key} = {value}\n" for value in values)
    metadata += (f"\tsource = {source_url}\n\tsha256sums = {digest(source_raw)}\n"
                 + metadata_extra + "".join(f"pkgname = {package}\n" for package in (packages or (name,))))
    body = {"PKGBUILD": (b"pkgname=" + name.encode() + b"\npackage() { :; }\n") if pkgbuild is None else pkgbuild,
            ".SRCINFO": metadata.encode()}
    pins = tuple(aur.FilePin(filename, f"https://raw.githubusercontent.com/archlinux/aur/{COMMIT}/{filename}",
                            (("sha256", digest(raw)),)) for filename, raw in body.items())
    source = aur.FilePin(name + "-1.0.tar.gz", source_url, (("sha256", digest(source_raw)),))
    pin = aur.RecipePin(name, COMMIT, "1.0-1", packages or (name,), pins, (source,), "aur_official_mirror")
    blobs = {entry.url: body[entry.name] for entry in pins} | {source_url: source_raw}
    return pin, blobs


def trust(pin):
    return aur.RecipeTrust(pin.recipe_id, os.geteuid(), str(uuid.uuid4()))


class AurRecipeTests(unittest.TestCase):
    def prepare(self, fixtures, *, roots=("app",), choices=(), fetcher=None, trusts=None):
        pins = tuple(pair[0] for pair in fixtures)
        blobs = {url: raw for _, content in fixtures for url, raw in content.items()}
        # Same-commit mirror URLs in synthetic fixtures must still distinguish
        # recipes; assign different commits in multi-recipe fixtures below.
        actual = (lambda url, maximum, deadline: blobs[url]) if fetcher is None else fetcher
        return aur.prepare_recipes(pins, tuple(trust(pin) for pin in pins) if trusts is None else trusts,
                                   roots=roots, choices=choices, _fetcher=actual)

    def unique(self, index, *args, **kwargs):
        pin, blobs = fixture(*args, **kwargs)
        commit = str(index) * 40
        files = tuple(replace(item, url=item.url.replace(COMMIT, commit)) for item in pin.files)
        pin = replace(pin, commit=commit, files=files)
        return pin, {url.replace(COMMIT, commit): raw for url, raw in blobs.items()}

    def error(self, code, callback):
        with self.assertRaises(aur.AurPreparationError) as error:
            callback()
        self.assertEqual(error.exception.code, code)
        self.assertNotIn(PRIVATE, str(error.exception))

    def test_pinned_inputs_are_retained_immutably_without_execution_authority(self):
        pin, blobs = fixture(pkgbuild=(PRIVATE + "\nsudo pacman -S package\n").encode())
        prepared = self.prepare([(pin, blobs)])
        public = prepared.as_dict()
        self.assertFalse(public["build_authorized"])
        self.assertFalse(public["installation_authorized"])
        self.assertEqual(public["generated_metadata"], "unverified")
        self.assertEqual(public["dependency_installation"], "not_performed")
        self.assertEqual(len(prepared._files), 3)
        self.assertNotIn(PRIVATE, json.dumps(public) + repr(prepared))
        self.assertNotIn("https://", json.dumps(public))
        manifest = json.loads(prepared._manifest)
        self.assertEqual(manifest["recipes"][0]["commit"], COMMIT)
        self.assertEqual(manifest["recipes"][0]["acquired_files"][0]["sha256"], digest(blobs[pin.files[0].url]))
        public["recipes"].clear()
        self.assertEqual(len(prepared.as_dict()["recipes"]), 1)
        with self.assertRaises(FrozenInstanceError):
            pin.commit = "0" * 40

    def test_recursive_aur_runtime_build_and_check_inputs_are_distinct(self):
        app = self.unique(1, runtime=("library>=1.0", "libc"), build=("compiler",), checks=("test-tool",))
        library = self.unique(2, "library", runtime=("libc",))
        choices = (aur.DependencyChoice("library", "aur", "library", "library"),
                   *(aur.DependencyChoice(name, "native") for name in ("libc", "compiler", "test-tool")))
        result = self.prepare([app, library], choices=choices).as_dict()
        self.assertEqual(result["build_order"], ["library", "app"])
        dependencies = {(item["recipe_base"], item["phase"], item["request"]): item for item in result["dependencies"]}
        self.assertEqual(dependencies["app", "runtime", "library>=1.0"]["source"], "aur")
        self.assertEqual(dependencies["app", "build", "compiler"]["source"], "native")
        self.assertEqual(dependencies["app", "check", "test-tool"]["source"], "native")
        self.assertTrue(all(item["constraint_verification"] == "requires_native_resolution"
                            for item in result["dependencies"]))

    def test_shared_recursive_recipe_is_acquired_once(self):
        app = self.unique(1, runtime=("library",))
        other = self.unique(2, "other", runtime=("library",))
        library = self.unique(3, "library")
        result = self.prepare([app, other, library], roots=("app", "other"),
                              choices=(aur.DependencyChoice("library", "aur", "library", "library"),))
        self.assertEqual(len(result._files), 9)
        self.assertEqual(result.as_dict()["build_order"], ["library", "app", "other"])

    def test_recursive_cycle_is_refused_without_build_or_install(self):
        app = self.unique(1, runtime=("library",))
        library = self.unique(2, "library", build=("app",))
        choices = (aur.DependencyChoice("library", "aur", "library", "library"),
                   aur.DependencyChoice("app", "aur", "app", "app"))
        self.error("aur_dependency_cycle", lambda: self.prepare([app, library], choices=choices))

    def test_own_output_build_and_check_dependencies_are_cycles(self):
        route = (aur.DependencyChoice("app", "aur", "app", "app"),)
        for kwargs in ({"build": ("app",)}, {"checks": ("app",)}, {"runtime": ("app",)}):
            with self.subTest(kwargs=kwargs):
                self.error("aur_dependency_cycle", lambda: self.prepare([fixture(**kwargs)], choices=route))

    def test_split_output_runtime_dependencies_do_not_require_a_recipe_rebuild(self):
        pin, blobs = fixture(packages=("app", "library"))
        srcinfo = blobs[pin.files[1].url].replace(b"pkgname = app\n", b"pkgname = app\ndepends = library\n")
        metadata_pin = replace(pin.files[1], digests=(("sha256", digest(srcinfo)),))
        pin = replace(pin, files=(pin.files[0], metadata_pin))
        result = self.prepare([(pin, blobs | {metadata_pin.url: srcinfo})],
                              choices=(aur.DependencyChoice("library", "aur", "app", "library"),))
        self.assertEqual(result.as_dict()["build_order"], ["app"])
        self.assertEqual(result.as_dict()["dependencies"][0]["target_package"], "library")

    def test_virtual_provider_routing_retains_constraint_without_solving_it(self):
        app = self.unique(1, runtime=("virtual>=999",))
        library = self.unique(2, "library", provides=("virtual=1.0",))
        result = self.prepare([app, library], choices=(aur.DependencyChoice("virtual", "aur", "library", "library"),))
        self.assertEqual(result.as_dict()["dependencies"][0]["request"], "virtual>=999")
        self.assertEqual(result.as_dict()["native_resolution"], "required")
        self.assertFalse(result.as_dict()["build_authorized"])

    def test_wrong_provider_and_missing_recipe_are_refused(self):
        app = self.unique(1, runtime=("virtual",))
        library = self.unique(2, "library")
        route = (aur.DependencyChoice("virtual", "aur", "library", "library"),)
        self.error("aur_provider_mismatch", lambda: self.prepare([app, library], choices=route))
        self.error("aur_recipe_missing", lambda: self.prepare([app], choices=route))

    def test_unknown_dependency_source_and_unused_recipe_are_explicit(self):
        self.error("dependency_source_required", lambda: self.prepare([fixture(runtime=("unknown",))]))
        self.error("unused_recipe_pin", lambda: self.prepare([self.unique(1), self.unique(2, "extra")]))

    def test_missing_unknown_or_changed_trust_prevents_acquisition(self):
        pin, blobs = fixture()
        called = []
        self.error("recipe_trust_required", lambda: self.prepare([(pin, blobs)], trusts=(),
                    fetcher=lambda *args: called.append(args)))
        self.error("recipe_trust_required", lambda: self.prepare([(pin, blobs)],
                    trusts=(aur.RecipeTrust("0" * 64, os.geteuid(), str(uuid.uuid4())),)))
        self.assertEqual(called, [])
        self.error("unknown_recipe_provenance", lambda: replace(pin, provenance="unknown"))

    def test_recipe_and_srcinfo_substitution_are_rejected_by_pins(self):
        pin, blobs = fixture()
        for item in pin.files:
            with self.subTest(name=item.name):
                changed = blobs | {item.url: blobs[item.url] + PRIVATE.encode()}
                self.error("source_digest_mismatch", lambda: self.prepare([(pin, changed)]))

    def test_accepted_expected_version_and_output_set_must_match_metadata(self):
        pin, blobs = fixture()
        for changed in (replace(pin, version="2.0-1"), replace(pin, package_base="other"),
                        replace(pin, packages=("other",))):
            self.error("recipe_metadata_mismatch", lambda: self.prepare([(changed, blobs)], roots=(changed.package_base,)))

    def test_source_url_digest_and_presence_must_match_metadata(self):
        pin, blobs = fixture()
        source = pin.sources[0]
        for changed in (replace(pin, sources=()),
                        replace(pin, sources=(replace(source, url=source.url + "/other"),)),
                        replace(pin, sources=(replace(source, digests=(("sha256", "0" * 64),)),))):
            self.error("source_metadata_mismatch", lambda: self.prepare([(changed, blobs)]))
        self.error("source_digest_mismatch", lambda: self.prepare([(pin, blobs | {source.url: b"substitution"})]))

    def test_unavailable_source_errors_are_fixed_and_private(self):
        pin, blobs = fixture()
        def failure(*args):
            raise RuntimeError(PRIVATE)
        self.error("source_unavailable", lambda: self.prepare([(pin, blobs)], fetcher=failure))

    def test_file_and_total_bounds_refuse_without_truncation(self):
        pin, blobs = fixture()
        with patch.object(aur, "MAX_METADATA_BYTES", 1):
            self.error("source_size_limit", lambda: self.prepare([(pin, blobs)]))
        with patch.object(aur, "MAX_TOTAL_BYTES", 1):
            self.error("source_size_limit", lambda: self.prepare([(pin, blobs)]))
        with patch.object(aur, "MAX_FILES", 1):
            self.error("aur_scope_limit", lambda: self.prepare([(pin, blobs)]))

    def test_hostile_startup_environment_and_recipe_cannot_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ran"
            evil = f"touch {marker}\nsudo pacman -S forbidden\n".encode()
            startup = Path(directory) / "startup"
            startup.write_bytes(evil)
            pin, blobs = fixture(pkgbuild=evil)
            with patch.dict(os.environ, {"BASH_ENV": str(startup), "ENV": str(startup),
                    "PYTHONSTARTUP": str(startup), "HTTP_PROXY": PRIVATE, "HTTPS_PROXY": PRIVATE}), \
                    patch("subprocess.Popen", side_effect=AssertionError("process executed")), \
                    patch("os.system", side_effect=AssertionError("shell executed")):
                result = self.prepare([(pin, blobs)])
            self.assertFalse(marker.exists())
            self.assertEqual(result.as_dict()["generated_metadata"], "unverified")

    def test_local_recipe_source_is_covered_by_recipe_pin(self):
        pin, blobs = fixture()
        patch_bytes = b"local patch bytes"
        patch_pin = aur.FilePin("fix.patch", f"https://raw.githubusercontent.com/archlinux/aur/{COMMIT}/fix.patch",
                                (("sha256", digest(patch_bytes)),))
        srcinfo = blobs[pin.files[1].url].replace(pin.sources[0].url.encode(), b"fix.patch").replace(
            dict(pin.sources[0].digests)["sha256"].encode(), digest(patch_bytes).encode())
        metadata_pin = replace(pin.files[1], digests=(("sha256", digest(srcinfo)),))
        pin = replace(pin, files=(pin.files[0], metadata_pin, patch_pin), sources=())
        blobs |= {metadata_pin.url: srcinfo, patch_pin.url: patch_bytes}
        result = self.prepare([(pin, blobs)])
        self.assertEqual(len(result._files), 3)


class SrcInfoTests(unittest.TestCase):
    def parse(self, raw):
        return aur.parse_srcinfo(raw.encode()).model

    def test_frozen_aur_metadata_matches_recorded_fixture_digests_and_dependencies(self):
        fixture_manifest = json.loads((ROOT / "docs/fixtures/2026-10-31-arch-native-inputs.json").read_text())
        for recipe in fixture_manifest["aur_packages"]:
            raw = (ROOT / "tests/fixtures/aur-recipes" / recipe["package_base"] / ".SRCINFO").read_bytes()
            self.assertEqual(digest(raw), recipe["recipe_files"][".SRCINFO"]["sha256_computed"])
            model = aur.parse_srcinfo(raw).model
            self.assertEqual(model["package_base"], recipe["package_base"])
            self.assertEqual(model["version"], recipe["srcinfo_version"])
            self.assertEqual(model["outputs"][0]["dependencies"], recipe["declared_runtime_dependencies"])
            self.assertEqual(model["fields"].get("makedepends", []), recipe["declared_build_dependencies"])
            self.assertEqual(model["fields"].get("checkdepends", []), recipe["declared_check_dependencies"])
            self.assertEqual([row["name"] for row in aur._sources(model)], [row["filename"] for row in recipe["sources"]])

    def test_split_package_overrides_and_architecture_specific_dependencies(self):
        model = self.parse('''pkgbase = split
pkgver = 1.0
pkgrel = 2
epoch = 3
arch = x86_64
arch = aarch64
depends = common
depends_x86_64 = machine
makedepends = compiler
pkgname = first
depends = replacement
pkgname = second
depends =
depends_x86_64 = alternate
''')
        self.assertEqual(model["version"], "3:1.0-2")
        self.assertEqual(model["outputs"][0]["dependencies"], ["replacement", "machine"])
        self.assertEqual(model["outputs"][1]["dependencies"], ["alternate"])

    def test_unknown_fields_duplicate_scalars_and_misplaced_build_inputs_fail_closed(self):
        valid = "pkgbase = app\npkgver = 1\npkgrel = 1\narch = any\npkgname = app\n"
        for raw in (valid + "makedepends = extra\n", valid + "source = path\n", valid + "mystery = value\n",
                    valid.replace("pkgrel = 1", "pkgrel = 1\npkgrel = 2"),
                    valid.replace("pkgbase = app", "pkgname = app"), valid + "pkgname = app\n"):
            with self.subTest(raw=raw), self.assertRaises(aur.AurPreparationError):
                self.parse(raw)

    def test_shell_expressions_are_never_expanded_as_versions_or_dependencies(self):
        for value in ("$(touch /tmp/should-not-exist)", "`sudo pacman -S forbidden`", "${pkgver}"):
            with self.subTest(value=value), self.assertRaises(aur.AurPreparationError):
                self.parse(f"pkgbase = app\npkgver = {value}\npkgrel = 1\narch = any\npkgname = app\n")

    def test_malformed_dependency_operators_are_rejected(self):
        for operator in ("==", "><", "=>", "<<", "=<", ">>"):
            for key in ("depends", "makedepends", "checkdepends", "provides"):
                with self.subTest(operator=operator, key=key), self.assertRaises(aur.AurPreparationError):
                    self.parse(f"pkgbase = app\npkgver = 1\npkgrel = 1\narch = any\n{key} = library{operator}1\npkgname = app\n")

    def test_weak_only_skipped_misaligned_or_vcs_sources_are_refused(self):
        pin, blobs = fixture()
        original = blobs[pin.files[1].url].decode()
        for text in (original.replace("sha256sums", "md5sums"),
                     original.replace(dict(pin.sources[0].digests)["sha256"], "SKIP"),
                     original.replace("pkgname = app", "sha256sums = " + "0" * 64 + "\npkgname = app"),
                     original.replace(pin.sources[0].url, "git+https://github.com/example/project.git#branch=main")):
            with self.subTest(text=text), self.assertRaises(aur.AurPreparationError):
                aur._sources(self.parse(text))

    def test_source_urls_refuse_credentials_queries_traversal_and_untrusted_hosts(self):
        for url in ("http://github.com/file", "https://user:secret@github.com/file", "https://github.com/file?token=x",
                    "https://github.com/../file", "https://github.com/%2e%2e/file", "https://unknown.example/file",
                    "file:///etc/passwd", "https://[invalid"):
            with self.subTest(url=url), self.assertRaises(aur.AurPreparationError):
                aur.FilePin("file", url, (("sha256", "0" * 64),))


class TransportTests(unittest.TestCase):
    def response(self, raw):
        stream = io.BytesIO(raw)
        stream.status = 200
        return stream

    def test_fixed_transport_ignores_proxy_environment_and_uses_bounded_reads(self):
        class Opener:
            def open(inner, request, timeout):
                self.assertEqual(request.full_url, "https://cpan.metacpan.org/file")
                self.assertGreater(timeout, 0)
                return self.response(b"content")
        with patch.dict(os.environ, {"HTTPS_PROXY": PRIVATE}), \
                patch.object(aur.urllib.request, "build_opener", return_value=Opener()) as build, \
                patch("subprocess.Popen", side_effect=AssertionError("process executed")):
            self.assertEqual(aur._fetch("https://cpan.metacpan.org/file", 20, aur.time.monotonic() + 5), b"content")
        self.assertEqual(build.call_args.args[0].proxies, {})

    def test_transport_size_timeout_and_redirect_limits_fail_closed(self):
        class Opener:
            def open(inner, request, timeout):
                return self.response(b"too large")
        with patch.object(aur.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(aur.AurPreparationError, "source_size_limit"):
                aur._fetch("https://cpan.metacpan.org/file", 2, aur.time.monotonic() + 5)
        with self.assertRaisesRegex(aur.AurPreparationError, "source_timeout"):
            aur._fetch("https://cpan.metacpan.org/file", 20, aur.time.monotonic() - 1)
        with self.assertRaisesRegex(aur.AurPreparationError, "unsupported_source"):
            aur._Redirect().redirect_request(None, None, 302, None, {}, "http://example.org/secret")

    def test_slow_chunks_return_to_budget_checks_without_filling_a_buffer(self):
        now = [0]
        class SlowResponse:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read1(self, maximum):
                now[0] += 2
                return b"x"
            def read(self, maximum):
                raise AssertionError("unbounded accumulating read")
        class Opener:
            def open(self, *args, **kwargs):
                return SlowResponse()
        with patch.object(aur.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(aur.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(aur.AurPreparationError, "source_timeout"):
                aur._fetch("https://cpan.metacpan.org/file", 100, 3)
        self.assertEqual(now[0], 4)


if __name__ == "__main__":
    unittest.main()
