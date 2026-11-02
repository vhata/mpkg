"""Private captured Compose preflight, without Docker or filesystem reads."""
from dataclasses import FrozenInstanceError, replace
import json
import os
import unittest
from unittest.mock import patch

from mpkg_manager import compose_inputs as inputs


BASE = "/accepted/private-project"
SOURCE = BASE + "/compose.yaml"


def document(value):
    return json.dumps(value).encode()


def capture(path, raw, classification="protected"):
    return inputs.CapturedComposeFile(BASE + "/" + path, classification, raw)


def bundle(model=None, extra=(), **changes):
    if model is None:
        model = {"services": {"sonarr": {"image": "registry.example/sonarr:fixed"}}}
    result = inputs.ComposeInputBundle(
        engine="accepted:engine", project="accepted-project", base_directory=BASE,
        source_paths=(SOURCE,), services=("sonarr",), profiles=(),
        files=(capture("compose.yaml", document(model)), *extra),
        interpolation_environment=())
    return replace(result, **changes)


class ComposeInputTests(unittest.TestCase):
    def assert_refused(self, value, code=None):
        with self.assertRaises(inputs.ComposeInputError) as raised:
            inputs.validate_compose_bundle(value)
        if code is not None:
            self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), raised.exception.code)
        self.assertNotIn(BASE, str(raised.exception))
        return raised.exception.code

    def test_exact_private_inputs_and_classification_survive_validation(self):
        value = bundle()
        result = inputs.validate_compose_bundle(value)
        self.assertIs(result.bundle, value)
        self.assertEqual(result.bundle.files[0].raw, value.files[0].raw)
        self.assertEqual(result.bundle.files[0].classification, "protected")
        self.assertEqual(result.references, ())
        self.assertEqual(result.as_dict(), {
            "subset": "compose_json_no_interpolation_v1", "source_count": 1,
            "captured_file_count": 1, "reference_count": 0,
            "supported_reference_closure": "complete",
            "capture_authentication": "caller_required", "effective_model": "unverified",
            "full_input_closure": "unverified", "apply_authorized": False})
        with self.assertRaises(FrozenInstanceError):
            result.bundle.project = "changed"
        with self.assertRaises(FrozenInstanceError):
            result.bundle.files[0].raw = b"changed"

    def test_order_and_original_base_are_preserved_across_overrides(self):
        first = {"services": {"sonarr": {"env_file": ["./first.env", "second.env"]}}}
        second = {"services": {"sonarr": {"env_file": "third.env",
                                          "environment": {"CHOICE": "explicit"}}}}
        value = bundle(first, (
            capture("overrides/local.yaml", document(second)),
            capture("first.env", b"CHOICE=first\n"),
            capture("second.env", b"CHOICE=second\n"),
            capture("third.env", b"CHOICE=third\n")),
            source_paths=(SOURCE, BASE + "/overrides/local.yaml"))
        result = inputs.validate_compose_bundle(value)
        self.assertEqual(result.bundle.source_paths, value.source_paths)
        self.assertEqual([(ref.source_index, ref.position, ref.path) for ref in result.references],
                         [(0, 0, BASE + "/first.env"), (0, 1, BASE + "/second.env"),
                          (1, 0, BASE + "/third.env")])
        # Source order remains significant; this validator never flattens env
        # precedence or guesses a merged effective environment.
        reversed_result = inputs.validate_compose_bundle(
            replace(value, source_paths=tuple(reversed(value.source_paths))))
        self.assertNotEqual(result, reversed_result)
        self.assertEqual(result.bundle.files[0].raw, value.files[0].raw)

    def test_local_files_bind_paths_volumes_and_networks_are_classified(self):
        model = {"services": {"sonarr": {
            "image": "sonarr:fixed", "platform": "linux/amd64", "restart": "unless-stopped",
            "env_file": "runtime.env", "profiles": ["media"],
            "configs": ["settings"], "secrets": ["password"], "networks": ["existing"],
            "volumes": [{"type": "bind", "source": "./config", "target": "/config"},
                        {"type": "bind", "source": "/media/movies", "target": "/movies", "read_only": True},
                        {"type": "volume", "source": "data", "target": "/data"}]}},
            "configs": {"settings": {"file": "settings.conf"}},
            "secrets": {"password": {"file": "secret.bin"}},
            "networks": {"existing": {"external": True, "name": "media_network"}},
            "volumes": {"data": None}}
        value = bundle(model, (capture("runtime.env", b"PUID=963\n", "nonsecret"),
                               capture("settings.conf", b"opaque $ bytes", "nonsecret"),
                               capture("secret.bin", b"\0\xffprivate")), profiles=("media",))
        result = inputs.validate_compose_bundle(value)
        self.assertEqual([(ref.kind, ref.path) for ref in result.references], [
            ("env", BASE + "/runtime.env"), ("bind", BASE + "/config"),
            ("bind", "/media/movies"), ("config", BASE + "/settings.conf"),
            ("secret", BASE + "/secret.bin")])

    def test_host_network_and_literal_dollars_are_retained_without_rewriting(self):
        model = {"services": {"sonarr": {"image": "sonarr:fixed", "network_mode": "host",
                                          "environment": {"LITERAL": "$$HOME", "EMPTY": ""},
                                          "command": ["echo", "$$$$HOME"], "entrypoint": ""}}}
        value = bundle(model)
        result = inputs.validate_compose_bundle(value)
        self.assertEqual(result.bundle.files[0].raw, value.files[0].raw)
        self.assertIn(b"$$HOME", result.bundle.files[0].raw)

    def test_no_files_environment_or_native_tools_are_consulted(self):
        value = bundle()
        with patch.dict(os.environ, {"DOCKER_HOST": "private-host", "DOCKER_CONTEXT": "private-context",
                                     "COMPOSE_FILE": "/private/other.yaml", "COMPOSE_PROJECT_NAME": "other",
                                     "COMPOSE_PROFILES": "other", "PROOF_IMAGE": "injected"}), \
                patch("builtins.open", side_effect=AssertionError("unexpected read")), \
                patch("os.open", side_effect=AssertionError("unexpected descriptor read")), \
                patch("subprocess.run", side_effect=AssertionError("unexpected tool")), \
                patch("subprocess.Popen", side_effect=AssertionError("unexpected tool")):
            result = inputs.validate_compose_bundle(value)
        self.assertEqual(result.bundle, value)

    def test_interpolation_and_supplied_environment_are_explicitly_unsupported(self):
        for expression in ("${IMAGE}", "$IMAGE", "${IMAGE:-fallback}", "$$$IMAGE", "$", "cost$5"):
            with self.subTest(expression=expression):
                self.assert_refused(bundle({"services": {"sonarr": {"image": expression}}}),
                                    "unsupported_compose_interpolation")
        for environment in ((('IMAGE', 'fixed'),), {}, None):
            self.assert_refused(bundle(interpolation_environment=environment), "unsupported_compose_interpolation")

    def test_source_dotenv_does_not_establish_interpolation_or_implicit_coverage(self):
        env = capture(".env", b"IMAGE=sonarr:fixed\n")
        self.assert_refused(bundle(extra=(env,)), "unexpected_compose_capture")
        self.assert_refused(bundle({"services": {"sonarr": {"image": "${IMAGE}"}}}, (env,)),
                            "unsupported_compose_interpolation")
        # A service may explicitly reference .env as runtime environment input.
        inputs.validate_compose_bundle(bundle({"services": {"sonarr": {"env_file": ".env"}}}, (env,)))

    def test_interpolated_disposable_proof_is_not_claimed_as_supported(self):
        proof = {"services": {"sonarr": {"image": "${PROOF_IMAGE}",
            "environment": {"PROOF_PRECEDENCE": "${CHOICE}", "PROOF_DOLLAR": "$$HOME"},
            "env_file": ["./runtime.env"], "volumes": ["./config:/config"]}}}
        self.assert_refused(bundle(proof, (capture("runtime.env", b"FIXTURE_LITERAL='kept$dollar'\n"),)),
                            "unsupported_compose_interpolation")

    def test_ambiguous_env_file_grammar_is_refused(self):
        for raw in (b"NAME", b"NAME\n", b"NAME=one\nNAME=two\n", b"NAME=$HOST\n",
                    b"NAME='literal'\n", b'NAME="literal"\n', b"export NAME=value\n",
                    b"NAME=value #comment\n", b"#comment\n", b"NAME=value\r\n",
                    b"NAME=\\escaped\n", b"NAME= leading\n", b"NAME=trailing \n",
                    b"NAME=\xff\n", b"NAME=one\0two\n", b"NAME=$$literal\n"):
            with self.subTest(raw=raw):
                self.assert_refused(bundle({"services": {"sonarr": {"env_file": "runtime.env"}}},
                                           (capture("runtime.env", raw),)), "unsupported_compose_env_file")
        inputs.validate_compose_bundle(bundle({"services": {"sonarr": {"env_file": "runtime.env"}}},
            (capture("runtime.env", b"\nEMPTY=\nNAME=internal space\nURL=http://local:8989/a=b\n"),)))

    def test_environment_inheritance_and_non_string_values_are_refused(self):
        for environment in ({"NAME": None}, {"NAME": True}, {"NAME": 1}, ["NAME"], ["NAME=explicit"]):
            self.assert_refused(bundle({"services": {"sonarr": {"environment": environment}}}))
        for env_file in ({"path": "runtime.env", "required": False}, [{"path": "runtime.env", "format": "raw"}]):
            self.assert_refused(bundle({"services": {"sonarr": {"env_file": env_file}}}))

    def test_recursive_closed_schema_rejects_external_reads_and_integration_fields(self):
        for field, value in (("include", ["other.yaml"]), ("x-custom", {}), ("version", "3.8"),
                             ("name", "other-project")):
            model = {"services": {"sonarr": {}}, field: value}
            self.assert_refused(bundle(model))
        for field, value in (("extends", {"file": "other.yaml"}), ("build", "."),
                             ("provider", {"type": "custom"}), ("post_start", [{"command": "touch file"}]),
                             ("pre_stop", []), ("label_file", "private.txt"), ("develop", {}),
                             ("x-custom", {}), ("ports", ["8989:8989"]), ("depends_on", ["other"])):
            self.assert_refused(bundle({"services": {"sonarr": {field: value}}}))
        for kind in ("configs", "secrets"):
            for body in ({"environment": "PRIVATE"}, {"external": True}, {"content": "private"},
                         {"file": "settings", "unknown": True}):
                self.assert_refused(bundle({"services": {"sonarr": {}}, kind: {"settings": body}}))
        for kind in ("volumes", "networks"):
            for body in ({"driver": "custom"}, {"driver_opts": {"device": "/private"}}, {"labels": {"x": "y"}}):
                self.assert_refused(bundle({"services": {"sonarr": {}}, kind: {"data": body}}))

    def test_json_only_duplicate_keys_and_nonstandard_numbers_are_refused(self):
        for raw, code in ((b"services:\n  sonarr:\n    image: fixed\n", "unsupported_compose_json"),
                          (b'{"services":{"sonarr":{"image":"one","image":"two"}}}', "duplicate_compose_key"),
                          (b'{"services":{},"services":{}}', "duplicate_compose_key"),
                          (b'{"services":{"sonarr":{"image":NaN}}}', "unsupported_compose_json"),
                          (b'{"services":{"sonarr":{"image":1.0}}}', "unsupported_compose_json"),
                          (b'\xff', "unsupported_compose_json"),
                          ('{"services":{}}'.encode('utf-16'), "unsupported_compose_json")):
            with self.subTest(raw=raw):
                self.assert_refused(bundle(files=(capture("compose.yaml", raw),)), code)
        self.assert_refused(bundle(files=(capture("compose.yaml", b'{"services":{"sonarr":{"image":"\\ud800"}}}'),)))

    def test_local_reference_paths_cannot_escape_or_change_interpretation(self):
        for path in ("../runtime.env", "./../runtime.env", "sub/../../runtime.env", "sub//runtime.env",
                     "sub/./runtime.env", "~/runtime.env", "https://remote/runtime.env", "git@host:repo",
                     "C:\\runtime.env", "runtime.env/", "./", "/outside/runtime.env", "/accepted/private-project2/runtime.env",
                     "//accepted/private-project/runtime.env", "./$$PATH"):
            with self.subTest(path=path):
                self.assert_refused(bundle({"services": {"sonarr": {"env_file": path}}},
                                           (capture("runtime.env", b"KEY=value\n"),)))
        value = bundle({"services": {"sonarr": {"env_file": BASE + "/runtime.env"}}},
                       (capture("runtime.env", b"KEY=value\n"),))
        inputs.validate_compose_bundle(value)

    def test_missing_surplus_duplicate_and_conflicting_capture_roles_are_refused(self):
        self.assert_refused(bundle({"services": {"sonarr": {"env_file": "missing.env"}}}), "missing_compose_capture")
        self.assert_refused(bundle(extra=(capture("unused", b"private"),)), "unexpected_compose_capture")
        self.assert_refused(bundle(extra=(capture("compose.yaml", b"private"),)), "duplicate_compose_capture")
        self.assert_refused(bundle({"services": {"sonarr": {"env_file": "compose.yaml"}}}),
                            "conflicting_compose_input_role")
        model = {"services": {"sonarr": {"env_file": "shared"}}, "configs": {"settings": {"file": "shared"}}}
        self.assert_refused(bundle(model, (capture("shared", b"NAME=value\n"),)), "conflicting_compose_input_role")
        model = {"services": {"sonarr": {}}, "secrets": {"secret": {"file": "secret"}}}
        self.assert_refused(bundle(model, (capture("secret", b"private", "nonsecret"),)),
                            "compose_secret_requires_protected_capture")

    def test_duplicate_paths_and_mount_targets_are_refused_but_shared_env_is_allowed(self):
        self.assert_refused(bundle(source_paths=(SOURCE, SOURCE)), "duplicate_compose_reference")
        model = {"services": {"sonarr": {"env_file": ["runtime.env", "./runtime.env"]}}}
        self.assert_refused(bundle(model, (capture("runtime.env", b"KEY=value\n"),)), "duplicate_compose_reference")
        model["services"]["sonarr"]["env_file"] = "runtime.env"
        model["services"]["radarr"] = {"env_file": "runtime.env"}
        result = inputs.validate_compose_bundle(bundle(model, (capture("runtime.env", b"KEY=value\n"),)))
        self.assertEqual(len(result.references), 2)
        mount = {"type": "bind", "source": "config", "target": "/config"}
        self.assert_refused(bundle({"services": {"sonarr": {"volumes": [mount, mount]}}}), "duplicate_compose_reference")

    def test_bind_paths_do_not_claim_capture_contents_or_filesystem_containment(self):
        value = bundle({"services": {"sonarr": {"volumes": [
            {"type": "bind", "source": "/nonexistent/or/symlink", "target": "/config"}]}}})
        result = inputs.validate_compose_bundle(value)
        self.assertEqual(result.references[0].path, "/nonexistent/or/symlink")
        self.assertEqual(result.as_dict()["full_input_closure"], "unverified")
        for mount in ("./config:/config", {"type": "image", "source": "image", "target": "/config"},
                      {"type": "bind", "source": "../config", "target": "/config"},
                      {"type": "bind", "source": "config", "target": "/config", "bind": {"propagation": "shared"}}):
            self.assert_refused(bundle({"services": {"sonarr": {"volumes": [mount]}}}))

    def test_service_profile_and_resource_references_require_declarations(self):
        self.assert_refused(bundle(services=("missing",)), "unknown_compose_selection")
        self.assert_refused(bundle(profiles=("missing",)), "unknown_compose_selection")
        self.assert_refused(bundle(services=()), "invalid_compose_bundle")
        self.assert_refused(bundle(services=("sonarr", "sonarr")), "duplicate_compose_reference")
        for key in ("networks", "configs", "secrets"):
            self.assert_refused(bundle({"services": {"sonarr": {key: ["missing"]}}}), "unknown_compose_reference")
        self.assert_refused(bundle({"services": {"sonarr": {"volumes": [
            {"type": "volume", "source": "missing", "target": "/data"}]}}}), "unknown_compose_reference")
        second = {"services": {"radarr": {"profiles": ["media"]}}, "networks": {"shared": {}}}
        value = bundle({"services": {"sonarr": {"networks": ["shared"]}}},
                       (capture("second.yaml", document(second)),),
                       source_paths=(SOURCE, BASE + "/second.yaml"), profiles=("media",))
        inputs.validate_compose_bundle(value)

    def test_unselected_services_are_still_checked(self):
        model = {"services": {"sonarr": {}, "unselected": {"include": "hidden.yaml", "profiles": ["disabled"]}}}
        self.assert_refused(bundle(model))

    def test_raw_json_and_mutable_input_containers_do_not_become_bundles(self):
        self.assert_refused(b'{"services":{}}', "invalid_compose_bundle")
        for changes in ({"source_paths": [SOURCE]}, {"files": list(bundle().files)}, {"profiles": []},
                        {"files": (capture("compose.yaml", bytearray(b"{}")),)},
                        {"files": (capture("compose.yaml", b"{}", "unspecified"),)},
                        {"base_directory": "/"}, {"base_directory": BASE + "/../other"},
                        {"engine": "unix:///var/run/docker.sock"}, {"project": "Other"}):
            self.assert_refused(bundle(**changes))

    def test_file_document_structure_and_reference_budgets(self):
        value = bundle()
        with patch.object(inputs, "MAX_FILE_BYTES", len(value.files[0].raw) - 1):
            self.assert_refused(value, "compose_input_limit")
        with patch.object(inputs, "MAX_BUNDLE_BYTES", len(value.files[0].raw) - 1):
            self.assert_refused(value, "compose_input_limit")
        with patch.object(inputs, "MAX_DOCUMENT_BYTES", len(value.files[0].raw) - 1):
            self.assert_refused(value, "compose_input_limit")
        with patch.object(inputs, "MAX_FILES", 0):
            self.assert_refused(value, "compose_input_limit")
        raw = b'[' * 20 + b'0' + b']' * 20
        self.assert_refused(bundle(files=(capture("compose.yaml", raw),)), "compose_input_limit")
        value = bundle({"services": {"sonarr": {"env_file": "runtime.env"}}}, (capture("runtime.env", b""),))
        with patch.object(inputs, "MAX_REFERENCES", 0):
            self.assert_refused(value, "compose_input_limit")
        with patch.object(inputs, "MAX_NODES", 1):
            self.assert_refused(value, "compose_input_limit")

    def test_private_values_never_appear_in_representations_or_summary(self):
        marker = "private-sentinel"
        model = {"services": {"sonarr": {"environment": {"SECRET": marker}, "env_file": "runtime.env"}}}
        result = inputs.validate_compose_bundle(bundle(model, (capture("runtime.env", b"TOKEN=private-sentinel\n"),)))
        for value in (result, result.bundle, result.bundle.files, result.references, result.as_dict()):
            public = repr(value)
            for private in (marker, BASE, "sonarr", "runtime.env", "accepted-project", "accepted:engine"):
                self.assertNotIn(private, public)
        summary = result.as_dict()
        summary["full_input_closure"] = "invented"
        self.assertEqual(result.as_dict()["full_input_closure"], "unverified")


if __name__ == "__main__":
    unittest.main()
