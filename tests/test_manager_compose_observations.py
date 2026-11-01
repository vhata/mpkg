"""Compose observations use synthetic responses and private local children."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from mpkg_manager.declarations import load_declaration
from mpkg_manager.observe_compose import (
    CONTAINER_FORMAT, CONTAINER_QUERY, DOCKER, ENGINE_QUERY, ENVIRONMENT,
    IMAGE_FORMAT, IMAGE_QUERY, LIST_QUERY, MAX_OUTPUT, PROJECT_FILTER,
    ComposeInventory, observe_compose, run_readonly,
)
from mpkg_manager.query_process import QueryResult


HOST = "98d1f834-494b-4a5e-bad0-ab8fb03fecb2"
WHEN = "2026-11-01T23:00:00Z"
ENGINE = "local-engine-accepted-by-trusted-context"
CID = "a" * 64
SECOND = "b" * 64
IMAGE = "sha256:" + "c" * 64
NETWORK = "d" * 64
DIGEST = "example.org/app@sha256:" + "e" * 64
SECRET = "private-credential-sentinel-must-not-export"
LIST = LIST_QUERY + (PROJECT_FILTER + "example",)


def resource(**desired):
    return {"id": "deployment", "kind": "compose",
            "identity": {"engine": "local", "project": "example"},
            "desired": {"services": ["app"], **desired}}


def container(**changes):
    return {"id": CID, "image_id": IMAGE, "status": "running", "running": True,
            "started_at": "2026-11-01T21:00:00.123456789Z",
            "finished_at": "0001-01-01T00:00:00Z", "project": "example",
            "service": "app", "number": "1", "oneoff": "False",
            "mounts": [{"type": "bind", "source": "/srv/media", "target": "/media",
                        "name": None, "driver": None, "rw": False},
                       {"type": "volume", "source": "/var/lib/docker/volumes/config/_data",
                        "target": "/config", "name": "config", "driver": "local", "rw": True}],
            "networks": [{"name": "example_default", "id": NETWORK}], **changes}


def image(**changes):
    return {"id": IMAGE, "os": "linux", "architecture": "amd64", "variant": None,
            "repository_digests": [DIGEST], **changes}


def encoded(value):
    return json.dumps(value).encode()


class Queries:
    def __init__(self, containers=None, images=None, overrides=None):
        self.containers = containers if containers is not None else {CID: container()}
        self.images = images if images is not None else {IMAGE: image()}
        self.overrides = deepcopy(overrides or {})
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        if argv in self.overrides:
            value = self.overrides[argv].pop(0)
            return value if isinstance(value, QueryResult) else QueryResult("ok", value)
        if argv == ENGINE_QUERY:
            value = encoded(ENGINE)
        elif argv == LIST:
            value = "".join(key + "\n" for key in self.containers).encode()
        elif argv[:-1] == CONTAINER_QUERY:
            value = encoded(self.containers[argv[-1]])
        elif argv[:-1] == IMAGE_QUERY:
            value = encoded(self.images[argv[-1]])
        else:
            raise AssertionError("unexpected query")
        return QueryResult("ok", value)


class ComposeObservationTests(unittest.TestCase):
    def observe(self, runner=None, declaration=None):
        return observe_compose(declaration or resource(), host_id=HOST,
                               accepted_engine_id=ENGINE, runner=runner or Queries(), observed_at=WHEN)

    def facts(self, inventory):
        return {fact.property: fact for fact in inventory.observations.facts}

    def assert_unknown(self, inventory, reason):
        projection = inventory.as_dict()
        self.assertEqual(projection["state"], "unknown")
        self.assertEqual(projection["reason"], reason)
        self.assertEqual(projection["containers"], [])
        self.assertTrue(all(f.state == "unknown" for f in inventory.observations.facts))
        self.assertNotIn(SECRET, json.dumps(projection))
        self.assertNotIn(SECRET, repr(inventory))

    def test_selected_inventory_is_immutable_and_preserves_identity_distinctions(self):
        runner = Queries()
        inventory = self.observe(runner)
        result = inventory.as_dict()
        self.assertEqual(result["state"], "known")
        self.assertEqual(result["accepted_engine_id"], ENGINE)
        self.assertEqual(result["images"][0]["id"], IMAGE)
        self.assertEqual(result["images"][0]["repository_digests"], [DIGEST])
        self.assertEqual(result["images"][0]["registry_platform_binding"], "unknown")
        self.assertEqual(result["images"][0]["architecture"], "amd64")
        self.assertTrue(self.facts(inventory)["running"].value)
        for prop in ("input_closure", "images", "health"):
            self.assertEqual(self.facts(inventory)[prop].state, "unknown")
        self.assertEqual(runner.calls.count(LIST), 2)
        self.assertEqual(runner.calls[0], ENGINE_QUERY)
        self.assertEqual(runner.calls[-1], ENGINE_QUERY)
        self.assertEqual(runner.calls.count(CONTAINER_QUERY + (CID,)), 2)
        result["containers"][0]["mounts"][0]["source"] = "changed"
        self.assertNotIn("changed", inventory.as_dict()["containers"][0]["mounts"][0].values())
        with self.assertRaises(FrozenInstanceError):
            inventory.inventory_bytes = b"{}"
        with self.assertRaisesRegex(ValueError, "invalid_compose_inventory"):
            ComposeInventory(inventory.observations, b'{"observations":null}')

    def test_stopped_and_absent_containers_are_distinct_from_unavailable_evidence(self):
        stopped = self.observe(Queries(containers={CID: container(status="exited", running=False)}))
        self.assertTrue(self.facts(stopped)["present"].value)
        self.assertIs(self.facts(stopped)["running"].value, False)
        empty = self.observe(Queries(containers={}))
        self.assertIs(self.facts(empty)["present"].value, False)
        self.assertEqual(self.facts(empty)["container_count"].value, 0)
        self.assertEqual(self.facts(empty)["running"].state, "unknown")
        for code in ("permission_denied", "tool_unavailable", "command_failed", "timeout"):
            with self.subTest(code=code):
                self.assert_unknown(self.observe(Queries(overrides={LIST: [QueryResult(code)]})), code)

    def test_accepted_engine_is_checked_before_and_after_and_never_adopted(self):
        runner = Queries(overrides={ENGINE_QUERY: [encoded("wrong-engine")]})
        self.assert_unknown(self.observe(runner), "engine_identity_mismatch")
        self.assertEqual(runner.calls, [ENGINE_QUERY])
        runner = Queries(overrides={ENGINE_QUERY: [encoded(ENGINE), encoded("changed-engine")]})
        self.assert_unknown(self.observe(runner), "engine_identity_changed")
        self.assertEqual(runner.calls[-1], ENGINE_QUERY)

    def test_duplicate_truncated_excessive_and_changing_container_lists_are_unknown(self):
        for raw in ((CID + "\n" + CID + "\n").encode(), b"short-id\n",
                    "\n".join(f"{number:064x}" for number in range(65)).encode()):
            with self.subTest(raw=raw[:80]):
                self.assert_unknown(self.observe(Queries(overrides={LIST: [raw]})), "container_inventory_invalid")
        changed = Queries(overrides={LIST: [(CID + "\n").encode(), b""]})
        self.assert_unknown(self.observe(changed), "compose_inventory_changed")

    def test_identity_attribution_and_restarted_container_metadata_must_match(self):
        for changes, reason in (({"id": SECOND}, "container_identity_mismatch"),
                                ({"project": "other"}, "container_identity_mismatch"),
                                ({"service": None}, "compose_attribution_unavailable"),
                                ({"number": ""}, "compose_attribution_unavailable"),
                                ({"oneoff": ""}, "compose_attribution_unavailable")):
            with self.subTest(changes=changes):
                self.assert_unknown(self.observe(Queries(containers={CID: container(**changes)})), reason)
        runner = Queries(overrides={CONTAINER_QUERY + (CID,):
                         [encoded(container()), encoded(container(started_at="2026-11-01T22:00:00Z"))]})
        self.assert_unknown(self.observe(runner), "compose_inventory_changed")

    def test_duplicate_service_numbers_are_ambiguous_and_replicas_are_explicit(self):
        runner = Queries(containers={CID: container(), SECOND: container(id=SECOND)})
        self.assert_unknown(self.observe(runner), "duplicate_compose_service_identity")
        runner = Queries(containers={CID: container(), SECOND: container(id=SECOND, number="2")})
        inventory = self.observe(runner)
        self.assertEqual(self.facts(inventory)["container_count"].value, 2)
        self.assertEqual(self.facts(inventory)["running"].limitations, ("compose_replica_scope_unresolved",))

    def test_aggregate_running_requires_exact_service_scope_and_no_oneoff_or_orphan(self):
        runner = Queries(containers={CID: container(), SECOND: container(id=SECOND, service="worker")})
        inventory = self.observe(runner, resource(services=["app", "worker"]))
        self.assertIs(self.facts(inventory)["running"].value, True)
        for declaration, changes in ((resource(), {"service": "orphan"}),
                                     (resource(services=[]), {}),
                                     (resource(), {"oneoff": "True"}),
                                     (resource(services=["app", "missing"]), {})):
            with self.subTest(declaration=declaration, changes=changes):
                inventory = self.observe(Queries(containers={CID: container(**changes)}), declaration)
                self.assertEqual(self.facts(inventory)["running"].state, "unknown")
                self.assertEqual(inventory.as_dict()["state"], "known")

    def test_transitional_and_mixed_states_are_not_running_success(self):
        for status in ("paused", "restarting", "removing"):
            inventory = self.observe(Queries(containers={CID: container(status=status)}))
            self.assertEqual(self.facts(inventory)["running"].state, "unknown")
        runner = Queries(containers={CID: container(), SECOND: container(
            id=SECOND, service="worker", status="exited", running=False)})
        self.assertEqual(self.facts(self.observe(runner, resource(services=["app", "worker"])))
                         ["running"].state, "unknown")
        invalid = Queries(containers={CID: container(status="running", running=False)})
        self.assert_unknown(self.observe(invalid), "container_state_unavailable")
        invalid = Queries(containers={CID: container(started_at="2026-99-99T99:99:99Z")})
        self.assert_unknown(self.observe(invalid), "container_state_unavailable")

    def test_attachment_identities_have_known_project_consumers_and_explicit_limits(self):
        runner = Queries(containers={CID: container(), SECOND: container(id=SECOND, service="worker")})
        projection = self.observe(runner).as_dict()
        self.assertFalse(projection["consumers_exhaustive"])
        self.assertEqual(projection["consumer_scope"], "project_labelled_containers_including_stopped")
        for key in ("binds", "volumes", "networks"):
            self.assertEqual(projection[key][0]["observed_container_ids"], [CID, SECOND])
        self.assertEqual(projection["volumes"][0]["name"], "config")
        self.assertEqual(projection["networks"][0]["id"], NETWORK)
        self.assertNotIn("/var/lib/docker", json.dumps(projection))
        self.assertIn("mount_paths_not_resolved_host_file_identities", projection["limitations"])

    def test_missing_conflicting_and_unsafe_attachment_identity_is_unknown(self):
        for field in ("mounts", "networks"):
            self.assert_unknown(self.observe(Queries(containers={CID: container(**{field: None})})),
                                "container_attachment_scope_unsupported")
        bad_mounts = [container()["mounts"][0] | {"source": "/srv/../private"},
                      container()["mounts"][0] | {"source": "/bad\ud800"},
                      container()["mounts"][1] | {"name": None}]
        for mount in bad_mounts:
            with self.subTest(mount=mount):
                self.assert_unknown(self.observe(Queries(containers={CID: container(mounts=[mount])})),
                                    "mount_identity_unavailable")
        self.assert_unknown(self.observe(Queries(containers={CID: container(networks=[
            {"name": "example_default", "id": ""}])})), "network_identity_unavailable")
        runner = Queries(containers={CID: container(), SECOND: container(
            id=SECOND, service="worker", networks=[{"name": "example_default", "id": "f" * 64}])})
        self.assert_unknown(self.observe(runner), "attachment_identity_inconsistent")

    def test_image_platform_and_identity_are_required_but_registry_binding_stays_unknown(self):
        for changes, reason in (({"architecture": ""}, "image_platform_unavailable"),
                                ({"os": None}, "image_platform_unavailable"),
                                ({"id": "sha256:" + "f" * 64}, "image_identity_mismatch")):
            with self.subTest(changes=changes):
                self.assert_unknown(self.observe(Queries(images={IMAGE: image(**changes)})), reason)
        projection = self.observe(Queries(images={IMAGE: image(repository_digests=None)})).as_dict()
        self.assertEqual(projection["images"][0]["repository_digests"], [])
        self.assertEqual(projection["images"][0]["registry_platform_binding"], "unknown")
        runner = Queries(overrides={IMAGE_QUERY + (IMAGE,):
                         [encoded(image()), encoded(image(architecture="arm64"))]})
        self.assert_unknown(self.observe(runner), "compose_inventory_changed")

    def test_malformed_incomplete_duplicate_and_private_fields_never_escape(self):
        raw = encoded(container())
        missing = container()
        del missing["mounts"]
        values = [b"{invalid " + SECRET.encode(), raw[:-1] + b',"id":"' + SECRET.encode() + b'"}',
                  encoded(container() | {"Config": {"Env": [SECRET]}}),
                  encoded(container() | {"State.Error": SECRET}), encoded(missing),
                  encoded(container(running=SECRET)), b"[" * 2000]
        for value in values:
            with self.subTest(raw=value[:50]):
                result = self.observe(Queries(overrides={CONTAINER_QUERY + (CID,): [value]}))
                self.assertEqual(result.as_dict()["state"], "unknown")
                self.assertNotIn(SECRET, json.dumps(result.as_dict()))
                self.assertNotIn(SECRET, repr(result))

    def test_output_and_collection_deadlines_report_unknown(self):
        self.assert_unknown(self.observe(Queries(overrides={ENGINE_QUERY: [b"x" * (MAX_OUTPUT + 1)]})),
                            "output_limit")
        with patch("mpkg_manager.observe_compose.time.monotonic", side_effect=[0, 0, 61]):
            self.assert_unknown(self.observe(), "compose_observation_timeout")
        with patch("mpkg_manager.observe_compose.MAX_TOTAL_OUTPUT", 1):
            self.assert_unknown(self.observe(), "output_limit")

    def test_valid_but_unsupported_declared_project_is_unknown_without_query(self):
        declaration = load_declaration(b'''schema=1
components=[]
[[resources]]
id="deployment"
kind="compose"
identity={engine="local",project="UpperCase"}
desired={services=["app"],running=true}
''')
        runner = Queries()
        self.assert_unknown(self.observe(runner, declaration.model["resources"][0]),
                            "compose_project_identity_unsupported")
        self.assertEqual(runner.calls, [])

    def test_invalid_caller_binding_is_rejected_before_queries(self):
        runner = Queries()
        with self.assertRaisesRegex(ValueError, "invalid_compose_observation_context"):
            observe_compose(resource(), host_id=HOST, accepted_engine_id="tcp://remote",
                            runner=runner, observed_at=WHEN)
        self.assertEqual(runner.calls, [])


class DockerQueryBoundaryTests(unittest.TestCase):
    def test_only_fixed_queries_and_local_endpoint_are_allowed(self):
        forbidden = [DOCKER + (verb,) for verb in ("run", "start", "stop", "restart", "rm", "pull", "build")]
        forbidden += [DOCKER + ("compose", "config"), DOCKER + ("system", "prune"),
                      DOCKER + ("volume", "rm", "config"), DOCKER + ("network", "rm", "network"),
                      ("docker", "info"), ("/usr/bin/sudo", "docker", "info"),
                      ENGINE_QUERY + ("--context", "other"), CONTAINER_QUERY + ("--help",),
                      LIST_QUERY + (PROJECT_FILTER + "example,other",),
                      DOCKER + ("container", "inspect", CID),
                      tuple(arg.replace("unix:///run/docker.sock", "tcp://remote") for arg in ENGINE_QUERY)]
        with patch("mpkg_manager.query_process.subprocess.Popen") as spawn:
            for argv in forbidden:
                with self.subTest(argv=argv):
                    self.assertEqual(run_readonly(argv).code, "invalid_query")
            spawn.assert_not_called()
        for excluded in ("Config.Env", "Health.Log", "State.Error", ".Args", "{{json .Config.Labels}}"):
            self.assertNotIn(excluded, CONTAINER_FORMAT + IMAGE_FORMAT)

    def child(self, code, **bounds):
        real_popen = subprocess.Popen
        seen = []

        def launch(argv, **kwargs):
            seen.append((argv, kwargs))
            return real_popen([sys.executable, "-c", code], **kwargs)

        with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=launch):
            result = run_readonly(ENGINE_QUERY, **bounds)
        self.assertEqual(seen[0][0], ENGINE_QUERY)
        self.assertEqual(seen[0][1]["env"], ENVIRONMENT)
        self.assertTrue(seen[0][1]["start_new_session"])
        self.assertNotIn("shell", seen[0][1])
        return result

    def test_local_queries_ignore_user_docker_proxy_tls_loader_and_secret_environment(self):
        keys = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH", "HTTP_PROXY", "HTTPS_PROXY", "LD_PRELOAD", "TOKEN")
        with patch.dict(os.environ, dict.fromkeys(keys, SECRET)):
            result = self.child("import os,json; print(json.dumps(dict(os.environ)))")
        self.assertEqual(result.code, "ok")
        self.assertNotIn(SECRET.encode(), result.output)
        self.assertEqual(json.loads(result.output), ENVIRONMENT)
        self.assertIn("/dev/null", ENGINE_QUERY)

    def test_timeout_output_and_nonzero_errors_are_private(self):
        failed = self.child(f"import sys; print({SECRET!r}); print({SECRET!r},file=sys.stderr);sys.exit(9)")
        self.assertEqual(failed.code, "command_failed")
        self.assertEqual(failed.output, b"")
        self.assertNotIn(SECRET, repr(failed))
        self.assertEqual(self.child("import time; time.sleep(2)", timeout=0.05).code, "timeout")
        self.assertEqual(self.child("import os;os.write(2,b'x'*10000)", max_output=1024).code, "output_limit")
        with patch("mpkg_manager.query_process.subprocess.Popen", side_effect=OSError(SECRET)):
            self.assertEqual(run_readonly(ENGINE_QUERY), QueryResult("start_failed"))


if __name__ == "__main__":
    unittest.main()
