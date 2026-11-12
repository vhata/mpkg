"""Application predicates survive actual store recording and accepted history."""
from dataclasses import replace
from datetime import datetime, timedelta
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sqlite3
import threading
import os
from pathlib import Path
import tempfile
import unittest

from mpkg_manager import application_collection as collection
from mpkg_manager import application_checks as app
from mpkg_manager.declarations import DeclarationError, canonical_json, load_declaration, validate_model
from mpkg_manager.host_policy import load_host_policy
from mpkg_manager.runtime_checks import RuntimeCheckManifest, RuntimeCheckError
from mpkg_manager.store import HostStore, StoreError
from mpkg_manager.observe_endpoint import observe_endpoint
from mpkg_manager._endpoint_process import ProbeResult
from test_manager_application_checks import Replies
from test_manager_runtime_checks import declaration, EMPTY, HOST


def source(*, name="radarr", port=18989, internal_port=None, root_id=1,
           root_path="/private/root", sentinel="Mpkg Sentinel (2000)", suffix="", metadata=True):
    doc = declaration(access=False, kind="compose", port=port)
    data = {"schema": 1, "name": name, "version": app.VERSIONS[name][0],
            "port": port if internal_port is None else internal_port}
    if name == "radarr":
        data.update(root_id=root_id, root_path=root_path, sentinel=sentinel)
    path = "/ping" if name == "sonarr" else f"/api/v3/rootfolder/{root_id}"
    raw = doc.source_bytes.decode()
    old = doc.model["checks"][0]["url"]
    raw = raw.replace(old, f"http://127.0.0.1:{port}{path}")
    if metadata:
        raw += 'application={' + ','.join(key + '=' + json.dumps(value) for key, value in data.items()) + '}\n'
    return load_declaration((raw + suffix).encode())


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.writer = HostStore.create(self.root / "store", HOST, owner_uid=os.geteuid(),
                                       engine_aliases={"local": "engine-1"})
        self.addCleanup(self.writer.close)
        self.policy_path = self.root / "policy.toml"
        self.policy_path.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{local="engine-1"}}\n'
                                    f'allowed_input_roots=["{self.root}"]\n')
        self.policy_path.chmod(0o600)
        self.policy = load_host_policy(path=self.policy_path, owner_uid=os.geteuid())
        self.addCleanup(self.policy.close)
        self.reader = self.open_reader()
        self.keys, self.workers, self.routes = [], [], []
        self.replies = Replies("radarr")

    def open_reader(self):
        reader = HostStore.open_readonly(self.root / "store", HOST, owner_uid=os.geteuid())
        self.addCleanup(reader.close)
        return reader

    def record(self, doc=None, adopt=False):
        doc = source() if doc is None else doc
        revision = self.writer.current()["revision"]
        if adopt:
            return self.writer.adopt(doc, revision, ["web"])
        return self.writer.record_intent(doc, revision)

    def context(self):
        current = self.writer.current()
        return dict(revision=current["revision"], snapshot_id=current["snapshot_id"])

    def manifest(self, **kwargs):
        return collection.application_check_manifest(self.reader, self.policy, **self.context(), **kwargs)

    def key(self, scope):
        self.keys.append(scope)
        return "PRIVATEKEY"

    def worker(self, data, key, namespace):
        self.workers.append((data, key))
        return "passed"

    def route(self, *args):
        self.routes.append(args)
        return "match"

    def collect(self, **kwargs):
        args = dict(check_applications=True, credential_resolver=self.key, query_runner=self.replies,
                    application_runner=self.worker, route_runner=self.route)
        args.update(kwargs)
        return collection.collect_application_checks(self.reader, self.policy, **self.context(), **args)

    def test_current_changes_keep_original_accepted_predicates(self):
        self.record(adopt=True)
        self.record(source(root_id=2, root_path="/new/root", sentinel="New Sentinel", internal_port=18990))
        manifest = self.manifest()
        metadata = [json.loads(raw)["context"]["check"]["application"] for raw in manifest._scopes]
        self.assertEqual([item["root_id"] for item in metadata], [1, 2])
        self.assertEqual([item["root_path"] for item in metadata], ["/private/root", "/new/root"])
        self.assertEqual([item["port"] for item in metadata], [18989, 18990])
        self.assertEqual([item["version"] for item in metadata], ["6.4.4.10685"] * 2)
        batch = self.collect()
        self.assertEqual([row["functional_result"] for row in batch.as_dict()["checks"]], ["passed", "unavailable"])
        self.assertEqual(self.workers[0][0]["root_path"], "/private/root")
        self.assertEqual(self.workers[0][0]["sentinel"], "Mpkg Sentinel (2000)")
        self.assertEqual(len(self.keys), 1)

    def test_changed_root_predicates_are_collected_separately(self):
        self.record(adopt=True)
        self.record(source(root_id=2, root_path="/new/root", sentinel="New Sentinel"))
        self.collect()
        self.assertEqual([item[0]["root_id"] for item in self.workers], [1, 2])
        self.assertEqual([item[0]["sentinel"] for item in self.workers], ["Mpkg Sentinel (2000)", "New Sentinel"])

    def test_relinquishment_removal_and_reopen_preserve_original(self):
        self.record(adopt=True)
        stable = self.writer.current()["resources"][0]["stable_id"]
        self.writer.relinquish([stable], 1)
        self.record(EMPTY)
        self.reader.close()
        self.reader = self.open_reader()
        before = {p.name: p.read_bytes() for p in (self.root / "store").iterdir()}
        batch = self.collect(selected_components=[])
        row, = batch.as_dict()["checks"]
        self.assertEqual((row["role"], row["management"], row["adoption_revision"]), ("accepted", "relinquished", 1))
        self.assertEqual(row["functional_result"], "passed")
        self.assertEqual(self.workers[0][0]["root_path"], "/private/root")
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / "store").iterdir()})
        self.assertNotIn("PRIVATEKEY", repr(batch) + json.dumps(batch.as_dict()))
        self.assertNotIn("/private/root", json.dumps(batch.as_dict()))

    def test_removing_metadata_does_not_erase_accepted_check(self):
        self.record(adopt=True)
        self.record(source(metadata=False))
        batch = self.collect()
        self.assertEqual(len(batch.as_dict()["checks"]), 1)
        self.assertEqual(batch.as_dict()["checks"][0]["role"], "accepted")

    def test_disabled_and_selected_modes_never_hide_retained_roles(self):
        self.record(adopt=True)
        batch = self.collect(check_applications=False)
        self.assertEqual(self.replies.calls, 0)
        self.assertEqual(self.keys, [])
        self.assertEqual([row["reason"] for row in batch.as_dict()["checks"]], ["collection_not_requested"] * 2)
        rows = self.collect(selected_components=[]).as_dict()["checks"]
        self.assertEqual([row["functional_result"] for row in rows], ["passed", "unavailable"])
        self.assertEqual(rows[1]["reason"], "current_not_selected")

    def test_stale_manifest_and_tampered_scope_refused_before_queries_and_keys(self):
        self.record(adopt=True)
        manifest = self.manifest()
        raw = json.loads(manifest._scopes[0])
        raw["context"]["check"]["application"]["root_path"] = "/tampered"
        scope = canonical_json(raw)
        forged = replace(manifest, _scopes=(scope,) + manifest._scopes[1:])
        for target, selected in ((forged, scope), (replace(manifest, _scopes=()), manifest._scopes[0])):
            with self.assertRaises((ValueError, RuntimeCheckError)):
                collection.observe_application(self.reader, self.policy, manifest=target, scope=selected,
                    credential=lambda: self.key(selected), query_runner=self.replies, application_runner=self.worker)
        self.record(source(suffix="# newer source\n"))
        with self.assertRaises(RuntimeCheckError):
            collection.observe_application(self.reader, self.policy, manifest=manifest, scope=manifest._scopes[0],
                credential=lambda: self.key(manifest._scopes[0]), query_runner=self.replies)
        self.assertEqual((self.replies.calls, self.keys), (0, []))

    def test_history_change_during_queries_refuses_before_credentials(self):
        self.record()
        changed = False
        def queries(*args, **kwargs):
            nonlocal changed
            result = self.replies(*args, **kwargs)
            if not changed:
                changed = True
                self.record(source(suffix="# changed\n"))
            return result
        with self.assertRaises(RuntimeCheckError):
            self.collect(query_runner=queries)
        self.assertEqual((self.keys, self.workers), ([], []))

    def test_policy_change_before_and_during_queries_refuses_credentials(self):
        self.record()
        def queries(*args, **kwargs):
            result = self.replies(*args, **kwargs)
            self.policy_path.chmod(0o644)
            return result
        with self.assertRaises(RuntimeCheckError):
            self.collect(query_runner=queries)
        self.assertEqual((self.keys, self.workers), ([], []))
        with self.assertRaises(RuntimeCheckError):
            self.collect()

    def test_result_freshness_and_complete_manifest_binding(self):
        self.record(adopt=True)
        batch = self.collect()
        manifest = self.manifest()
        when = datetime.fromisoformat(batch.observed_at)
        self.assertTrue(batch.matches_manifest(manifest, now=when))
        self.assertFalse(batch.matches_manifest(manifest, now=when + timedelta(seconds=61)))
        self.assertFalse(batch.matches_manifest(manifest, now=when - timedelta(seconds=1)))
        self.assertFalse(batch.matches_manifest(replace(manifest, _scopes=()), now=when))
        with self.assertRaises(collection.ApplicationCollectionError):
            replace(batch, _rows=batch._rows[:1])
        self.record(source(root_path="/new/root"))
        self.assertFalse(batch.matches_manifest(self.manifest()))

    def test_durable_snapshot_tampering_refused_before_delivery(self):
        self.record(adopt=True)
        manifest = self.manifest()
        with sqlite3.connect(self.root / "store" / "state.sqlite3") as database:
            sql = database.execute("SELECT sql FROM sqlite_schema WHERE name='snapshots_update'").fetchone()[0]
            database.execute("DROP TRIGGER snapshots_update")
            database.execute("UPDATE snapshots SET canonical=? WHERE id=?", (b"{}", manifest._snapshot_id))
            database.execute(sql)
        with self.assertRaises((RuntimeCheckError, StoreError)):
            collection.observe_application(self.reader, self.policy, manifest=manifest, scope=manifest._scopes[0],
                credential=lambda: self.key(manifest._scopes[0]), query_runner=self.replies)
        self.assertEqual((self.replies.calls, self.keys), (0, []))

    def test_recorded_radarr_through_real_worker_and_route(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, self.headers.get("X-Api-Key")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"id": 1, "path": "/private/root", "accessible": True,
                    "unmappedFolders": [{"name": "Mpkg Sentinel (2000)",
                                         "path": "/private/root/Mpkg Sentinel (2000)"}]}).encode())
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.record(source(port=server.server_port))
            batch = self.collect(application_runner=app.run_application, route_runner=app.published_route)
            row, = batch.as_dict()["checks"]
            self.assertEqual((row["functional_result"], row["route_result"]), ("passed", "match"))
            self.assertEqual(requests, [("/api/v3/rootfolder/1?timeout=true", "PRIVATEKEY")])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_no_application_metadata_means_no_functional_claim(self):
        self.record(source(metadata=False))
        batch = self.collect()
        self.assertEqual(batch.as_dict()["checks"], [])
        self.assertEqual((self.replies.calls, self.keys), (0, []))

    def test_changed_history_after_credential_resolution_prevents_worker(self):
        self.record()
        def key(scope):
            self.record(source(suffix="# changed during resolution\n"))
            return "PRIVATEKEY"
        with self.assertRaises(RuntimeCheckError):
            self.collect(credential_resolver=key)
        self.assertEqual(self.workers, [])


class DeclarationTests(unittest.TestCase):
    def test_closed_metadata_validation_and_backward_compatibility(self):
        for name in ("sonarr", "radarr"):
            doc = source(name=name)
            self.assertEqual(validate_model(doc.model), doc.model)
        self.assertNotIn("application", source(metadata=False).model["checks"][0])
        for key, value in (("schema", True), ("schema", 2), ("version", "latest"), ("port", True),
                           ("root_id", 0), ("root_path", "/../bad"), ("sentinel", "../bad"),
                           ("key", "PRIVATEKEY"), ("headers", {}), ("command", "anything")):
            model = source().model
            model["checks"][0]["application"][key] = value
            with self.assertRaises(DeclarationError):
                validate_model(model)
        for key, value in (("expected_status", 204), ("timeout_seconds", 11),
                           ("url", "http://127.0.0.1:18989/wrong")):
            model = source().model
            model["checks"][0][key] = value
            with self.assertRaises(DeclarationError):
                validate_model(model)

    def test_application_metadata_does_not_promote_ordinary_endpoint_result(self):
        model = source().model
        result = observe_endpoint(model["checks"][0], model["resources"][0], host_id=HOST,
            engine_aliases={"local": "engine-1"}, runner=lambda *args: ProbeResult("ok", 200))
        self.assertEqual(result.functional_result, "unverified")


if __name__ == "__main__":
    unittest.main()
