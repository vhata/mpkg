"""Recorded endpoint coverage uses private stores and owned loopback fixtures."""
from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager import endpoint_checks as collector
from mpkg_manager.declarations import load_declaration
from mpkg_manager._endpoint_process import ProbeResult
from mpkg_manager.store import HostStore


HOST = "12345678-1234-4234-8234-123456789abc"
WHEN = "2026-11-02T10:00:00Z"
PRIVATE = "private-collector-predicate"
EMPTY = load_declaration(b"schema=1\ncomponents=[]\nresources=[]\n")


def declaration(*, logical="daemon", status=200, port=12345, kind="service", alias="local",
                checks=("health",), unlinked=(), timeout=1, source_suffix="", unit="example.service"):
    identity = (f'manager="system",unit="{unit}"' if kind == "service"
                else f'engine="{alias}",project="example"')
    text = f'''schema=1
components=[]
[[resources]]
id="{logical}"
kind="{kind}"
identity={{{identity}}}
checks={json.dumps(list(checks))}
'''
    for name in (*checks, *unlinked):
        text += f'''[[checks]]
id="{name}"
kind="endpoint"
resource="{logical}"
url="http://127.0.0.1:{port}/{PRIVATE}/{name}"
expected_status={status}
timeout_seconds={timeout}
'''
    return load_declaration((text + source_suffix).encode())


class EndpointCheckCollectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "records"
        self.store = HostStore.create(self.directory, HOST, owner_uid=os.geteuid(),
                                     engine_aliases={"local": "fixture-engine", "alias": "fixture-engine"})
        self.addCleanup(self.store.close)
        self.calls = []

    def runner(self, url, timeout):
        self.calls.append((url, timeout))
        return ProbeResult("ok", 200)

    def collect(self, **kwargs):
        current = self.store.current()
        with patch.object(collector, "utc_now", return_value=WHEN):
            return collector.collect_endpoint_checks(
                self.store, revision=current["revision"], snapshot_id=current["snapshot_id"],
                runner=kwargs.pop("runner", self.runner), **kwargs)

    def assert_error(self, code, callback):
        with self.assertRaises(collector.EndpointCollectionError) as raised:
            callback()
        self.assertEqual(str(raised.exception), code)
        self.assertEqual(raised.exception.code, code)

    def test_identical_current_and_accepted_predicates_share_one_probe_without_losing_roles(self):
        original = declaration()
        decision = self.store.adopt(original, 0, ["daemon"])
        batch = self.collect()
        public = batch.as_dict()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(batch.probe_count, 1)
        self.assertEqual([row["role"] for row in public["checks"]], ["accepted", "current"])
        self.assertTrue(all(row["route_result"] == "match" for row in public["checks"]))
        self.assertIs(batch.checks[0].observation, batch.checks[1].observation)
        self.assertTrue(batch.matches_context(host_id=HOST, revision=1, snapshot_id=decision["snapshot_id"]))
        self.assertFalse(batch.matches_context(host_id=HOST, revision=2, snapshot_id=decision["snapshot_id"]))
        self.assertTrue(all(row.functional_result == "unverified" for row in batch.checks))
        self.assertTrue(all(row.limitations == collector.LIMITATIONS for row in batch.checks))
        self.assertFalse(public["executable"])
        self.assertTrue(public["coverage_complete"])

    def test_same_id_changed_predicate_gets_distinct_accepted_and_current_observations(self):
        original = declaration()
        first = self.store.adopt(original, 0, ["daemon"])
        latest = self.store.record_intent(declaration(status=204), 1)
        batch = self.collect()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([row.as_dict()["route_result"] for row in batch.checks], ["match", "mismatch"])
        accepted = batch.checks[0]
        record = self.store.current()["resources"][0]
        context = dict(host_id=HOST, role="accepted", snapshot_id=first["snapshot_id"],
                       adoption_revision=1, stable_id=record["stable_id"])
        self.assertTrue(accepted.matches_context(original.model["checks"][0], original.model["resources"][0], **context))
        self.assertFalse(accepted.matches_context(declaration(status=204).model["checks"][0],
                                                 original.model["resources"][0], **context))
        self.assertFalse(accepted.matches_context(original.model["checks"][0], original.model["resources"][0],
                                                 **(context | {"snapshot_id": latest["snapshot_id"]})))
        self.assertFalse(accepted.matches_context(original.model["checks"][0], original.model["resources"][0],
                                                 **(context | {"role": "current"})))

    def test_removed_and_relinquished_accepted_checks_remain_explicit(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        stable = self.store.current()["resources"][0]["stable_id"]
        self.store.relinquish([stable], 1)
        self.store.record_intent(EMPTY, 2)
        batch = self.collect()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(batch.checks), 1)
        row = batch.checks[0].as_dict()
        self.assertEqual((row["role"], row["management"], row["adoption_revision"]), ("accepted", "relinquished", 1))
        self.assertEqual(row["stable_id"], stable)
        self.assertEqual(row["functional_result"], "unverified")

    def test_logical_rename_preserves_original_accepted_labels_and_physical_binding(self):
        self.store.adopt(declaration(), 0, ["daemon"])
        self.store.record_intent(declaration(logical="renamed"), 1)
        batch = self.collect()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([row.as_dict()["resource_id"] for row in batch.checks], ["daemon", "renamed"])
        self.assertEqual([row.observation.as_dict()["resource_id"] for row in batch.checks], ["daemon", "renamed"])

    def test_unreferenced_root_checks_never_get_probed(self):
        self.store.record_intent(declaration(checks=(), unlinked=("unused",)), 0)
        self.assertEqual(self.collect().checks, ())
        self.assertEqual(self.calls, [])

    def test_count_and_time_limits_keep_complete_unavailable_coverage(self):
        self.store.record_intent(declaration(checks=("first", "second", "third")), 0)
        batch = self.collect(max_probes=1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([row.as_dict()["reason"] for row in batch.checks],
                         ["status_matches", "collection_probe_limit", "collection_probe_limit"])
        self.calls.clear()
        with patch.object(collector.time, "monotonic", return_value=0):
            batch = self.collect(budget_seconds=1, runner=lambda url, timeout: ProbeResult("timeout"))
        self.assertEqual(batch.probe_count, 3)
        self.assertTrue(all(row.observation.reason == "timeout" for row in batch.checks))
        clock = [0]
        def consume(url, timeout):
            self.calls.append((url, timeout))
            clock[0] += 0.6
            return ProbeResult("ok", 200)
        with patch.object(collector.time, "monotonic", side_effect=lambda: clock[0]):
            batch = self.collect(budget_seconds=1, runner=consume)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][1], 1)
        self.assertEqual([row.as_dict()["reason"] for row in batch.checks],
                         ["status_matches", "collection_budget_exhausted", "collection_budget_exhausted"])

    def test_changed_revision_returns_no_batch(self):
        self.store.record_intent(declaration(), 0)
        def change(url, timeout):
            self.store.record_intent(EMPTY, 1)
            return ProbeResult("ok", 200)
        self.assert_error("endpoint_revision_changed", lambda: self.collect(runner=change))

    def test_public_projection_is_immutable_and_redacts_predicates_and_snapshot_digests(self):
        decision = self.store.adopt(declaration(), 0, ["daemon"])
        batch = self.collect()
        public = batch.as_dict()
        encoded = json.dumps(public) + repr(batch)
        for value in (PRIVATE, decision["snapshot_id"], "expected_status", "url", "example.service"):
            self.assertNotIn(value, encoded)
        self.assertEqual(public["observed_at"], WHEN)
        public["checks"][0]["limitations"].clear()
        public["checks"].clear()
        self.assertEqual(len(batch.as_dict()["checks"]), 2)
        self.assertTrue(batch.as_dict()["checks"][0]["limitations"])
        with self.assertRaises(FrozenInstanceError):
            batch.probe_count = 7
        with self.assertRaises(FrozenInstanceError):
            batch.checks[0].unavailable_reason = "changed"
