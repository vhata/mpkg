"""Join installed recording requests to inert attempt history in owned fixtures."""
import json
import os
import unittest
import uuid

from mpkg_manager import attempt_journal as journal
from mpkg_manager.store import HostStore
import test_manager_protected_recording as recording


class ExecutionFoundationIntegrationTests(unittest.TestCase):
    def test_prepared_recording_origin_survives_adoption_attempt_and_new_intent(self):
        fixture = recording.ProtectedRecordingTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original_bytes = fixture.secret.read_bytes()
        self.assertEqual(fixture.record(fixture.prepare())[0], 0)
        self.assertEqual(fixture.record(fixture.prepare(1), 1, adopt=True)[0], 0)

        with HostStore.open_existing(fixture.store, recording.HOST,
                                     owner_uid=os.geteuid()) as store:
            selected = [item["stable_id"] for item in store.current()["resources"]]
            plan = journal._fixture_plan(store, expected_revision=2,
                                         stable_resource_ids=selected)
            writer = journal._FixtureJournal(store)
            worker = journal.WorkerIdentity(os.geteuid(), os.geteuid(),
                                            str(uuid.uuid4()), str(uuid.uuid4()))
            attempt = writer.create(plan, worker, stable_resource_ids=selected).as_dict()
            context = json.loads(store._db.execute(
                "SELECT context FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0])
            self.assertEqual(context["target"]["declared_inputs"][0]["origin_revision"], 1)
            self.assertEqual(context["target"]["declared_inputs"][0]["state"], "bound")
            self.assertEqual(context["target"]["inputs"][0]["capture_id"], fixture.reference)
            for kind, outcome in (("action_started", "started"),
                                  ("command_completed", "unknown"),
                                  ("observation_completed", "failed")):
                attempt = writer.append(attempt["attempt_id"],
                    expected_sequence=attempt["sequence"],
                    action_id=attempt["actions"][0]["action_id"],
                    kind=kind, outcome=outcome).as_dict()
            self.assertEqual(attempt["state"], "unknown")
            with self.assertRaises(journal.JournalError):
                writer.append(attempt["attempt_id"], expected_sequence=attempt["sequence"],
                              action_id=None, kind="attempt_finished", outcome="failed")

        fixture.source.write_text("schema=1\ncomponents=[]\nresources=[]\n")
        self.assertEqual(fixture.invoke("record", str(fixture.source),
            "--source-is-nonsecret", "--expected-revision", "2")[0], 0)
        with HostStore.open_readonly(fixture.store, recording.HOST,
                                     owner_uid=os.geteuid()) as store:
            retained = journal.read_attempt(store, attempt["attempt_id"]).as_dict()
            self.assertEqual(retained["decision_state"], "superseded")
            self.assertEqual(retained["revision"], 2)
            self.assertEqual(retained["state"], "unknown")
            self.assertEqual(retained["events"], attempt["events"])
            self.assertFalse(retained["executable"])
            self.assertNotIn(recording.SECRET, json.dumps(retained))
            self.assertNotIn(str(fixture.inputs), json.dumps(retained))
            self.assertNotIn(fixture.reference, json.dumps(retained))
        self.assertEqual(fixture.secret.read_bytes(), original_bytes)
        self.assertEqual(fixture.invoke("history")[0], 0)


if __name__ == "__main__":
    unittest.main()
