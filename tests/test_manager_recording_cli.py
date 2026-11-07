"""Recording CLI through owned fixtures and substituted transport, never sudo."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import pty
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mpkg_manager.cli import main
from mpkg_manager.host_client import (HostClientError, _Reply, _TransportFailure,
                                      _authorize, _exchange, request_host)
from mpkg_manager.host_helper import HostBoundary, handle_request
from mpkg_manager.host_protocol import parse_request


HOST = "12345678-1234-4234-8234-123456789abc"
EMPTY = 'schema=1\ncomponents=[]\nresources=[]\n'
SENTINEL = "PRIVATE_RECORDING_SENTINEL"
FILE = f'''schema=1
components=[]
[[resources]]
id="config"
kind="file"
purpose="{SENTINEL}"
identity={{path="/{SENTINEL}/config"}}
manage=["present"]
desired={{present=true}}
'''


def wire(operation, **arguments):
    return json.dumps({"version": 1, "verb": "export" if operation in {"current", "history"} else "record",
                       "arguments": {"operation": operation, **arguments}}).encode()


def reply(result, returncode=0):
    return _Reply(json.dumps({"version": 1, "ok": True, "result": result}).encode(), returncode)


def failure(code, returncode=2):
    return _Reply(json.dumps({"version": 1, "ok": False, "error": {"code": code}}).encode(), returncode)


class RecordingCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = self.root / "policy.toml"
        self.policy.write_text(f'schema=1\nhost_id="{HOST}"\nengine_aliases={{}}\n'
                               f'allowed_input_roots={json.dumps([str(self.root)])}\n')
        self.policy.chmod(0o600)
        self.runtime = self.root / "run"
        self.runtime.mkdir(mode=0o700)
        self.lock = self.runtime / "apply.lock"
        self.lock.touch(mode=0o600)
        self.boundary = HostBoundary(policy_path=self.policy, store_directory=self.root / "store",
                                     mutation_lock=self.lock, owner_uid=os.geteuid())
        self.source = self.root / SENTINEL
        self.source.write_bytes(FILE.encode())
        self.sent = []

    def sender(self, raw):
        self.sent.append(raw)
        raw = handle_request(raw, boundary=self.boundary)
        return _Reply(raw, 0 if json.loads(raw)["ok"] else 2)

    def invoke(self, *arguments, sender=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch("subprocess.Popen", side_effect=AssertionError("unexpected subprocess")):
            code = main(list(arguments), _sender=self.sender if sender is None else sender)
        output = stdout.getvalue()
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(SENTINEL, output)
        self.assertNotIn(str(self.source), output)
        return code, output

    def json(self, *arguments, **kwargs):
        code, output = self.invoke(*arguments, "--json", **kwargs)
        return code, json.loads(output)

    def record(self, command="record", revision=0, *extra):
        return self.json(command, str(self.source), "--source-is-nonsecret",
                         "--expected-revision", str(revision), *extra)

    def test_full_recording_flow_preserves_source_retention_and_explicit_revisions(self):
        code, result = self.json("current")
        self.assertEqual((code, result["error"]["code"]), (6, "store_missing"))
        self.assertFalse((self.root / "store").exists())
        self.assertEqual(self.json("init")[0], 0)
        self.assertEqual(self.record()[0], 0)
        self.assertEqual(parse_request(self.sent[-1]).source, FILE.encode())
        code, current = self.json("current")
        self.assertEqual((code, current["result"]["revision"], current["result"]["resources"]), (0, 1, []))
        self.assertEqual(self.record("adopt", 1, "--resource", "config")[0], 0)
        current = self.json("current")[1]["result"]
        stable_id = current["resources"][0]["stable_id"]
        self.assertEqual(current["resources"][0]["observation"], {"state": "unknown", "reason": "not_observed"})
        self.source.write_text(EMPTY)
        self.assertEqual(self.record(revision=2)[0], 0)
        resource = self.json("current")[1]["result"]["resources"][0]
        self.assertTrue(resource["pending_disposition"])
        self.assertEqual(resource["stable_id"], stable_id)
        code, rejected = self.json("relinquish", "--resource", stable_id, "--expected-revision", "2")
        self.assertEqual((code, rejected["category"], rejected["error"]["code"]),
                         (6, "rejected", "revision_conflict"))
        self.assertEqual(self.json("relinquish", "--resource", stable_id, "--expected-revision", "3")[0], 0)
        current = self.json("current")[1]["result"]
        self.assertEqual(current["revision"], 4)
        self.assertEqual(current["resources"][0]["management"], "relinquished")
        history = self.json("history")[1]["result"]["decisions"]
        self.assertEqual([item["kind"] for item in history], ["intent", "adopt", "intent", "relinquish"])

    def test_human_current_has_stable_selection_ids_and_unknown_observation(self):
        self.json("init")
        self.record("adopt", 0, "--resource", "config")
        code, output = self.invoke("current")
        stable_id = self.json("current")[1]["result"]["resources"][0]["stable_id"]
        self.assertEqual(code, 0)
        self.assertIn(stable_id, output)
        self.assertIn("recorded revision 1", output)
        self.assertIn("Live state has not been observed", output)
        code, output = self.invoke("history")
        self.assertEqual(code, 0)
        self.assertIn("Revision 1: adopt", output)

    def test_initialization_refuses_existing_without_repair_or_retry(self):
        self.assertEqual(self.json("init")[0], 0)
        before = self.json("history")[1]
        code, result = self.json("init")
        self.assertEqual((code, result["error"]["code"]), (6, "store_exists"))
        self.assertEqual(self.json("history")[1], before)
        self.assertEqual(len(self.sent), 4)

    def test_source_acknowledgment_revision_and_selection_are_required(self):
        base = ["record", str(self.source)]
        cases = [base, base + ["--expected-revision", "0"],
                 base + ["--source-is-nonsecret"],
                 ["adopt", str(self.source), "--source-is-nonsecret", "--expected-revision", "0"],
                 ["relinquish", "--expected-revision", "0"],
                 ["relinquish", "--resource", HOST],
                 base + ["--source-is-nonsecret", "--expected-revision", "auto"]]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                self.assertEqual(self.json(*arguments)[0], 2)
        self.assertEqual(self.sent, [])

    def test_revision_scalar_bounds_are_checked_before_transport(self):
        for revision in ("-1", "+1", "1.0", "true", "1_000", "１２", str(2**63 - 1), "9" * 5000):
            with self.subTest(revision=revision[:20]):
                self.assertEqual(self.json("record", str(self.source), "--source-is-nonsecret",
                                           "--expected-revision", revision)[0], 2)
        self.assertEqual(self.sent, [])

    def test_exact_utf8_bytes_including_crlf_and_comments_are_sent_once(self):
        raw = FILE.replace("\n", "\r\n").encode() + "# å comment\r\n".encode()
        self.source.write_bytes(raw)
        self.json("init")
        self.assertEqual(self.record()[0], 0)
        self.assertEqual(parse_request(self.sent[-1]).source, raw)
        self.assertEqual(len(self.sent), 2)
        self.assertTrue(json.loads(self.sent[-1])["arguments"]["source_is_nonsecret"])

    def test_invalid_and_unavailable_sources_never_reach_transport(self):
        self.source.write_text(SENTINEL + "=true")
        code, result = self.record()
        self.assertEqual((code, result["category"]), (2, "validation"))
        self.source.unlink()
        self.assertEqual(self.record()[0], 3)
        self.assertEqual(self.sent, [])

    def test_nonregular_source_is_refused_without_opening_reference_files(self):
        self.source.unlink()
        os.mkfifo(self.source)
        self.assertEqual(self.record()[0], 2)
        self.source.unlink()
        self.source.symlink_to(self.policy)
        self.assertEqual(self.record()[0], 3)
        self.assertEqual(self.sent, [])

    def test_protected_source_has_explicit_fixed_refusal(self):
        self.source.write_text(EMPTY + f'''[[inputs]]
id="private"
base_directory="/{SENTINEL}"
files=[{{path="secret.env",classification="protected",reference="{HOST}"}}]
''')
        code, result = self.record()
        self.assertEqual((code, result["error"]["code"]), (2, "protected_preparation_required"))
        self.assertEqual(self.sent, [])

    def test_selection_validation_rejects_duplicates_unknown_ids_and_logical_relinquishment(self):
        for ids in (["missing"], ["config", "config"]):
            extra = [argument for identity in ids for argument in ("--resource", identity)]
            self.assertEqual(self.record("adopt", 0, *extra)[0], 2)
        self.assertEqual(self.json("relinquish", "--resource", "config", "--expected-revision", "0")[0], 2)
        self.assertEqual(self.sent, [])

    def test_no_privileged_configuration_or_unimplemented_verbs_are_exposed(self):
        for command in ("observe", "plan", "apply", "prepare", "recover"):
            self.assertEqual(self.json(command)[0], 2)
        for flag in ("helper", "helper-path", "store", "policy", "uid", "env", "program", "sender"):
            self.assertEqual(self.json("init", "--" + flag, SENTINEL)[0], 2)
        self.assertEqual(self.sent, [])

    def test_unknown_mutation_result_is_not_retried_or_described_as_rejection(self):
        calls = []
        def sender(raw):
            calls.append(raw)
            return failure("record_outcome_unknown")
        code, result = self.json("init", sender=sender)
        self.assertEqual((code, result["category"]), (7, "uncertain"))
        self.assertIn("inspect_current_and_history", result["next_step"])
        self.assertEqual(len(calls), 1)
        code, output = self.invoke("init", sender=sender)
        self.assertEqual(code, 7)
        self.assertIn("helper may still be running", output)

    def test_validated_declaration_command_keeps_its_existing_contract(self):
        code, result = self.json("validate", str(self.source))
        self.assertEqual(code, 0)
        self.assertTrue(result["valid"])
        self.assertEqual(result["application"], "not_implemented")
        self.assertEqual(self.sent, [])


class ResponseTests(unittest.TestCase):
    def assert_failure(self, raw, response, code, category):
        with self.assertRaises(HostClientError) as caught:
            request_host(raw, _sender=lambda request: response)
        self.assertEqual((caught.exception.exit_status, caught.exception.category), (code, category))
        self.assertNotIn(SENTINEL, str(caught.exception))

    def test_malformed_foreign_and_wrong_status_responses_are_uncertain_for_mutations(self):
        invalid = [b"", SENTINEL.encode(), b'{} {}', b'\xff', b'[' * 2000,
                   b'{"ok":true,"ok":true,"version":1,"result":{}}',
                   json.dumps({"version": 1, "ok": False, "error": {"code": SENTINEL}}).encode(),
                   json.dumps({"version": True, "ok": True, "result": {}}).encode(),
                   json.dumps({"version": 1, "ok": True, "result": {"source": SENTINEL}}).encode()]
        for response in [_Reply(raw, 0) for raw in invalid] + [
                reply({"host_id": HOST, "revision": 0, "initialized": True}, returncode=1),
                failure("revision_conflict", returncode=0), failure("revision_conflict", returncode=1)]:
            with self.subTest(response=response):
                self.assert_failure(wire("initialize"), response, 7, "uncertain")
                self.assert_failure(wire("current"), response, 5, "transport")

    def test_helper_fixed_errors_have_decisive_categories(self):
        for code in ("revision_conflict", "store_missing", "mutation_busy", "record_rejected"):
            self.assert_failure(wire("initialize"), failure(code), 6, "rejected")
        for code in ("commit_outcome_unknown", "record_outcome_unknown", "response_size_limit", "internal_error"):
            self.assert_failure(wire("initialize"), failure(code), 7, "uncertain")
        for code in ("request_timeout", "transport_unavailable"):
            self.assert_failure(wire("initialize"), failure(code, 1), 5, "transport")
        self.assert_failure(wire("initialize"), failure("installed_helper_unavailable", 1), 7, "uncertain")

    def test_pre_and_post_dispatch_failures_preserve_uncertainty_boundary(self):
        for dispatched in (False, True):
            def sender(raw):
                raise _TransportFailure("helper_unavailable", dispatched=dispatched)
            for operation in ("initialize", "current"):
                with self.subTest(dispatched=dispatched, operation=operation), self.assertRaises(HostClientError) as caught:
                    request_host(wire(operation), _sender=sender)
                self.assertEqual(caught.exception.exit_status, 7 if dispatched and operation == "initialize" else 5)

    def test_cancellation_during_response_validation_preserves_unknown_mutation_outcome(self):
        response = reply({"host_id": HOST, "revision": 0, "initialized": True})
        for operation in ("initialize", "current"):
            with self.subTest(operation=operation), \
                    patch("mpkg_manager.host_client._response", side_effect=KeyboardInterrupt):
                with self.assertRaises(HostClientError) as caught:
                    request_host(wire(operation), _sender=lambda raw: response)
            self.assertEqual(caught.exception.exit_status, 7 if operation == "initialize" else 5)
            self.assertEqual(caught.exception.code, "helper_interrupted")

    def test_current_disallows_extra_values_unsafe_identifiers_and_invalid_scalar_shapes(self):
        current = {"host_id": HOST, "revision": 0, "snapshot_id": None, "snapshot": None, "resources": []}
        changes = [{"source": SENTINEL}, {"host_id": "\x1b[31m" + SENTINEL},
                   {"revision": False}, {"resources": {}}, {"snapshot_id": "a" * 64}]
        for change in changes:
            self.assert_failure(wire("current"), reply(current | change), 5, "transport")

    def test_mutation_response_must_match_requested_kind_and_revision(self):
        raw = wire("intent", expected_revision=4, source=EMPTY, source_is_nonsecret=True)
        for change in ({"revision": 4}, {"revision": True}, {"kind": "adopt"}, {"snapshot_id": SENTINEL}):
            self.assert_failure(raw, reply({"revision": 5, "kind": "intent", "snapshot_id": "a" * 64} | change),
                                7, "uncertain")

    def test_history_rejects_gaps_timestamp_controls_and_hidden_fields(self):
        decision = {"revision": 1, "parent_revision": None, "kind": "intent", "snapshot_id": "a" * 64,
                    "created_at": "2026-11-02T12:00:00.000000+00:00"}
        good = reply({"host_id": HOST, "decisions": [decision]})
        self.assertEqual(request_host(wire("history"), _sender=lambda request: good)["decisions"], [decision])
        for change in ({"revision": 2}, {"created_at": SENTINEL + "\n"}, {"source": SENTINEL}):
            self.assert_failure(wire("history"), reply({"host_id": HOST, "decisions": [decision | change]}),
                                5, "transport")


class TransportTests(unittest.TestCase):
    def test_owned_terminal_keeps_authorization_foreground_and_helper_in_same_session(self):
        # An owned PTY supplies a real controlling terminal. Both sudo commands
        # are replaced by Python probes; no authentication or root code runs.
        script = r'''
import fcntl, json, os, subprocess, sys, termios
from unittest.mock import patch
from mpkg_manager.host_client import _authorize, _exchange
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
session, group = os.getsid(0), os.getpgrp()
actual_run, actual_popen = subprocess.run, subprocess.Popen
auth_probe = "import os,sys; fd=os.open('/dev/tty',os.O_RDWR); sys.exit(0 if os.getsid(0)==%d and os.tcgetpgrp(fd)==os.getpgrp()==%d and os.read(0,1)==b'' else 2)" % (session, group)
helper_probe = "import json,os,sys; raw=sys.stdin.buffer.read(); fd=os.open('/dev/tty',os.O_RDWR); print(json.dumps({'session':os.getsid(0),'group':os.getpgrp(),'foreground':os.tcgetpgrp(fd),'pid':os.getpid(),'request':raw.decode()}))"
def auth(argv, **options):
    return actual_run([sys.executable, '-I', '-c', auth_probe], **options)
def helper(argv, **options):
    return actual_popen([sys.executable, '-I', '-c', helper_probe], **options)
with patch('mpkg_manager.host_client.subprocess.run', auth):
    _authorize()
with patch('mpkg_manager.host_client.subprocess.Popen', helper):
    response = _exchange(b'exact request')
result = json.loads(response.raw)
assert result['session'] == session
assert result['foreground'] == group
assert result['group'] == result['pid'] != group
assert result['request'] == 'exact request'
print('owned terminal checks passed')
'''
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen([sys.executable, "-c", script], stdin=slave,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       cwd=Path(__file__).resolve().parents[1], start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=10)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertEqual(stdout, b"owned terminal checks passed\n")
        finally:
            os.close(slave)
            os.close(master)

    def test_authorization_uses_fixed_argv_and_minimal_environment_without_request_stdin(self):
        with patch.dict(os.environ, {"SUDO_ASKPASS": SENTINEL, "PYTHONPATH": SENTINEL}), \
                patch("mpkg_manager.host_client.subprocess.run") as run:
            run.return_value.returncode = 0
            _authorize()
        arguments, options = run.call_args
        self.assertEqual(arguments[0], ("/usr/bin/sudo", "-v", "-u", "root"))
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(options["env"], {"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        self.assertEqual(options["cwd"], "/")
        self.assertNotIn("shell", options)

    def test_authentication_failure_prevents_helper_dispatch_and_never_echoes_raw_diagnostics(self):
        for outcome in (subprocess.CompletedProcess([], 1), subprocess.TimeoutExpired(SENTINEL, 1), KeyboardInterrupt()):
            with self.subTest(outcome=type(outcome).__name__), \
                    patch("mpkg_manager.host_client.subprocess.run") as run, \
                    patch("mpkg_manager.host_client._exchange") as exchange:
                if isinstance(outcome, BaseException):
                    run.side_effect = outcome
                else:
                    run.return_value = outcome
                with self.assertRaises(HostClientError) as caught:
                    request_host(wire("initialize"))
                self.assertEqual((caught.exception.exit_status, caught.exception.category), (4, "authentication"))
                exchange.assert_not_called()
                self.assertNotIn(SENTINEL, str(caught.exception))

    def test_missing_sudo_or_helper_spawn_reports_pre_dispatch_transport_failure(self):
        with patch("mpkg_manager.host_client.subprocess.run", side_effect=FileNotFoundError(SENTINEL)):
            with self.assertRaises(HostClientError) as caught:
                request_host(wire("initialize"))
        self.assertEqual(caught.exception.exit_status, 5)
        with patch("mpkg_manager.host_client._authorize"), \
                patch("mpkg_manager.host_client.subprocess.Popen", side_effect=FileNotFoundError(SENTINEL)):
            with self.assertRaises(HostClientError) as caught:
                request_host(wire("initialize"))
        self.assertEqual(caught.exception.exit_status, 5)

    def substitute(self, script):
        actual = subprocess.Popen
        calls = []
        def launch(arguments, **options):
            calls.append((arguments, options.copy()))
            return actual([sys.executable, "-I", "-c", script], **options)
        return calls, patch("mpkg_manager.host_client.subprocess.Popen", launch)

    def test_real_pipes_send_complete_source_through_eof_with_fixed_helper_invocation(self):
        script = 'import sys; raw=sys.stdin.buffer.read(); sys.stdout.buffer.write(raw); sys.stderr.write("' + SENTINEL + '")'
        calls, substitute = self.substitute(script)
        raw = b"x" * (1024 * 1024)
        with substitute, patch.dict(os.environ, {"PYTHONPATH": SENTINEL, "SUDO_ASKPASS": SENTINEL}):
            response = _exchange(raw)
        self.assertEqual(response.raw, raw)
        self.assertEqual(response.returncode, 0)
        self.assertEqual(len(calls), 1)
        arguments, options = calls[0]
        self.assertEqual(arguments, ("/usr/bin/sudo", "-n", "-u", "root", "--", "/usr/lib/mpkg/host-helper.py"))
        self.assertEqual(options["env"], {"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        self.assertEqual(options["cwd"], "/")
        self.assertTrue(options["close_fds"])
        self.assertEqual(options["process_group"], 0)
        self.assertNotIn("start_new_session", options)
        self.assertNotIn("shell", options)

    def test_output_overflow_and_timeout_are_bounded_and_uncertain_without_retry(self):
        scripts = ['import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b"x" * 8192)',
                   'import sys,time; sys.stdin.buffer.read(); time.sleep(10)']
        for script in scripts:
            calls, substitute = self.substitute(script)
            with self.subTest(script=script), substitute, \
                    patch("mpkg_manager.host_client._authorize"), \
                    patch("mpkg_manager.host_client.MAX_RESPONSE_BYTES", 4096), \
                    patch("mpkg_manager.host_client._REQUEST_SECONDS", 0.2):
                with self.assertRaises(HostClientError) as caught:
                    request_host(wire("initialize"))
                self.assertEqual(caught.exception.exit_status, 7)
            self.assertEqual(len(calls), 1)

    def test_partial_write_failure_is_uncertain_and_not_retried(self):
        calls, substitute = self.substitute('import sys,time; sys.stdin.buffer.read(); time.sleep(10)')
        actual_write = os.write
        writes = []
        def write(fd, data):
            writes.append(len(data))
            if len(writes) == 2:
                raise OSError(SENTINEL)
            return actual_write(fd, data)
        raw = wire("intent", source=EMPTY + "#" + "x" * 100000, source_is_nonsecret=True, expected_revision=0)
        with substitute, patch("mpkg_manager.host_client._authorize"), \
                patch("mpkg_manager.host_client.os.write", write):
            with self.assertRaises(HostClientError) as caught:
                request_host(raw)
        self.assertEqual(caught.exception.exit_status, 7)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(writes), 2)
        self.assertNotIn(SENTINEL, str(caught.exception))

    def test_interruption_after_dispatch_reports_uncertain_and_does_not_retry(self):
        calls, substitute = self.substitute('import sys,time; sys.stdin.buffer.read(); time.sleep(10)')
        with substitute, patch("mpkg_manager.host_client._authorize"), \
                patch("mpkg_manager.host_client.selectors.PollSelector.select", side_effect=KeyboardInterrupt):
            with self.assertRaises(HostClientError) as caught:
                request_host(wire("initialize"))
        self.assertEqual((caught.exception.exit_status, caught.exception.category), (7, "uncertain"))
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
