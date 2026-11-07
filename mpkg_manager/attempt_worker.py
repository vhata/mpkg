"""Fixed attempt worker; production effect adapters remain unavailable.

The installed entrypoint accepts only an attempt UUID. Trusted test assembly
can enable the private inert child runner against owned temporary stores.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import sys

from .attempt_journal import read_attempt
from .attempt_supervisor import (SupervisionError, _append, _boot_id, _require,
                                 _worker_identity, _ENVIRONMENT)
from .host_helper import MUTATION_LOCK, STORE_DIRECTORY, _mutation_lock
from .host_policy import POLICY_PATH, load_host_policy
from .query_process import QueryResult, run_bounded
from .store import HostStore


@dataclass(frozen=True)
class ChildOutcome:
    code: str

    def __post_init__(self):
        _require(type(self.code) is str and self.code in ("complete", "failed", "unknown"))


def _run_inert_child():
    """Fixed owned child used only by explicit fixture construction."""
    result = run_bounded((sys.executable, "-I", "-c", "pass"),
                         environment=_ENVIRONMENT, timeout=1, max_output=4096)
    return _child_outcome(result)


def _child_outcome(result):
    if type(result) is not QueryResult:
        return ChildOutcome("unknown")
    if result.code == "ok":
        return ChildOutcome("complete")
    if result.code in ("command_failed", "tool_unavailable", "permission_denied", "start_failed"):
        return ChildOutcome("failed")
    # A timeout/output/transport error can leave cleanup or effects uncertain.
    return ChildOutcome("unknown")


class AttemptWorker:
    """Hold the host lock through one durable, reserved attempt."""
    def __init__(self, *, policy_path=POLICY_PATH, store_directory=STORE_DIRECTORY,
                 mutation_lock=MUTATION_LOCK, owner_uid=0, _fixture=False,
                 _fixture_boot=None, _runner=None):
        self.policy_path, self.store_directory = policy_path, store_directory
        self.mutation_lock, self.owner_uid = Path(mutation_lock), owner_uid
        self.fixture, self.fixture_boot = _fixture, _fixture_boot
        self.runner = _run_inert_child if _runner is None else _runner

    def run(self, attempt_id):
        from .attempt_journal import _uuid
        _require(_uuid(attempt_id) and type(self.fixture) is bool)
        _require(type(self.owner_uid) is int and self.owner_uid == os.geteuid(), "worker_owner_required")
        boot_id = self.fixture_boot if self.fixture else _boot_id()
        _require(_uuid(boot_id), "worker_identity_unavailable")
        with _mutation_lock(self.mutation_lock, self.owner_uid):
            with load_host_policy(path=self.policy_path, owner_uid=self.owner_uid) as policy:
                with HostStore.open_existing(self.store_directory, policy.policy.host_id,
                                             owner_uid=self.owner_uid) as store:
                    _require(store.engine_aliases == policy.policy.engine_aliases, "worker_identity_mismatch")
                    _worker_identity(store, attempt_id, boot_id, fixture=self.fixture)
                    current = read_attempt(store, attempt_id).as_dict()
                    launch = current["supervision"]
                    _require(launch["reserved"] and launch["worker"] == "not_started"
                             and launch["dispatch"] != "rejected", "worker_claim_refused")
                    _append(store, attempt_id, "worker_started", "owned")
                    try:
                        for action in current["actions"]:
                            policy.policy
                            identity = action["action_id"]
                            _append(store, attempt_id, "action_started", "started", identity)
                            try:
                                result = self.runner()
                                if type(result) is not ChildOutcome:
                                    result = ChildOutcome("unknown")
                            except Exception:
                                result = ChildOutcome("unknown")
                            command = {"complete": "succeeded", "failed": "failed", "unknown": "unknown"}[result.code]
                            _append(store, attempt_id, "command_completed", command, identity)
                            current = _append(store, attempt_id, "observation_completed",
                                "satisfied" if result.code == "complete" else "unavailable", identity)
                            if result.code != "complete":
                                break
                        if current["state"] != "unknown":
                            _append(store, attempt_id, "attempt_finished", current["state"])
                        _append(store, attempt_id, "worker_completed",
                            "verified_complete" if current["state"] == "observed-complete" else "unresolved")
                    except BaseException:
                        # Best-effort metadata never clears the durable launch
                        # gate. A poisoned handle or interruption keeps it held.
                        try:
                            _append(store, attempt_id, "worker_completed", "unresolved")
                        except BaseException:
                            pass
                        raise
                    return read_attempt(store, attempt_id).as_dict()


def main(attempt_id):
    """Installed launcher supplies one validated UUID and no fixture overrides."""
    try:
        AttemptWorker().run(attempt_id)
        return 0
    except BaseException:
        # The service stdout/stderr are null; even direct calls get no traceback
        # or raw child output. Journal/reservation state carries uncertainty.
        return 1
