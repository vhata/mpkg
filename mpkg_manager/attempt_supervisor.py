"""Fixed system-manager launch adapter and durable launch/worker ownership.

No host request can dispatch an attempt yet. The only writer integration is
an explicitly constructed private fixture boundary. Its attempts stay inert
and non-executable; production plan authorization remains separate work.
"""
from dataclasses import dataclass
from pathlib import Path
import os

from .attempt_journal import (JournalError, _FixtureJournal, _decode, _replay, _rows, _uuid,
                              read_attempt, require_no_pending_launch)
from .host_helper import MUTATION_LOCK, STORE_DIRECTORY, _mutation_lock
from .host_policy import POLICY_PATH, load_host_policy
from .query_process import QueryResult, run_bounded
from .store import HostStore


WORKER = "/usr/lib/mpkg/attempt-worker.py"
_ENVIRONMENT = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
_PROPERTIES = ("Type=exec", "ExitType=cgroup", "KillMode=control-group", "Restart=no",
               "RemainAfterExit=yes", "StandardInput=null", "StandardOutput=null",
               "StandardError=null", "LimitCORE=0", "UMask=0077", "WorkingDirectory=/",
               "TimeoutStartSec=30s")


class SupervisionError(RuntimeError):
    def __init__(self, code="invalid_supervision_request"):
        self.code = code
        super().__init__(code)


def _require(condition, code="invalid_supervision_request"):
    if not condition:
        raise SupervisionError(code)


def _boot_id():
    # Only installed code selects this fixed kernel identity; no request path.
    try:
        with open("/proc/sys/kernel/random/boot_id", "rb") as source:
            raw = source.read(64)
        value = raw.decode("ascii").strip()
        _require(_uuid(value), "worker_identity_unavailable")
        return value
    except (OSError, UnicodeError):
        raise SupervisionError("worker_identity_unavailable") from None


@dataclass(frozen=True)
class LaunchSpec:
    """One canonical attempt ID determines every service and executable field."""
    attempt_id: str

    def __post_init__(self):
        _require(_uuid(self.attempt_id))

    @property
    def unit(self):
        return f"mpkg-attempt-{self.attempt_id}.service"

    def argv(self):
        self.__post_init__()
        return ("/usr/bin/systemd-run", "--system", "--quiet", "--no-ask-password",
                f"--unit={self.unit}", *(f"--property={item}" for item in _PROPERTIES),
                "--", WORKER, self.attempt_id)


@dataclass(frozen=True)
class LaunchResult:
    outcome: str

    def __post_init__(self):
        _require(type(self.outcome) is str and self.outcome in ("accepted", "rejected", "unknown"))


class SystemdTransport:
    """Bounded client invocation, with detached service ownership and no retry.

    Success acknowledges startup, never application success. Losing this
    client cannot be treated as cancellation of the independent service.
    """
    def launch(self, spec):
        _require(type(spec) is LaunchSpec)
        result = run_bounded(spec.argv(), environment=_ENVIRONMENT, timeout=10, max_output=65536)
        if type(result) is not QueryResult:
            return LaunchResult("unknown")
        if result.code == "ok":
            return LaunchResult("accepted")
        if result.code in ("tool_unavailable", "permission_denied", "start_failed"):
            return LaunchResult("rejected")
        return LaunchResult("unknown")


def _append(store, attempt_id, kind, outcome, action_id=None):
    """Retry only a metadata CAS racing the one startup acknowledgement.

    Never redispatch a worker or repeat an effect. Each append still validates
    the durable state machine; competing action writers cannot replay starts.
    """
    for _ in range(8):
        current = read_attempt(store, attempt_id).as_dict()
        try:
            return _FixtureJournal(store).append(attempt_id, expected_sequence=current["sequence"],
                action_id=action_id, kind=kind, outcome=outcome).as_dict()
        except JournalError as error:
            if error.code != "attempt_sequence_conflict":
                raise
    raise SupervisionError("attempt_journal_busy")


def _worker_identity(store, attempt_id, boot_id, *, fixture):
    with store._read():
        row, actions, events = _rows(store, attempt_id)
        context = _decode(row[6])
        _require(fixture and context["authority"] == "fixture_only", "execution_unavailable")
        worker = context["worker"]
        _require(worker["worker_uid"] == os.geteuid() and worker["boot_id"] == boot_id
                 and worker["unit"] == LaunchSpec(attempt_id).unit, "worker_identity_mismatch")
        _require(store._revision() == row[2], "attempt_target_changed")
        _require(_replay(actions, events)[2]["recovery"] != "quiescent",
                 "attempt_recovered")
        return worker


class AttemptSupervisor:
    """Trusted construction; the installed request boundary does not expose it.

    Private fixture arguments are unavailable from JSON, CLI or unit argv.
    Production construction refuses fixture authority before dispatch.
    """
    def __init__(self, *, policy_path=POLICY_PATH, store_directory=STORE_DIRECTORY,
                 mutation_lock=MUTATION_LOCK, owner_uid=0, _fixture=False,
                 _fixture_boot=None, _transport=None):
        self.policy_path, self.store_directory = policy_path, store_directory
        self.mutation_lock, self.owner_uid = Path(mutation_lock), owner_uid
        _require(type(_fixture) is bool and (not _fixture or _transport is not None))
        self.fixture, self.fixture_boot = _fixture, _fixture_boot
        self.transport = SystemdTransport() if _transport is None else _transport

    def dispatch(self, attempt_id):
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
                    _require(not current["supervision"]["reserved"], "attempt_already_dispatched")
                    require_no_pending_launch(store)
                    _append(store, attempt_id, "launch_reserved", "reserved")
                    host_id = store.host_id
        # The durable reservation now protects the lock handoff. No store or
        # host lock is inherited/held by the system-manager client call.
        try:
            result = self.transport.launch(LaunchSpec(attempt_id))
            if type(result) is not LaunchResult:
                result = LaunchResult("unknown")
        except Exception:
            result = LaunchResult("unknown")
        # A worker may already own the lock or have finished before this reply.
        # Appending launch metadata never waits for that application lock.
        with HostStore.open_existing(self.store_directory, host_id, owner_uid=self.owner_uid) as store:
            _append(store, attempt_id, "launch_result", result.outcome)
        return {"attempt_id": attempt_id, "launch": result.outcome, "executable": False}
