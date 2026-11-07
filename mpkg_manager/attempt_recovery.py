"""Evidence-backed attempt disposition; never stop, replay or infer success.

Evidence acquisition is a trusted adapter boundary, not a JSON credential.
Only explicitly assembled inert fixtures are available. Installed recovery
collectors and production request authorization remain separate work.
"""
from dataclasses import dataclass, field
from contextlib import contextmanager
from pathlib import Path
import json
import os
import time
import uuid

from .attempt_journal import (JournalError, _FixtureJournal, _decode, _rows, _uuid,
                              read_attempt)
from .host_helper import BoundaryError, MUTATION_LOCK, STORE_DIRECTORY, _mutation_lock
from .host_policy import POLICY_PATH, PolicyError, load_host_policy
from .store import HostStore, StoreError, _json


MAX_RECOVERY_OBSERVATIONS = 128
MAX_EVIDENCE_BYTES = 128 * 1024
EVIDENCE_SECONDS = 30
_STATES = ("quiescent", "active", "unavailable")


class RecoveryError(RuntimeError):
    """Closed diagnostics, with no observation or child error text."""
    def __init__(self, code="invalid_recovery_evidence"):
        self.code = code
        super().__init__(code)


def _require(condition, code="invalid_recovery_evidence"):
    if not condition:
        raise RecoveryError(code)


@dataclass(frozen=True)
class RecoveryRequest:
    """One fresh collection challenge bound to immutable attempt scope."""
    challenge_id: str
    host_id: str
    attempt_id: str
    sequence: int
    original_boot_id: str
    current_boot_id: str
    unit: str
    package_lock_required: bool
    engine_ids: tuple = field(repr=False)
    resource_ids: tuple


@dataclass(frozen=True)
class RecoveryEvidence:
    """Trusted collector output; absence alone never means quiescence.

    `settled` covers the launcher and all queued system-manager requests.
    `idle` covers native transaction ownership, not just lock-file absence.
    Engine/resource quiescence includes outstanding daemon operations.
    """
    request: RecoveryRequest = field(repr=False)
    dispatch: str
    unit: str
    cgroup: str
    package_lock: str
    engines: tuple = field(repr=False)
    resources: tuple = field(repr=False)


def _scope(context, engine_aliases):
    resources = context["target"]["resources"]
    engines = set()
    for resource in resources:
        alias = resource["definition"]["identity"].get("engine")
        if alias is not None:
            _require(alias in engine_aliases, "recovery_scope_unavailable")
            engines.add(engine_aliases[alias])
    return (any(row["definition"]["kind"] == "package" for row in resources),
            tuple(sorted(engines)), tuple(row["stable_id"] for row in resources))


def _request(store, attempt_id, sequence, current_boot):
    with store._read():
        row, _, _ = _rows(store, attempt_id)
        context = _decode(row[6])
        package, engines, resources = _scope(context, store.engine_aliases)
        return RecoveryRequest(str(uuid.uuid4()), store.host_id, attempt_id,
            sequence, context["worker"]["boot_id"], current_boot,
            context["worker"]["unit"], package, engines, resources)


def _unavailable(request):
    return RecoveryEvidence(request, "unavailable", "unavailable", "unavailable",
        "unavailable" if request.package_lock_required else "not_applicable",
        tuple((identity, "unavailable") for identity in request.engine_ids),
        tuple((identity, "unavailable") for identity in request.resource_ids))


def _pairs(value, identities):
    _require(type(value) is list and len(value) == len(identities))
    _require(all(type(row) is list and len(row) == 2
                 and type(row[0]) is str and type(row[1]) is str
                 and row[1] in _STATES for row in value))
    _require([row[0] for row in value] == list(identities))


def _validate_payload(payload):
    """Validate closed persisted evidence without trusting its disposition."""
    _require(type(payload) is dict and set(payload) == {"version", "challenge_id",
        "host_id", "attempt_id", "sequence", "operator_uid", "original_boot_id",
        "current_boot_id", "unit", "package_lock_required", "engine_ids",
        "resource_ids", "dispatch", "unit_state", "cgroup", "package_lock",
        "engines", "resources", "disposition"})
    _require(type(payload["version"]) is int and payload["version"] == 1)
    _require(all(_uuid(payload[key]) for key in ("challenge_id", "host_id",
        "attempt_id", "original_boot_id", "current_boot_id")))
    _require(type(payload["sequence"]) is int and 1 <= payload["sequence"] < 2**63)
    _require(type(payload["operator_uid"]) is int and 0 <= payload["operator_uid"] < 2**32 - 1)
    _require(payload["unit"] == f'mpkg-attempt-{payload["attempt_id"]}.service')
    _require(type(payload["package_lock_required"]) is bool)
    _require(type(payload["engine_ids"]) is list and len(payload["engine_ids"]) <= 128
        and all(type(value) is str and 0 < len(value) <= 256 for value in payload["engine_ids"])
        and sorted(set(payload["engine_ids"])) == payload["engine_ids"])
    _require(type(payload["resource_ids"]) is list and 1 <= len(payload["resource_ids"]) <= 128
        and all(_uuid(value) for value in payload["resource_ids"])
        and len(set(payload["resource_ids"])) == len(payload["resource_ids"]))
    for key, choices in (("dispatch", ("settled", "pending", "unavailable")),
                         ("unit_state", ("inactive", "exited", "absent", "active", "unavailable")),
                         ("cgroup", ("empty", "populated", "unavailable")),
                         ("package_lock", ("idle", "held", "unavailable", "not_applicable"))):
        _require(type(payload[key]) is str and payload[key] in choices)
    _require((payload["package_lock"] != "not_applicable") == payload["package_lock_required"])
    _pairs(payload["engines"], payload["engine_ids"])
    _pairs(payload["resources"], payload["resource_ids"])
    quiescent = (payload["dispatch"] == "settled"
        and payload["unit_state"] in ("inactive", "exited", "absent")
        and payload["cgroup"] == "empty"
        and payload["package_lock"] in ("idle", "not_applicable")
        and all(row[1] == "quiescent" for row in payload["engines"] + payload["resources"]))
    _require(payload["disposition"] == ("quiescent" if quiescent else "blocked"))
    return payload


def _decode_evidence(outcome):
    try:
        _require(type(outcome) is str and len(outcome.encode()) <= MAX_EVIDENCE_BYTES)
        payload = json.loads(outcome)
        _require(_json(payload).decode() == outcome)
        return _validate_payload(payload)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise RecoveryError() from None


def _verify_binding(payload, context, sequence, attempt_id, engine_aliases):
    package, engines, resources = _scope(context, engine_aliases)
    _require(payload["attempt_id"] == attempt_id and payload["sequence"] == sequence
        and payload["host_id"] == context["target"]["host_id"]
        and payload["original_boot_id"] == context["worker"]["boot_id"]
        and payload["unit"] == context["worker"]["unit"]
        and payload["package_lock_required"] == package
        and payload["engine_ids"] == list(engines)
        and payload["resource_ids"] == list(resources))


def _encode_evidence(evidence, request, operator_uid):
    _require(type(evidence) is RecoveryEvidence and evidence.request is request,
             "recovery_evidence_mismatch")
    _require(type(evidence.engines) is tuple and type(evidence.resources) is tuple
             and all(type(row) is tuple for row in evidence.engines + evidence.resources))
    payload = {"version": 1, "challenge_id": request.challenge_id,
        "host_id": request.host_id, "attempt_id": request.attempt_id,
        "sequence": request.sequence, "operator_uid": operator_uid,
        "original_boot_id": request.original_boot_id, "current_boot_id": request.current_boot_id,
        "unit": request.unit, "package_lock_required": request.package_lock_required,
        "engine_ids": list(request.engine_ids), "resource_ids": list(request.resource_ids),
        "dispatch": evidence.dispatch, "unit_state": evidence.unit, "cgroup": evidence.cgroup,
        "package_lock": evidence.package_lock, "engines": [list(row) for row in evidence.engines],
        "resources": [list(row) for row in evidence.resources], "disposition": "blocked"}
    # Compute the disposition from validated fields, never accept it from a caller.
    if (evidence.dispatch == "settled" and evidence.unit in ("inactive", "exited", "absent")
            and evidence.cgroup == "empty" and evidence.package_lock in ("idle", "not_applicable")
            and all(len(row) == 2 and row[1] == "quiescent" for row in evidence.engines + evidence.resources)):
        payload["disposition"] = "quiescent"
    raw = _json(_validate_payload(payload)).decode()
    _require(len(raw.encode()) <= MAX_EVIDENCE_BYTES)
    return raw


@contextmanager
def _outcome_boundary():
    """Keep all enclosing context cleanup inside the durable outcome boundary."""
    state = {"appending": False, "recorded": False}
    try:
        yield state
    except Exception as error:
        if (state["recorded"] or (isinstance(error, StoreError) and error.code == "commit_outcome_unknown")
                or (state["appending"] and not isinstance(error,
                    (RecoveryError, JournalError, StoreError, PolicyError, BoundaryError)))):
            raise RecoveryError("recovery_outcome_unknown") from None
        if isinstance(error, (RecoveryError, JournalError, StoreError, PolicyError, BoundaryError)):
            raise
        raise RecoveryError("recovery_failed") from None


class AttemptRecovery:
    """Trusted fixture assembly. Public arguments select only an existing ID.

    The host lock covers collection through the disposition commit. No store
    transaction spans collection, and no collector may mutate host resources.
    """
    def __init__(self, *, policy_path=POLICY_PATH, store_directory=STORE_DIRECTORY,
                 mutation_lock=MUTATION_LOCK, owner_uid=0, _fixture=False,
                 _fixture_boot=None, _collector=None):
        self.policy_path, self.store_directory = policy_path, store_directory
        self.mutation_lock, self.owner_uid = Path(mutation_lock), owner_uid
        _require(type(_fixture) is bool)
        self.fixture, self.boot, self.collector = _fixture, _fixture_boot, _collector

    def recover(self, attempt_id, *, expected_sequence):
        _require(_uuid(attempt_id) and type(expected_sequence) is int and expected_sequence >= 0,
                 "invalid_recovery_request")
        _require(self.fixture and callable(self.collector), "recovery_unavailable")
        _require(type(self.owner_uid) is int and self.owner_uid == os.geteuid(), "recovery_owner_required")
        _require(_uuid(self.boot), "recovery_boot_unavailable")
        with _outcome_boundary() as outcome, _mutation_lock(self.mutation_lock, self.owner_uid):
            with load_host_policy(path=self.policy_path, owner_uid=self.owner_uid) as policy:
                with HostStore.open_existing(self.store_directory, policy.policy.host_id,
                                             owner_uid=self.owner_uid) as store:
                    _require(store.engine_aliases == policy.policy.engine_aliases, "recovery_scope_unavailable")
                    current = read_attempt(store, attempt_id).as_dict()
                    _require(current["sequence"] == expected_sequence, "recovery_sequence_conflict")
                    _require(current["supervision"]["reserved"] and not current["supervision"]["released"],
                             "recovery_not_required")
                    request = _request(store, attempt_id, expected_sequence, self.boot)
                    started = time.monotonic()
                    try:
                        evidence = self.collector(request)
                    except Exception:
                        evidence = _unavailable(request)
                    if time.monotonic() - started > EVIDENCE_SECONDS:
                        evidence = _unavailable(request)
                    policy.policy  # Revalidate the pinned policy before committing.
                    raw = _encode_evidence(evidence, request, self.owner_uid)
                    outcome["appending"] = True
                    result = _FixtureJournal(store)._append_recovery(attempt_id,
                        expected_sequence=expected_sequence, outcome=raw)
                    outcome["recorded"] = True
                    return result.as_dict()
