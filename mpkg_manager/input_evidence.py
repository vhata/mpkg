"""Immutable redacted input evidence; shape validation is not authentication."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
import uuid

from .declarations import canonical_json


MAX_EVIDENCE_BYTES = 64 * 1024
MAX_EVIDENCE_ENTRIES = 64
SOURCE = "protected_recorder_compare_input"
SCOPE = "current_recorded_snapshot"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
REASONS = {"collected", "policy_unavailable", "target_changed", "store_unavailable",
           "protected_input_limit"}


class InputEvidenceError(ValueError):
    def __init__(self):
        super().__init__("invalid_input_evidence")


def collection_time(value=None):
    """Return validated UTC collection-start text; never advance it per file."""
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    try:
        if type(value) is not str or not value.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset().total_seconds() != 0:
            raise ValueError
    except (ValueError, AttributeError, OverflowError):
        raise InputEvidenceError() from None
    return value


def _require(value):
    if not value:
        raise InputEvidenceError()


def _validate(value):
    _require(type(value) is dict and set(value) == {
        "schema_version", "host_id", "revision", "snapshot", "observed_at", "source",
        "scope", "state", "reason", "entries"})
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    host = value["host_id"]
    _require(type(host) is str and str(uuid.UUID(host)) == host)
    _require(type(value["revision"]) is int and 1 <= value["revision"] < 2**63)
    snapshot = value["snapshot"]
    _require(type(snapshot) is dict and set(snapshot) == {
        "id", "source_sha256", "canonical_sha256", "schema_version", "normalization_version"})
    for name in ("id", "source_sha256", "canonical_sha256"):
        _require(type(snapshot[name]) is str and _HASH.fullmatch(snapshot[name]))
    for name in ("schema_version", "normalization_version"):
        _require(type(snapshot[name]) is int and snapshot[name] == 1)
    _require(type(value["observed_at"]) is str)
    collection_time(value["observed_at"])
    _require(value["source"] == SOURCE and value["scope"] == SCOPE)
    _require(value["state"] in ("complete", "unavailable") and value["reason"] in REASONS)
    _require((value["state"] == "complete") == (value["reason"] == "collected"))
    _require(type(value["entries"]) is list and len(value["entries"]) <= MAX_EVIDENCE_ENTRIES)
    seen = set()
    for entry in value["entries"]:
        _require(type(entry) is dict and set(entry) == {"input_id", "file_index", "state"})
        _require(type(entry["input_id"]) is str and _ID.fullmatch(entry["input_id"]))
        _require(type(entry["file_index"]) is int and 0 <= entry["file_index"] < 2**63)
        _require(entry["state"] in ("same", "changed", "unavailable"))
        _require(value["state"] == "complete" or entry["state"] == "unavailable")
        key = (entry["input_id"], entry["file_index"])
        _require(key not in seen)
        seen.add(key)


@dataclass(frozen=True)
class ProtectedInputEvidence:
    canonical_bytes: bytes = field(repr=False)

    def __post_init__(self):
        try:
            _require(type(self.canonical_bytes) is bytes and len(self.canonical_bytes) <= MAX_EVIDENCE_BYTES)
            value = json.loads(self.canonical_bytes)
            _require(canonical_json(value) == self.canonical_bytes)
            _validate(value)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            raise InputEvidenceError() from None

    def as_dict(self):
        return json.loads(self.canonical_bytes)


def input_evidence(value):
    """Revalidate caller objects and wire projections into a private copy."""
    try:
        raw = value.canonical_bytes if isinstance(value, ProtectedInputEvidence) else canonical_json(value)
        return ProtectedInputEvidence(raw)
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise InputEvidenceError() from None
