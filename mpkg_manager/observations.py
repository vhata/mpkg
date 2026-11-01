"""Immutable, bounded facts; observation neither adopts nor grants authority."""
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
import uuid


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_context(host_id, observed_at):
    try:
        valid_host = str(uuid.UUID(host_id)) == host_id
        timestamp = datetime.fromisoformat(observed_at)
        valid_time = observed_at.endswith("Z") and timestamp.utcoffset().total_seconds() == 0
    except (ValueError, TypeError, AttributeError):
        raise ValueError("invalid_observation_context") from None
    if not valid_host or not valid_time:
        raise ValueError("invalid_observation_context")


@dataclass(frozen=True)
class Observation:
    host_id: str
    resource_id: str
    kind: str
    identity: object
    property: str
    state: str
    value: object
    observed_at: str
    evidence_source: str
    limitations: tuple = ()

    def __post_init__(self):
        validate_context(self.host_id, self.observed_at)
        if self.state not in ("known", "absent", "unknown"):
            raise ValueError("invalid_observation_state")
        if self.state != "known" and self.value is not None:
            raise ValueError("unknown_observation_has_value")
        if type(self.value) not in (str, int, bool, type(None)):
            raise ValueError("unsupported_observation_value")
        identity = dict(self.identity)
        if any(type(k) is not str or type(v) is not str for k, v in identity.items()):
            raise ValueError("invalid_observation_identity")
        if any(type(item) is not str for item in self.limitations):
            raise ValueError("invalid_observation_limitations")
        object.__setattr__(self, "identity", MappingProxyType(identity))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if self.state == "unknown" and not self.limitations:
            raise ValueError("unknown_observation_requires_reason")

    def as_dict(self):
        return {
            "host_id": self.host_id, "resource_id": self.resource_id,
            "kind": self.kind, "identity": dict(self.identity),
            "property": self.property, "state": self.state, "value": self.value,
            "observed_at": self.observed_at, "evidence_source": self.evidence_source,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ObservationBatch:
    host_id: str
    observed_at: str
    facts: tuple
    coverage: tuple
    limitations: tuple = ()

    def __post_init__(self):
        validate_context(self.host_id, self.observed_at)
        object.__setattr__(self, "facts", tuple(self.facts))
        object.__setattr__(self, "coverage", tuple(self.coverage))
        object.__setattr__(self, "limitations", tuple(self.limitations))
        if (any(type(value) is not str for value in self.coverage + self.limitations)
                or len(set(self.coverage)) != len(self.coverage)):
            raise ValueError("invalid_observation_coverage")
        if any(not isinstance(f, Observation) or f.host_id != self.host_id
               or f.observed_at != self.observed_at for f in self.facts):
            raise ValueError("inconsistent_observation_batch")
        if (any(f.resource_id not in self.coverage for f in self.facts)
                or len({(f.resource_id, f.property) for f in self.facts}) != len(self.facts)):
            raise ValueError("inconsistent_observation_batch")

    def for_resource(self, resource_id):
        return tuple(fact for fact in self.facts if fact.resource_id == resource_id)

    def as_dict(self):
        return {"host_id": self.host_id, "observed_at": self.observed_at,
                "facts": [fact.as_dict() for fact in self.facts],
                "coverage": list(self.coverage), "limitations": list(self.limitations)}
