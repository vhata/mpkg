"""Closed versioned nonsecret application metadata retained in endpoint checks."""
from dataclasses import dataclass, asdict
import json
import re

VERSIONS = {"sonarr": ("4.0.20.3014", "sha256:076be80fcab2bd0acdea4c8c5f604318f2feb61aeeaacd71cfcb1983a8fb50bf"),
            "radarr": ("6.4.4.10685", "sha256:a9b08c177649ae4e2c03f4ab375140ac8e633f87a781eeaa7a0e7f1e85b112a8")}

def _require(condition):
    if not condition:
        raise ValueError


@dataclass(frozen=True)
class ApplicationPredicate:
    application: str
    version: str
    port: int
    base: str = ""
    root_id: int = 0
    root_path: str = ""
    sentinel: str = ""

    def __post_init__(self):
        try:
            _require(self.application in VERSIONS and self.version == VERSIONS[self.application][0])
            _require(type(self.port) is int and 1 <= self.port <= 65535)
            _require(type(self.base) is str and re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*", self.base))
            if self.application == "sonarr":
                _require((self.root_id, self.root_path, self.sentinel) == (0, "", ""))
            else:
                _require(type(self.root_id) is int and 0 < self.root_id < 2**31)
                _require(re.fullmatch(r"/(?:[A-Za-z0-9 _.-]+/)*[A-Za-z0-9 _.-]+", self.root_path))
                _require(all(part not in (".", "..") for part in self.root_path.split("/")))
                _require(re.fullmatch(r"[A-Za-z0-9 _().-]{1,255}", self.sentinel))
                _require(self.sentinel not in (".", ".."))
            _require(len(json.dumps(asdict(self)).encode("utf-8")) < 8192)
        except (ValueError, TypeError, KeyError):
            raise ValueError("invalid_application_predicate") from None



def predicate_from_metadata(value):
    """Validate a closed v1 object, never credentials or executable requests."""
    try:
        if type(value) is not dict or type(value.get("schema")) is not int or value["schema"] != 1:
            raise ValueError
        allowed = {"schema", "name", "version", "port", "base", "root_id", "root_path", "sentinel"}
        if not set(value) <= allowed or not {"schema", "name", "version", "port"} <= set(value):
            raise ValueError
        if value["name"] == "radarr" and not {"root_id", "root_path", "sentinel"} <= set(value):
            raise ValueError
        if value["name"] == "sonarr" and set(value) & {"root_id", "root_path", "sentinel"}:
            raise ValueError
        return ApplicationPredicate(application=value["name"], **{
            key: item for key, item in value.items() if key not in ("schema", "name")})
    except (ValueError, TypeError, KeyError):
        raise ValueError("invalid_application_predicate") from None


def normalize_metadata(value):
    predicate = predicate_from_metadata(value)
    result = {"schema": 1, "name": predicate.application, "version": predicate.version,
              "port": predicate.port, "base": predicate.base}
    if predicate.application == "radarr":
        result.update(root_id=predicate.root_id, root_path=predicate.root_path, sentinel=predicate.sentinel)
    return result
