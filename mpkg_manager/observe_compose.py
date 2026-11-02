"""Bounded local Compose-labelled inventory, without rendering or adoption."""
from dataclasses import dataclass, field
from datetime import datetime
import json
import posixpath
import re
import time

from .declarations import canonical_json
from .observations import Observation, ObservationBatch, utc_now, validate_context
from .query_process import QueryResult, run_bounded


DOCKER = ("/usr/bin/docker", "--config", "/dev/null", "--host", "unix:///run/docker.sock")
ENVIRONMENT = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C", "HOME": "/dev/null"}
ENGINE_QUERY = DOCKER + ("info", "--format", "{{json .ID}}")
LIST_QUERY = DOCKER + ("container", "ls", "--all", "--quiet", "--no-trunc", "--filter")
PROJECT_FILTER = "label=com.docker.compose.project="
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,254}\Z")
ENGINE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:-]{0,127}\Z")
OBJECT_ID = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPO_DIGEST = re.compile(r"[a-z0-9][a-z0-9._:/-]{0,511}@sha256:[0-9a-f]{64}\Z")
PLATFORM_PART = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z\Z")
MAX_OUTPUT = 256 * 1024
MAX_TOTAL_OUTPUT = 8 * 1024 * 1024
MAX_CONTAINERS = 64
COLLECTION_TIMEOUT = 60


def _fields(fields):
    return ",".join('"' + key + '":{{json ' + value + '}}' for key, value in fields)


CONTAINER_FORMAT = "{" + _fields((
    ("id", ".Id"), ("image_id", ".Image"), ("status", ".State.Status"),
    ("running", ".State.Running"), ("started_at", ".State.StartedAt"),
    ("finished_at", ".State.FinishedAt"),
    ("project", '(index .Config.Labels "com.docker.compose.project")'),
    ("service", '(index .Config.Labels "com.docker.compose.service")'),
    ("number", '(index .Config.Labels "com.docker.compose.container-number")'),
    ("oneoff", '(index .Config.Labels "com.docker.compose.oneoff")'),
)) + ',"mounts":{{if eq .Mounts nil}}null{{else}}[{{range $i,$m := .Mounts}}{{if $i}},{{end}}{' + _fields((
    ("type", "$m.Type"), ("source", "$m.Source"), ("target", "$m.Destination"),
    ("name", "$m.Name"), ("driver", "$m.Driver"), ("rw", "$m.RW"),
)) + '}{{end}}]{{end}},"networks":{{if eq .NetworkSettings.Networks nil}}null{{else}}' \
    + '[{{$comma := ""}}{{range $name,$n := .NetworkSettings.Networks}}' \
    + '{{$comma}}{' + _fields((("name", "$name"), ("id", "$n.NetworkID"))) \
    + '}{{$comma = ","}}{{end}}]{{end}}}'
IMAGE_FORMAT = "{" + _fields((("id", ".Id"), ("os", ".Os"),
                               ("architecture", ".Architecture"), ("variant", ".Variant"),
                               ("repository_digests", ".RepoDigests"))) + "}"
CONTAINER_QUERY = DOCKER + ("container", "inspect", "--format", CONTAINER_FORMAT, "--")
IMAGE_QUERY = DOCKER + ("image", "inspect", "--format", IMAGE_FORMAT, "--")
LIMITATIONS = (
    "time_bounded_observation_not_atomic_engine_snapshot",
    "project_labels_not_verified_compose_input_closure",
    "project_attachment_consumers_not_exhaustive",
    "mount_paths_not_resolved_host_file_identities",
    "network_mode_and_external_endpoints_not_observed",
    "volume_and_network_lifecycle_authority_not_observed",
    "image_ids_not_registry_manifest_pins",
    "container_running_not_application_health",
)


@dataclass(frozen=True)
class ComposeInventory:
    """Canonical immutable selected facts and the fixed scalar projection."""
    observations: ObservationBatch
    inventory_bytes: bytes = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.observations, ObservationBatch) or type(self.inventory_bytes) is not bytes:
            raise ValueError("invalid_compose_inventory")
        try:
            value = json.loads(self.inventory_bytes)
            if (type(value) is not dict or set(value) != {
                    "accepted_engine_id", "project", "state", "reason", "consumer_scope",
                    "consumers_exhaustive", "limitations", "containers", "images", "volumes",
                    "networks", "binds"} or canonical_json(value) != self.inventory_bytes):
                raise ValueError("invalid_compose_inventory")
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError("invalid_compose_inventory") from None

    def as_dict(self):
        return {**json.loads(self.inventory_bytes), "observations": self.observations.as_dict()}


def _allowed_query(argv):
    if argv == ENGINE_QUERY:
        return True
    if (len(argv) == len(LIST_QUERY) + 1 and argv[:-1] == LIST_QUERY
            and argv[-1].startswith(PROJECT_FILTER)):
        return bool(PROJECT.fullmatch(argv[-1][len(PROJECT_FILTER):]))
    return any(len(argv) == len(prefix) + 1 and argv[:-1] == prefix
               and pattern.fullmatch(argv[-1])
               for prefix, pattern in ((CONTAINER_QUERY, OBJECT_ID), (IMAGE_QUERY, IMAGE_ID)))


def run_readonly(argv, *, timeout=10, max_output=MAX_OUTPUT):
    """Execute only selected-field queries against the fixed local endpoint."""
    if (type(argv) is not tuple or any(type(arg) is not str for arg in argv)
            or not _allowed_query(argv)):
        return QueryResult("invalid_query")
    return run_bounded(argv, environment=ENVIRONMENT, timeout=timeout, max_output=max_output)


class _Unavailable(Exception):
    pass


def _fail(code="malformed_docker_output"):
    raise _Unavailable(code)


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail()
    return value


def _matches(value, pattern):
    return type(value) is str and bool(pattern.fullmatch(value))


def _path(value):
    if type(value) is not str:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return (type(value) is str and len(value) <= 4096 and value.startswith("/")
            and not value.startswith("//") and posixpath.normpath(value) == value
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _timestamp(value):
    if not _matches(value, TIMESTAMP):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail()
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda value: _fail(), parse_float=lambda value: _fail())
    except (ValueError, UnicodeError, RecursionError):
        _fail()


class _Collector:
    def __init__(self, runner):
        self.runner = runner
        self.deadline = time.monotonic() + COLLECTION_TIMEOUT
        self.total = 0

    def query(self, argv):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            _fail("compose_observation_timeout")
        result = (self.runner(argv) if self.runner is not None
                  else run_readonly(argv, timeout=min(10, remaining)))
        if not isinstance(result, QueryResult):
            _fail("invalid_query_result")
        if result.code != "ok":
            _fail(result.code)
        self.total += len(result.output)
        if len(result.output) > MAX_OUTPUT or self.total > MAX_TOTAL_OUTPUT:
            _fail("output_limit")
        if time.monotonic() >= self.deadline:
            _fail("compose_observation_timeout")
        return result.output


def _container(raw, expected_id, project):
    value = _object(_json(raw), ("id", "image_id", "status", "running", "started_at",
                                "finished_at", "project", "service", "number", "oneoff",
                                "mounts", "networks"))
    if value["id"] != expected_id or value["project"] != project:
        _fail("container_identity_mismatch")
    if (not _matches(value["service"], NAME)
            or not _matches(value["number"], re.compile(r"[1-9][0-9]{0,5}\Z"))
            or value["oneoff"] not in ("True", "False", "true", "false")):
        _fail("compose_attribution_unavailable")
    if (not _matches(value["image_id"], IMAGE_ID) or type(value["running"]) is not bool
            or value["status"] not in ("created", "running", "paused", "restarting", "removing", "exited", "dead")
            or not _timestamp(value["started_at"])
            or not _timestamp(value["finished_at"])
            or (value["status"] == "running" and not value["running"])
            or (value["status"] in ("created", "exited", "dead") and value["running"])):
        _fail("container_state_unavailable")
    if (type(value["mounts"]) is not list or len(value["mounts"]) > 64
            or type(value["networks"]) is not list or len(value["networks"]) > 32):
        _fail("container_attachment_scope_unsupported")
    mounts = []
    targets = set()
    for mount in value["mounts"]:
        _object(mount, ("type", "source", "target", "name", "driver", "rw"))
        if not _path(mount["target"]) or mount["target"] in targets or type(mount["rw"]) is not bool:
            _fail("mount_identity_unavailable")
        targets.add(mount["target"])
        result = {"type": mount["type"], "target": mount["target"], "read_only": not mount["rw"]}
        if mount["type"] == "bind" and _path(mount["source"]):
            result["source"] = mount["source"]
        elif mount["type"] == "volume" and _matches(mount["name"], NAME) and _matches(mount["driver"], NAME):
            result.update(name=mount["name"], driver=mount["driver"])
        elif mount["type"] != "tmpfs":
            _fail("mount_identity_unavailable")
        mounts.append(result)
    networks = []
    names = set()
    ids = set()
    for network in value["networks"]:
        _object(network, ("name", "id"))
        if (not _matches(network["name"], NAME) or not _matches(network["id"], OBJECT_ID)
                or network["name"] in names or network["id"] in ids):
            _fail("network_identity_unavailable")
        names.add(network["name"])
        ids.add(network["id"])
        networks.append(network)
    return {**{key: value[key] for key in ("id", "image_id", "status", "running",
                                          "started_at", "finished_at", "service")},
            "number": int(value["number"]), "oneoff": value["oneoff"].lower() == "true",
            "mounts": sorted(mounts, key=lambda item: item["target"]),
            "networks": sorted(networks, key=lambda item: item["name"])}


def _image(raw, expected_id):
    value = _object(_json(raw), ("id", "os", "architecture", "variant", "repository_digests"))
    if value["id"] != expected_id:
        _fail("image_identity_mismatch")
    if not _matches(value["os"], PLATFORM_PART) or not _matches(value["architecture"], PLATFORM_PART):
        _fail("image_platform_unavailable")
    variant = value["variant"]
    if variant not in (None, "") and not _matches(variant, PLATFORM_PART):
        _fail("image_platform_unavailable")
    digests = value["repository_digests"]
    if digests is None:
        digests = []
    if (type(digests) is not list or len(digests) > 64
            or any(not _matches(digest, REPO_DIGEST) for digest in digests)
            or len(set(digests)) != len(digests)):
        _fail("image_registry_metadata_unavailable")
    return {"id": expected_id, "os": value["os"], "architecture": value["architecture"],
            "variant": variant or "", "repository_digests": sorted(digests),
            "registry_platform_binding": "unknown"}


def _snapshot(collector, project):
    raw = collector.query(LIST_QUERY + (PROJECT_FILTER + project,))
    try:
        ids = raw.decode("ascii").splitlines()
    except UnicodeError:
        _fail()
    if (len(ids) > MAX_CONTAINERS or any(not OBJECT_ID.fullmatch(item) for item in ids)
            or len(set(ids)) != len(ids)):
        _fail("container_inventory_invalid")
    containers = [_container(collector.query(CONTAINER_QUERY + (item,)), item, project)
                  for item in sorted(ids)]
    identities = [(item["service"], item["number"]) for item in containers if not item["oneoff"]]
    if len(identities) != len(set(identities)):
        _fail("duplicate_compose_service_identity")
    images = [_image(collector.query(IMAGE_QUERY + (item,)), item)
              for item in sorted({container["image_id"] for container in containers})]
    attachments = {"volumes": {}, "networks": {}, "binds": {}}
    for container in containers:
        for mount in container["mounts"]:
            if mount["type"] == "volume":
                key, identity = mount["name"], {"name": mount["name"], "driver": mount["driver"]}
                bucket = attachments["volumes"]
            elif mount["type"] == "bind":
                key, identity = mount["source"], {"source": mount["source"]}
                bucket = attachments["binds"]
            else:
                continue
            entry = bucket.setdefault(key, {**identity, "observed_container_ids": []})
            if any(entry[name] != value for name, value in identity.items()):
                _fail("attachment_identity_inconsistent")
            if container["id"] not in entry["observed_container_ids"]:
                entry["observed_container_ids"].append(container["id"])
        for network in container["networks"]:
            entry = attachments["networks"].setdefault(network["name"],
                                                       {**network, "observed_container_ids": []})
            if entry["id"] != network["id"]:
                _fail("attachment_identity_inconsistent")
            entry["observed_container_ids"].append(container["id"])
    if len({entry["id"] for entry in attachments["networks"].values()}) != len(attachments["networks"]):
        _fail("attachment_identity_inconsistent")
    return {"containers": containers, "images": images,
            **{name: [entries[key] for key in sorted(entries)] for name, entries in attachments.items()}}


def observe_compose(resource, *, host_id, accepted_engine_id, runner=None, observed_at=None):
    """Inspect one declaration using an engine ID already accepted by the caller.

    Labels and object inventory do not establish input closure or adoption.
    The engine binding must come from trusted context, never this discovery.
    """
    when = observed_at or utc_now()
    validate_context(host_id, when)
    if not _matches(accepted_engine_id, ENGINE_ID):
        raise ValueError("invalid_compose_observation_context")
    if (type(resource) is not dict or type(resource.get("id")) is not str
            or resource.get("kind") != "compose" or type(resource.get("identity")) is not dict
            or set(resource["identity"]) != {"engine", "project"}
            or any(not _matches(value, NAME) for value in resource["identity"].values())):
        raise ValueError("invalid_observation_resource")
    project = resource["identity"]["project"]
    desired = resource.get("desired", {})
    if type(desired) is not dict:
        raise ValueError("invalid_observation_resource")
    services = desired.get("services", [])
    if (type(services) is not list or any(not _matches(service, NAME) for service in services)
            or len(set(services)) != len(services)):
        raise ValueError("invalid_observation_resource")
    error = None
    snapshot = None
    try:
        if not PROJECT.fullmatch(project):
            _fail("compose_project_identity_unsupported")
        collector = _Collector(runner)
        if _json(collector.query(ENGINE_QUERY)) != accepted_engine_id:
            _fail("engine_identity_mismatch")
        first = _snapshot(collector, project)
        second = _snapshot(collector, project)
        if _json(collector.query(ENGINE_QUERY)) != accepted_engine_id:
            _fail("engine_identity_changed")
        if first != second:
            _fail("compose_inventory_changed")
        snapshot = second
    except _Unavailable as unavailable:
        error = str(unavailable)
    facts = []

    def add(prop, value=None, reason=None):
        facts.append(Observation(host_id, resource["id"], "compose", resource["identity"], prop,
                                 "unknown" if reason else "known", value, when,
                                 "docker_selected_project_inventory", (reason,) if reason else ()))

    if error:
        for prop in ("present", "container_count", "running"):
            add(prop, reason=error)
    else:
        containers = snapshot["containers"]
        add("present", bool(containers))
        add("container_count", len(containers))
        observed_services = [container["service"] for container in containers]
        if (not services or set(services) != set(observed_services)
                or any(container["oneoff"] for container in containers)):
            add("running", reason="compose_declared_service_scope_unresolved")
        elif len(observed_services) != len(set(observed_services)):
            add("running", reason="compose_replica_scope_unresolved")
        elif all(container["status"] == "running" for container in containers):
            add("running", True)
        elif all(container["status"] in ("created", "exited", "dead") for container in containers):
            add("running", False)
        else:
            add("running", reason="compose_running_state_mixed_or_transitional")
    for prop, reason in (("input_closure", "compose_inputs_not_observed"),
                         ("images", "image_intent_resolution_not_observed"),
                         ("health", "application_health_not_observed")):
        add(prop, reason=reason)
    batch = ObservationBatch(host_id, when, tuple(facts), (resource["id"],), LIMITATIONS)
    inventory = {"accepted_engine_id": accepted_engine_id, "project": project,
                 "state": "unknown" if error else "known", "reason": error,
                 "consumer_scope": "project_labelled_containers_including_stopped",
                 "consumers_exhaustive": False, "limitations": list(LIMITATIONS),
                 **(snapshot or {name: [] for name in ("containers", "images", "volumes", "networks", "binds")})}
    return ComposeInventory(batch, canonical_json(inventory))
