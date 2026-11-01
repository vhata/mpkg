"""Pure, closed-schema declaration validation and immutable snapshots.

Parsing never reads referenced files, resolves live host identities, or invokes
an integration. A valid declaration is intent, not an executable plan.
"""
from dataclasses import dataclass
import hashlib
import json
import posixpath
import re
import tomllib


SCHEMA_VERSION = 1
NORMALIZATION_VERSION = 1
MAX_DECLARATION_BYTES = 16 * 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")


class DeclarationError(ValueError):
    """A bounded code and structural location, never source or field values."""

    def __init__(self, code, path=()):
        self.code = code
        self.path = tuple(path)
        super().__init__(code)


def _fail(code, path=()):
    raise DeclarationError(code, path)


def _json_value(value, path=()):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            _fail("integer_out_of_range", path)
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            _fail("invalid_unicode", path)
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _json_value(item, path + (index,))
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail("invalid_object_key", path)
            _json_value(key, path)
            # Do not put arbitrary caller-supplied keys into diagnostics.
            _json_value(item, path)
        return
    _fail("unsupported_value_type", path)


def canonical_json(value):
    """Encode fixed JSON scalar types, preserving meaningful array order."""
    _json_value(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class Declaration:
    source_bytes: bytes
    canonical_bytes: bytes
    sha256: str
    schema_version: int = SCHEMA_VERSION
    normalization_version: int = NORMALIZATION_VERSION

    @property
    def model(self):
        """Return a fresh projection; callers cannot change this snapshot."""
        return json.loads(self.canonical_bytes)


def _object(value, allowed, required, path):
    if type(value) is not dict:
        _fail("expected_table", path)
    if set(value) - set(allowed):
        _fail("unknown_key", path)
    if set(required) - set(value):
        _fail("missing_key", path)
    return value


def _string(value, path):
    if type(value) is not str or not value or "\0" in value:
        _fail("expected_nonempty_string", path)
    return value


def _identifier(value, path):
    if type(value) is not str or not _ID.fullmatch(value):
        _fail("invalid_identifier", path)
    return value


def _name(value, path):
    if type(value) is not str or not _NAME.fullmatch(value):
        _fail("invalid_name", path)
    return value


def _boolean(value, path):
    if type(value) is not bool:
        _fail("expected_boolean", path)
    return value


def _integer(value, path, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        _fail("integer_out_of_range", path)
    return value


def _enum(value, choices, path):
    if type(value) is not str or value not in choices:
        _fail("unsupported_value", path)
    return value


def _path(value, path):
    value = _string(value, path)
    if not value.startswith("/") or value.startswith("//"):
        _fail("expected_absolute_path", path)
    return posixpath.normpath(value)


def _list(value, path, validate, *, unique=True):
    if type(value) is not list:
        _fail("expected_array", path)
    result = [validate(item, path + (index,)) for index, item in enumerate(value)]
    if unique and len({canonical_json(item) for item in result}) != len(result):
        _fail("duplicate_value", path)
    return result


def _version(value, path):
    value = _object(value, ("policy", "value", "recipe_revision"), ("policy",), path)
    policy = _enum(value["policy"], ("any", "exact"), path + ("policy",))
    if policy == "any" and set(value) != {"policy"}:
        _fail("unexpected_version_binding", path)
    if policy == "exact" and "value" not in value:
        _fail("missing_exact_version", path)
    return {key: _string(item, path + (key,)) for key, item in value.items()}


def _images(value, path):
    def image(item, location):
        item = _object(item, ("service", "policy", "reference", "digest", "platform",
                              "updates_allowed"), ("service", "policy", "reference"), location)
        result = {"service": _name(item["service"], location + ("service",)),
                  "policy": _enum(item["policy"], ("any", "exact"), location + ("policy",)),
                  "reference": _string(item["reference"], location + ("reference",))}
        for key in ("digest", "platform"):
            if key in item:
                result[key] = _string(item[key], location + (key,))
        if result["policy"] == "exact":
            if not {"digest", "platform"} <= set(result):
                _fail("missing_exact_image_binding", location)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", result["digest"]):
                _fail("invalid_image_digest", location + ("digest",))
        elif "digest" in item:
            _fail("unexpected_image_binding", location)
        if "updates_allowed" in item:
            result["updates_allowed"] = _boolean(item["updates_allowed"], location + ("updates_allowed",))
        return result
    result = _list(value, path, image)
    if len({item["service"] for item in result}) != len(result):
        _fail("duplicate_image_service", path)
    return result


_PATH_PROPERTIES = {"present": _boolean, "owner": _name, "group": _name,
                    "mode": lambda value, path: _integer(value, path, 0, 0o7777)}
_PROPERTIES = {
    "package": {"present": _boolean,
                "source": lambda value, path: _enum(value, ("repository", "aur", "unknown"), path),
                "version": _version},
    "compose": {"running": _boolean, "profiles": lambda value, path: _list(value, path, _name),
                "services": lambda value, path: _list(value, path, _name), "images": _images},
    "volume": {"present": _boolean},
    "network": {"present": _boolean},
    "service": {"running": _boolean, "enabled": _boolean},
    "user": {"present": _boolean, "home": _path, "shell": _path, "primary_group": _name,
             "groups": lambda value, path: _list(value, path, _name)},
    "group": {"present": _boolean, "members": lambda value, path: _list(value, path, _name)},
    "file": _PATH_PROPERTIES | {"content": _string, "content_input": _identifier},
    "directory": _PATH_PROPERTIES,
    "symlink": _PATH_PROPERTIES | {"target": _string},
    "sonarr_xml": {"port": lambda value, path: _integer(value, path, 1024, 65535)},
}


def _identity(kind, value, path):
    keys = {"package": ("name",), "compose": ("engine", "project"),
            "volume": ("engine", "name"), "network": ("engine", "name"),
            "service": ("manager", "unit"), "user": ("name",), "group": ("name",),
            "file": ("path",), "directory": ("path",), "symlink": ("path",),
            "sonarr_xml": ("path",)}[kind]
    value = _object(value, keys, keys, path)
    result = {}
    for key, item in value.items():
        at = path + (key,)
        if key == "path":
            result[key] = _path(item, at)
        elif key == "manager":
            result[key] = _enum(item, ("system",), at)
        else:
            result[key] = _name(item, at)
    return result


def _physical_key(resource):
    kind, identity = resource["kind"], resource["identity"]
    if "path" in identity:
        return ("path", identity["path"])
    return (kind, *[identity[key] for key in sorted(identity)])


def physical_key(resource, host_id, engine_aliases):
    """Bind a validated declaration identity to accepted host/engine IDs."""
    host_id = _string(host_id, ("host_id",))
    identity = dict(resource["identity"])
    if "engine" in identity:
        alias = identity["engine"]
        if alias not in engine_aliases:
            _fail("unbound_engine_alias", ("identity", "engine"))
        identity["engine"] = _string(engine_aliases[alias], ("engine_id",))
    return (host_id, *_physical_key(resource | {"identity": identity}))


def _resource(value, path):
    value = _object(value, ("id", "kind", "identity", "purpose", "manage", "desired",
                            "consumers", "checks", "input", "requires"),
                    ("id", "kind", "identity"), path)
    kind = _enum(value["kind"], _PROPERTIES, path + ("kind",))
    result = {"id": _identifier(value["id"], path + ("id",)), "kind": kind,
              "identity": _identity(kind, value["identity"], path + ("identity",))}
    desired = _object(value.get("desired", {}), _PROPERTIES[kind], (), path + ("desired",))
    result["desired"] = {key: _PROPERTIES[kind][key](item, path + ("desired", key))
                         for key, item in desired.items()}
    for key in ("manage", "consumers", "checks", "requires"):
        result[key] = _list(value.get(key, []), path + (key,), _identifier)
    if not set(result["manage"]) <= set(desired):
        _fail("managed_property_without_value", path + ("manage",))
    if kind == "package":
        version = result["desired"].get("version", {})
        if (result["desired"].get("source") == "aur" and version.get("policy") == "exact"
                and "recipe_revision" not in version):
            _fail("missing_recipe_revision", path + ("desired", "version"))
        if "recipe_revision" in version and result["desired"].get("source") != "aur":
            _fail("unexpected_recipe_revision", path + ("desired", "version"))
    if kind == "file" and {"content", "content_input"} <= set(desired):
        _fail("conflicting_content_sources", path + ("desired",))
    if "purpose" in value:
        result["purpose"] = _string(value["purpose"], path + ("purpose",))
    if "input" in value:
        item = _object(value["input"], ("bundle",), ("bundle",), path + ("input",))
        result["input"] = {"bundle": _identifier(item["bundle"], path + ("input", "bundle"))}
    return result


def _component(value, path):
    value = _object(value, ("id", "purpose", "resources", "requirements"),
                    ("id", "purpose", "resources"), path)
    result = {"id": _identifier(value["id"], path + ("id",)),
              "purpose": _string(value["purpose"], path + ("purpose",)),
              "resources": _list(value["resources"], path + ("resources",), _identifier)}
    if result["id"].startswith("external:"):
        _fail("reserved_component_identifier", path + ("id",))
    def requirement(item, at):
        item = _object(item, ("resource", "property", "value"),
                       ("resource", "property", "value"), at)
        return {"resource": _identifier(item["resource"], at + ("resource",)),
                "property": _identifier(item["property"], at + ("property",)), "value": item["value"]}
    result["requirements"] = _list(value.get("requirements", []), path + ("requirements",), requirement)
    return result


def _unique(items, path):
    result = {}
    for index, item in enumerate(items):
        if item["id"] in result:
            _fail("duplicate_identifier", path + (index, "id"))
        result[item["id"]] = item
    return result


def _validate(model):
    _object(model, ("schema", "components", "resources", "inputs", "checks", "runtime_rules"),
            ("schema", "components", "resources"), ())
    if type(model["schema"]) is not int or model["schema"] != SCHEMA_VERSION:
        _fail("unsupported_schema", ("schema",))
    result = {"schema": SCHEMA_VERSION,
              "components": _list(model["components"], ("components",), _component),
              "resources": _list(model["resources"], ("resources",), _resource)}
    # These typed extensions are intentionally unavailable in the first API
    # checkpoint rather than accepting unchecked opaque values.
    for key in ("inputs", "checks", "runtime_rules"):
        value = model.get(key, [])
        if type(value) is not list:
            _fail("expected_array", (key,))
        if value:
            _fail("declaration_extension_not_supported", (key,))
        result[key] = []
    components = _unique(result["components"], ("components",))
    resources = _unique(result["resources"], ("resources",))
    physical = set()
    for index, resource in enumerate(result["resources"]):
        at = ("resources", index)
        key = _physical_key(resource)
        if key in physical:
            _fail("duplicate_physical_identity", at + ("identity",))
        physical.add(key)
        for reference in resource["consumers"]:
            if reference not in components and not reference.startswith("external:"):
                _fail("missing_consumer", at + ("consumers",))
        if any(reference not in resources for reference in resource["requires"]):
            _fail("missing_resource", at + ("requires",))
        if resource["checks"] or "input" in resource or "content_input" in resource["desired"]:
            _fail("missing_reference", at)
    requirements = {}
    for index, component in enumerate(result["components"]):
        at = ("components", index)
        if any(reference not in resources for reference in component["resources"]):
            _fail("missing_resource", at + ("resources",))
        for requirement in component["requirements"]:
            reference, prop = requirement["resource"], requirement["property"]
            if reference not in component["resources"]:
                _fail("requirement_outside_component", at + ("requirements",))
            resource = resources[reference]
            if prop not in _PROPERTIES[resource["kind"]]:
                _fail("unsupported_property", at + ("requirements",))
            value = _PROPERTIES[resource["kind"]][prop](requirement["value"], at + ("requirements",))
            requirement["value"] = value
            encoded = canonical_json(value)
            key = (reference, prop)
            if key in requirements and requirements[key] != encoded:
                _fail("conflicting_requirements", at + ("requirements",))
            if prop in resource["desired"] and canonical_json(resource["desired"][prop]) != encoded:
                _fail("conflicting_requirements", at + ("requirements",))
            requirements[key] = encoded
    # Iterative traversal keeps deeply nested valid graphs off Python's stack.
    states = {}
    for root in resources:
        stack = [(root, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                states[node] = 2
            elif states.get(node) == 1:
                _fail("resource_reference_cycle", ("resources",))
            elif states.get(node) != 2:
                states[node] = 1
                stack.append((node, True))
                stack.extend((child, False) for child in reversed(resources[node]["requires"]))
    return result


def load_declaration(raw):
    """Validate TOML bytes without reading referenced files or host facts."""
    if type(raw) is not bytes:
        _fail("expected_bytes")
    if len(raw) > MAX_DECLARATION_BYTES:
        _fail("declaration_too_large")
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        raise DeclarationError("invalid_toml") from None
    try:
        _json_value(parsed)
        model = _validate(parsed)
        encoded = canonical_json(model)
    except RecursionError:
        raise DeclarationError("declaration_nesting_limit") from None
    return Declaration(raw, encoded, hashlib.sha256(encoded).hexdigest())
