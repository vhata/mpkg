"""Pure, closed-schema declaration validation and immutable snapshots.

Parsing never reads referenced files, resolves live host identities, or invokes
an integration. A valid declaration is intent, not an executable plan.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import posixpath
import re
import tomllib
from urllib.parse import urlsplit
import uuid


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
    try:
        _json_value(value)
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except RecursionError:
        raise DeclarationError("declaration_nesting_limit") from None


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


def _text(value, path):
    if type(value) is not str or "\0" in value:
        _fail("expected_text", path)
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


def _relative_path(value, path):
    value = _string(value, path)
    normalized = posixpath.normpath(value)
    if (value.startswith("/") or normalized in (".", "..")
            or normalized.startswith("../")):
        _fail("expected_contained_relative_path", path)
    return normalized


def _opaque_reference(value, path):
    value = _string(value, path)
    try:
        valid = str(uuid.UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        _fail("invalid_protected_reference", path)
    return value


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
    result = {key: _string(item, path + (key,)) for key, item in value.items()}
    if "value" in result and (len(result["value"]) > 255 or
                               any(char.isspace() for char in result["value"])):
        _fail("invalid_exact_version", path + ("value",))
    if "recipe_revision" in result and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", result["recipe_revision"]):
        _fail("invalid_recipe_revision", path + ("recipe_revision",))
    return result


def _package_version_binding(properties, path):
    version = properties.get("version", {})
    if (properties.get("source") == "aur" and version.get("policy") == "exact"
            and "recipe_revision" not in version):
        _fail("missing_recipe_revision", path)
    if "recipe_revision" in version and properties.get("source") != "aur":
        _fail("unexpected_recipe_revision", path)


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
    "file": _PATH_PROPERTIES | {"content": _text, "content_input": _identifier},
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


def _input(value, path):
    value = _object(value, ("id", "base_directory", "files"),
                    ("id", "base_directory", "files"), path)
    def item(entry, at):
        entry = _object(entry, ("path", "classification", "reference"),
                        ("path", "classification"), at)
        result = {"path": _relative_path(entry["path"], at + ("path",)),
                  "classification": _enum(entry["classification"], ("nonsecret", "protected"),
                                          at + ("classification",))}
        if result["classification"] == "protected":
            if "reference" not in entry:
                _fail("missing_protected_reference", at)
            result["reference"] = _opaque_reference(entry["reference"], at + ("reference",))
        elif "reference" in entry:
            _fail("unexpected_protected_reference", at)
        return result
    files = _list(value["files"], path + ("files",), item)
    if not files:
        _fail("empty_input_bundle", path + ("files",))
    if len({entry["path"] for entry in files}) != len(files):
        _fail("duplicate_input_path", path + ("files",))
    return {"id": _identifier(value["id"], path + ("id",)),
            "base_directory": _path(value["base_directory"], path + ("base_directory",)),
            "files": files}


def _endpoint_url(value, path):
    value = _string(value, path)
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        _fail("unsupported_endpoint_url", path)
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme in ("http", "https") and parsed.hostname in ("localhost", "127.0.0.1", "::1")
                 and parsed.username is None and parsed.password is None
                 and not parsed.fragment and not parsed.query and parsed.port is not None)
    except ValueError:
        valid = False
    if not valid:
        _fail("unsupported_endpoint_url", path)
    return value


def _check(value, path):
    common = ("id", "kind", "resource", "timeout_seconds")
    if type(value) is not dict:
        _fail("expected_table", path)
    kind = _enum(value.get("kind"), ("package", "service", "endpoint", "access"), path + ("kind",))
    extra = {"package": ("expected",), "service": ("expected",),
             "endpoint": ("url", "expected_status"),
             "access": ("as_user", "operation", "consumer")}[kind]
    _object(value, common + extra, common + extra, path)
    result = {"id": _identifier(value["id"], path + ("id",)), "kind": kind,
              "resource": _identifier(value["resource"], path + ("resource",)),
              "timeout_seconds": _integer(value["timeout_seconds"], path + ("timeout_seconds",), 1, 60)}
    if kind in ("package", "service"):
        validators = ({"present": _boolean, "version": _string,
                       "reason": lambda item, at: _enum(item, ("explicit", "dependency"), at)}
                      if kind == "package" else {"running": _boolean, "enabled": _boolean})
        expected = _object(value["expected"], validators, (), path + ("expected",))
        if not expected:
            _fail("empty_check_expectation", path + ("expected",))
        result["expected"] = {key: validators[key](item, path + ("expected", key))
                              for key, item in expected.items()}
    elif kind == "endpoint":
        result["url"] = _endpoint_url(value["url"], path + ("url",))
        result["expected_status"] = _integer(value["expected_status"], path + ("expected_status",), 100, 599)
    else:
        result["as_user"] = _name(value["as_user"], path + ("as_user",))
        result["operation"] = _enum(value["operation"], ("read", "list"), path + ("operation",))
        result["consumer"] = _identifier(value["consumer"], path + ("consumer",))
    return result


def _runtime_rule(value, path):
    keys = ("id", "component", "root", "patterns", "types", "exceptions")
    value = _object(value, keys, keys, path)
    def pattern(item, at):
        item = _string(item, at)
        if item.startswith("/") or ".." in item.split("/"):
            _fail("invalid_runtime_pattern", at)
        return item
    result = {"id": _identifier(value["id"], path + ("id",)),
              "component": _identifier(value["component"], path + ("component",)),
              "root": _path(value["root"], path + ("root",)),
              "patterns": _list(value["patterns"], path + ("patterns",), pattern),
              "types": _list(value["types"], path + ("types",),
                             lambda item, at: _enum(item, ("file", "directory", "symlink"), at)),
              "exceptions": _list(value["exceptions"], path + ("exceptions",), _path)}
    if not result["patterns"] or not result["types"]:
        _fail("empty_runtime_scope", path)
    if any(not _within(item, result["root"]) for item in result["exceptions"]):
        _fail("runtime_exception_outside_root", path + ("exceptions",))
    return result


def _within(path, root):
    return root == "/" or path == root or path.startswith(root + "/")


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
    for key, validator in (("inputs", _input), ("checks", _check), ("runtime_rules", _runtime_rule)):
        result[key] = _list(model.get(key, []), (key,), validator)
    components = _unique(result["components"], ("components",))
    resources = _unique(result["resources"], ("resources",))
    inputs = _unique(result["inputs"], ("inputs",))
    checks = _unique(result["checks"], ("checks",))
    _unique(result["runtime_rules"], ("runtime_rules",))
    physical = set()
    for index, resource in enumerate(result["resources"]):
        at = ("resources", index)
        key = _physical_key(resource)
        if key in physical:
            _fail("duplicate_physical_identity", at + ("identity",))
        physical.add(key)
        for reference in resource["consumers"]:
            if (reference not in components and not reference.startswith("external:")
                    or reference == "external:"):
                _fail("missing_consumer", at + ("consumers",))
            if reference in components and resource["id"] not in components[reference]["resources"]:
                _fail("consumer_without_resource_reference", at + ("consumers",))
        if any(reference not in resources for reference in resource["requires"]):
            _fail("missing_resource", at + ("requires",))
        for reference in resource["checks"]:
            if reference not in checks or checks[reference]["resource"] != resource["id"]:
                _fail("missing_or_mismatched_check", at + ("checks",))
        if "input" in resource and resource["input"]["bundle"] not in inputs:
            _fail("missing_input", at + ("input",))
    requirements = {}
    requirement_paths = {}
    for index, component in enumerate(result["components"]):
        at = ("components", index)
        if any(reference not in resources for reference in component["resources"]):
            _fail("missing_resource", at + ("resources",))
        for reference in component["resources"]:
            if component["id"] not in resources[reference]["consumers"]:
                resources[reference]["consumers"].append(component["id"])
        for requirement_index, requirement in enumerate(component["requirements"]):
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
            if key in requirements and canonical_json(requirements[key]) != encoded:
                _fail("conflicting_requirements", at + ("requirements",))
            if prop in resource["desired"] and canonical_json(resource["desired"][prop]) != encoded:
                _fail("conflicting_requirements", at + ("requirements",))
            requirements[key] = value
            requirement_paths[key] = at + ("requirements", requirement_index, "value")
    for index, resource in enumerate(result["resources"]):
        # Every kind's contextual checks use the combined constraints, without
        # promoting consumer requirements into desired state or authority.
        effective = dict(resource["desired"])
        at = ("resources", index, "desired")
        property_paths = {prop: at + (prop,) for prop in effective}
        for prop in _PROPERTIES[resource["kind"]]:
            key = (resource["id"], prop)
            if key in requirements and prop not in effective:
                effective[prop] = requirements[key]
                property_paths[prop] = requirement_paths[key]
        if resource["kind"] == "package":
            _package_version_binding(effective, property_paths.get("version", at))
        if resource["kind"] == "file":
            if {"content", "content_input"} <= set(effective):
                _fail("conflicting_content_sources", property_paths["content_input"])
            if "content_input" in effective:
                reference = effective["content_input"]
                if reference not in inputs or len(inputs[reference]["files"]) != 1:
                    _fail("content_requires_single_file_input", property_paths["content_input"])
    check_resources = {"package": {"package"}, "service": {"service"},
                       "endpoint": {"compose", "service"},
                       "access": {"file", "directory", "symlink", "volume"}}
    for index, check in enumerate(result["checks"]):
        at = ("checks", index)
        if check["resource"] not in resources:
            _fail("missing_resource", at + ("resource",))
        resource = resources[check["resource"]]
        if resource["kind"] not in check_resources[check["kind"]]:
            _fail("check_resource_kind_mismatch", at + ("resource",))
        if check["kind"] == "access" and check["consumer"] not in resource["consumers"]:
            _fail("unknown_access_consumer", at + ("consumer",))
    for index, rule in enumerate(result["runtime_rules"]):
        at = ("runtime_rules", index)
        if rule["component"] not in components:
            _fail("missing_component", at + ("component",))
        for resource in resources.values():
            if (resource["kind"] in ("file", "sonarr_xml")
                    and _within(resource["identity"]["path"], rule["root"])
                    and resource["identity"]["path"] not in rule["exceptions"]):
                _fail("runtime_scope_hides_configuration", at + ("exceptions",))
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


def validate_model(value):
    """Normalize decoded declaration data without retaining caller objects."""
    try:
        # Validate fixed types before copying so caller-defined objects cannot
        # supply copy hooks. Normalization only touches this private copy.
        _json_value(value)
        return _validate(deepcopy(value))
    except RecursionError:
        raise DeclarationError("declaration_nesting_limit") from None


def load_declaration(raw):
    """Validate TOML bytes without reading referenced files or host facts."""
    if type(raw) is not bytes:
        _fail("expected_bytes")
    if len(raw) > MAX_DECLARATION_BYTES:
        _fail("declaration_too_large")
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        # tomllib can also raise plain ValueError for Python's integer
        # conversion limit; no parser diagnostics belong in public output.
        raise DeclarationError("invalid_toml") from None
    model = validate_model(parsed)
    encoded = canonical_json(model)
    return Declaration(raw, encoded, hashlib.sha256(encoded).hexdigest())
