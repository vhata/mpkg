"""Pure preflight of a closed JSON Compose subset over private captured bytes.

This validates supported references, not capture authenticity, native merge or
effective configuration. No files, environment variables or tools are read.
"""
from dataclasses import dataclass, field
import json
import re


SUBSET = "compose_json_no_interpolation_v1"
MAX_FILES = 64
MAX_SOURCES = 16
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_REFERENCES = 1024
MAX_ITEMS = 256
MAX_NODES = 16384
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}\Z")
_ENGINE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_ENV_VALUE = re.compile(r"[A-Za-z0-9_./:@%+,= -]*\Z")


class ComposeInputError(ValueError):
    """Fixed diagnostics; never include private paths, bytes or values."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class CapturedComposeFile:
    """Private value supplied by a trusted reader; construction is not proof."""
    path: str = field(repr=False)
    classification: str
    raw: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ComposeInputBundle:
    """Exact caller-owned capture context, without inherited environment."""
    engine: str = field(repr=False)
    project: str = field(repr=False)
    base_directory: str = field(repr=False)
    source_paths: tuple[str, ...] = field(repr=False)
    services: tuple[str, ...] = field(repr=False)
    profiles: tuple[str, ...] = field(repr=False)
    files: tuple[CapturedComposeFile, ...] = field(repr=False)
    interpolation_environment: tuple[tuple[str, str], ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ComposeInputReference:
    """Private occurrence in one original document; no merged-model claim."""
    source_index: int
    kind: str
    owner: str = field(repr=False)
    position: int
    path: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ValidatedComposeInputs:
    """Immutable private preparation; it is not an execution authorization."""
    bundle: ComposeInputBundle = field(repr=False)
    references: tuple[ComposeInputReference, ...] = field(repr=False)

    def as_dict(self):
        """Redact all source identities, names, paths, bytes and digests."""
        return {"subset": SUBSET, "source_count": len(self.bundle.source_paths),
                "captured_file_count": len(self.bundle.files),
                "reference_count": len(self.references),
                "supported_reference_closure": "complete",
                "capture_authentication": "caller_required",
                "effective_model": "unverified", "full_input_closure": "unverified",
                "apply_authorized": False}


def _fail(code="unsupported_compose_schema"):
    raise ComposeInputError(code)


def _require(condition, code="unsupported_compose_schema"):
    if not condition:
        _fail(code)


def _string(value, *, empty=False):
    _require(type(value) is str and len(value) <= 65536 and (empty or value))
    _require(not any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF
                     for char in value))
    return value


def _literal(value, *, empty=False):
    value = _string(value, empty=empty)
    # Preserve original $$ bytes; never perform interpolation or dollar rewriting.
    _require("$" not in value.replace("$$", ""), "unsupported_compose_interpolation")
    return value


def _name(value, pattern=_NAME):
    _require(type(value) is str and pattern.fullmatch(value) is not None)
    return value


def _path(value):
    value = _string(value)
    _require(len(value) <= 4096 and value.startswith("/") and value != "/"
             and not any(char in value for char in "$\\:")
             and all(part not in ("", ".", "..") for part in value[1:].split("/")),
             "unsupported_compose_path")
    return value


def _resolve(value, base, *, captured):
    value = _string(value)
    if value.startswith("/"):
        resolved = _path(value)
    else:
        if value.startswith("./"):
            value = value[2:]
        _require(not any(char in value for char in "$\\:~")
                 and all(part not in ("", ".", "..") for part in value.split("/")),
                 "unsupported_compose_path")
        resolved = _path(base + "/" + value)
    _require(not captured or resolved.startswith(base + "/"), "compose_input_outside_base")
    return resolved


def _object(value, allowed, required=()):
    _require(type(value) is dict and len(value) <= MAX_ITEMS)
    _require(set(value) <= set(allowed) and set(required) <= set(value))
    return value


def _list(value):
    _require(type(value) is list and len(value) <= MAX_ITEMS)
    return value


def _names(value):
    value = [_name(item) for item in _list(value)]
    _require(len(set(value)) == len(value), "duplicate_compose_reference")
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate_compose_key")
        result[key] = value
    return result


def _document(raw):
    _require(len(raw) <= MAX_DOCUMENT_BYTES, "compose_input_limit")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail("unsupported_compose_json"),
                           parse_float=lambda _: _fail("unsupported_compose_json"))
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ComposeInputError):
            raise
        raise ComposeInputError("unsupported_compose_json") from None
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _require(count <= MAX_NODES and depth <= 16, "compose_input_limit")
        if type(item) is dict:
            _require(len(item) <= MAX_ITEMS, "compose_input_limit")
            for key, child in item.items():
                _string(key)
                pending.append((child, depth + 1))
        elif type(item) is list:
            _require(len(item) <= MAX_ITEMS, "compose_input_limit")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            _literal(item, empty=True)
    return value


def _environment_file(raw):
    # An intentionally narrow grammar, not an approximation of dotenv parsing.
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise ComposeInputError("unsupported_compose_env_file") from None
    names = set()
    for line in text.split("\n"):
        if not line:
            continue
        key, equal, value = line.partition("=")
        _require(equal and _ENV_KEY.fullmatch(key) and _ENV_VALUE.fullmatch(value)
                 and value == value.strip() and key not in names,
                 "unsupported_compose_env_file")
        names.add(key)
        _require(len(names) <= MAX_ITEMS, "compose_input_limit")


class _Validator:
    def __init__(self, bundle, files):
        self.bundle, self.files = bundle, files
        self.references = []
        self.roles = {path: "source" for path in bundle.source_paths}
        self.declared = {kind: set() for kind in ("services", "volumes", "networks", "configs", "secrets")}
        self.links = []
        self.profiles = set()

    def reference(self, source, kind, owner, position, path):
        captured = kind != "bind"
        path = _resolve(path, self.bundle.base_directory, captured=captured)
        if captured:
            _require(path in self.files, "missing_compose_capture")
            _require(path not in self.roles or self.roles[path] == kind,
                     "conflicting_compose_input_role")
            if kind == "secret":
                _require(self.files[path].classification == "protected",
                         "compose_secret_requires_protected_capture")
            if kind == "env" and path not in self.roles:
                _environment_file(self.files[path].raw)
            self.roles[path] = kind
        self.references.append(ComposeInputReference(source, kind, owner, position, path))
        _require(len(self.references) <= MAX_REFERENCES, "compose_input_limit")
        return path

    def service(self, source, name, value):
        _object(value, ("image", "platform", "restart", "network_mode", "environment", "env_file",
                        "profiles", "volumes", "networks", "configs", "secrets", "command", "entrypoint"))
        for key in ("image", "platform", "restart", "network_mode"):
            if key in value:
                _literal(value[key])
        if "restart" in value:
            _require(value["restart"] in ("no", "always", "on-failure", "unless-stopped"))
        if "network_mode" in value:
            _require(value["network_mode"] in ("host", "none") and "networks" not in value)
        for key in ("command", "entrypoint"):
            if key in value:
                if type(value[key]) is list:
                    for item in _list(value[key]):
                        _literal(item, empty=True)
                else:
                    _literal(value[key], empty=True)
        if "environment" in value:
            environment = value["environment"]
            _require(type(environment) is dict and len(environment) <= MAX_ITEMS)
            for key, item in environment.items():
                _name(key, _ENV_KEY)
                _literal(item, empty=True)
        if "env_file" in value:
            paths = value["env_file"]
            paths = [paths] if type(paths) is str else _list(paths)
            resolved = [self.reference(source, "env", name, position, path)
                        for position, path in enumerate(paths)]
            _require(len(set(resolved)) == len(resolved), "duplicate_compose_reference")
        if "profiles" in value:
            self.profiles.update(_names(value["profiles"]))
        for kind in ("networks", "configs", "secrets"):
            if kind in value:
                for target in _names(value[kind]):
                    self.links.append((kind, target))
        if "volumes" in value:
            targets = set()
            for position, mount in enumerate(_list(value["volumes"])):
                _object(mount, ("type", "source", "target", "read_only"), ("type", "source", "target"))
                _require(mount["type"] in ("bind", "volume"))
                target = _path(mount["target"])
                _require(target not in targets, "duplicate_compose_reference")
                targets.add(target)
                if "read_only" in mount:
                    _require(type(mount["read_only"]) is bool)
                if mount["type"] == "bind":
                    self.reference(source, "bind", name, position, mount["source"])
                else:
                    self.links.append(("volumes", _name(mount["source"])))

    def document(self, source, value):
        _object(value, self.declared, ("services",))
        for kind, declarations in value.items():
            _require(type(declarations) is dict and len(declarations) <= MAX_ITEMS)
            if kind == "services":
                _require(declarations)
            for name, body in declarations.items():
                _name(name)
                self.declared[kind].add(name)
                if kind == "services":
                    self.service(source, name, body)
                elif kind in ("configs", "secrets"):
                    _object(body, ("file",), ("file",))
                    self.reference(source, "config" if kind == "configs" else "secret",
                                   name, 0, body["file"])
                else:
                    if body is None:
                        body = {}
                    _object(body, ("name", "external"))
                    if "name" in body:
                        _name(body["name"])
                    if "external" in body:
                        _require(type(body["external"]) is bool)


def validate_compose_bundle(bundle):
    """Validate captured reference coverage without reads or native execution.

    Every supplied file must be an original ordered source or a supported
    referenced file. Bind sources are lexical paths, not captured contents.
    The caller must separately authenticate captures and preserve privacy.
    """
    _require(type(bundle) is ComposeInputBundle, "invalid_compose_bundle")
    _name(bundle.engine, _ENGINE)
    _name(bundle.project, _PROJECT)
    _path(bundle.base_directory)
    _require(type(bundle.interpolation_environment) is tuple
             and not bundle.interpolation_environment, "unsupported_compose_interpolation")
    for names, minimum, maximum in ((bundle.source_paths, 1, MAX_SOURCES),
                                    (bundle.services, 1, MAX_ITEMS), (bundle.profiles, 0, MAX_ITEMS)):
        _require(type(names) is tuple and minimum <= len(names) <= maximum, "invalid_compose_bundle")
        _require(all(type(name) is str for name in names), "invalid_compose_bundle")
        _require(len(set(names)) == len(names), "duplicate_compose_reference")
    for name in bundle.services + bundle.profiles:
        _name(name)
    _require(type(bundle.files) is tuple and 1 <= len(bundle.files) <= MAX_FILES,
             "compose_input_limit")
    files, total = {}, 0
    for captured in bundle.files:
        _require(type(captured) is CapturedComposeFile, "invalid_compose_bundle")
        _path(captured.path)
        _require(captured.path.startswith(bundle.base_directory + "/"), "compose_input_outside_base")
        _require(captured.path not in files, "duplicate_compose_capture")
        _require(captured.classification in ("nonsecret", "protected")
                 and type(captured.raw) is bytes, "invalid_compose_capture")
        total += len(captured.raw)
        _require(len(captured.raw) <= MAX_FILE_BYTES and total <= MAX_BUNDLE_BYTES, "compose_input_limit")
        files[captured.path] = captured
    validator = _Validator(bundle, files)
    for index, path in enumerate(bundle.source_paths):
        _path(path)
        _require(path in files, "missing_compose_capture")
        validator.document(index, _document(files[path].raw))
    _require(set(files) == set(validator.roles), "unexpected_compose_capture")
    _require(set(bundle.services) <= validator.declared["services"], "unknown_compose_selection")
    _require(set(bundle.profiles) <= validator.profiles, "unknown_compose_selection")
    _require(all(name in validator.declared[kind] for kind, name in validator.links),
             "unknown_compose_reference")
    return ValidatedComposeInputs(bundle, tuple(validator.references))
