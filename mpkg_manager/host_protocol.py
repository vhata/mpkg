"""Closed wire requests for the installed host helper.

Parsing is pure. A parsed request is data, not an authorization capability.
"""
from dataclasses import dataclass, field
import json
import re
import uuid

from .declarations import DeclarationError, MAX_DECLARATION_BYTES, load_declaration


PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 20 * 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_SELECTION = 4096
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_VERBS = frozenset({"observe", "record", "prepare", "plan", "apply", "recover", "export"})


class RequestError(ValueError):
    """Fixed public diagnostics without request contents or parser messages."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class HostRequest:
    verb: str
    operation: str
    expected_revision: int | None = None
    source: bytes | None = field(default=None, repr=False)
    resource_ids: tuple = field(default=(), repr=False)
    selected_components: tuple | None = field(default=None, repr=False)
    probe_endpoints: bool = False
    capture_inputs: bool = False
    check_file_content: bool = False
    attribute_endpoints: bool = False
    check_consumer_access: bool = False
    preparation_id: str | None = field(default=None, repr=False)
    include_attempts: bool = False
    page_limit: int = 20
    after_id: str | None = None
    attempt_id: str | None = None
    after_event: int = 0
    plan_id: str | None = None
    expected_sequence: int = 0
    interruption: str | None = None


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RequestError("invalid_request")
        value[key] = item
    return value


def _reject_number(value):
    raise RequestError("invalid_request")


def _selection(value, *, stable=False, empty=False):
    if (type(value) is not list or not (0 if empty else 1) <= len(value) <= MAX_SELECTION
            or any(type(item) is not str for item in value) or len(set(value)) != len(value)):
        raise RequestError("invalid_request")
    for item in value:
        if stable:
            try:
                if str(uuid.UUID(item)) != item:
                    raise ValueError
            except ValueError:
                raise RequestError("invalid_request") from None
        elif not _IDENTIFIER.fullmatch(item):
            raise RequestError("invalid_request")
    return tuple(value)


def _status(arguments):
    if arguments.get("operation") != "status":
        raise RequestError("operation_unsupported")
    keys = {"operation", "expected_revision", "source", "source_is_nonsecret",
            "selected_components", "probe_endpoints"}
    keys.update(name for name in ("check_file_content", "attribute_endpoints", "check_consumer_access", "include_attempts")
                if name in arguments)
    if set(arguments) != keys:
        raise RequestError("invalid_request")
    revision = arguments["expected_revision"]
    if revision is not None and (type(revision) is not int or not 0 <= revision < 2**63 - 1):
        raise RequestError("invalid_request")
    if type(arguments["probe_endpoints"]) is not bool:
        raise RequestError("invalid_request")
    options = {name: arguments.get(name, False) for name in
               ("check_file_content", "attribute_endpoints", "check_consumer_access", "include_attempts")}
    if any(type(value) is not bool for value in options.values()):
        raise RequestError("invalid_request")
    selection = arguments["selected_components"]
    selection = None if selection is None else _selection(selection, empty=True)
    source = arguments["source"]
    if source is None:
        if arguments["source_is_nonsecret"] is not False:
            raise RequestError("invalid_request")
    else:
        if type(source) is not str or arguments["source_is_nonsecret"] is not True:
            raise RequestError("invalid_request")
        source = source.encode("utf-8")
        if len(source) > MAX_DECLARATION_BYTES:
            raise RequestError("request_size_limit")
        declaration = load_declaration(source)
        if selection is not None and not set(selection) <= {item["id"] for item in declaration.model["components"]}:
            raise RequestError("invalid_status_selection")
    return HostRequest("observe", "status", revision, source,
                       selected_components=selection, probe_endpoints=arguments["probe_endpoints"],
                       **options)


def _execution(verb, arguments):
    operation = arguments.get("operation")
    keys = {
        ("prepare", "execution"): {"operation", "expected_revision", "resource_ids", "interruption"},
        ("plan", "accept"): {"operation", "plan_id"},
        ("plan", "inspect"): {"operation", "plan_id"},
        ("apply", "execution"): {"operation", "plan_id"},
        ("recover", "attempt"): {"operation", "attempt_id", "expected_sequence"},
    }
    if type(operation) is not str or (verb, operation) not in keys:
        raise RequestError("operation_unsupported")
    if set(arguments) != keys[verb, operation]:
        raise RequestError("invalid_request")
    values = {}
    for name in ("plan_id", "attempt_id"):
        if name in arguments:
            _selection([arguments[name]], stable=True)
            values[name] = arguments[name]
    for name in ("expected_revision", "expected_sequence"):
        if name in arguments:
            value = arguments[name]
            if type(value) is not int or not 0 <= value < 2**63 - 1:
                raise RequestError("invalid_request")
            values[name] = value
    if verb == "prepare":
        values["resource_ids"] = _selection(arguments["resource_ids"], stable=True)
        if arguments["interruption"] != "stop_and_require_recovery":
            raise RequestError("operation_unsupported")
        values["interruption"] = "stop_and_require_recovery"
    return HostRequest(verb, operation, **values)


def parse_request(raw):
    """Validate one UTF-8 JSON object; no lookup, file access or mutation."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_REQUEST_BYTES:
        raise RequestError("request_size_limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                           parse_float=_reject_number, parse_constant=_reject_number)
        if type(value) is not dict or set(value) != {"version", "verb", "arguments"}:
            raise RequestError("invalid_request")
        if type(value["version"]) is not int or value["version"] != PROTOCOL_VERSION:
            raise RequestError("protocol_unsupported")
        verb, arguments = value["verb"], value["arguments"]
        if type(verb) is not str or verb not in _VERBS or type(arguments) is not dict:
            raise RequestError("invalid_request")
        if verb == "observe":
            return _status(arguments)
        if verb in {"plan", "apply", "recover"} or (verb == "prepare" and arguments.get("operation") == "execution"):
            return _execution(verb, arguments)
        if verb not in {"record", "export", "prepare"}:
            raise RequestError("operation_unsupported")
        operation = arguments.get("operation")
        if type(operation) is not str:
            raise RequestError("invalid_request")
        if verb == "prepare":
            if operation != "protected-inputs":
                raise RequestError("operation_unsupported")
            if set(arguments) != {"operation", "expected_revision", "source", "source_is_nonsecret"}:
                raise RequestError("invalid_request")
            revision = arguments["expected_revision"]
            if (type(revision) is not int or not 0 <= revision < 2**63 - 1
                    or arguments["source_is_nonsecret"] is not True
                    or type(arguments["source"]) is not str):
                raise RequestError("invalid_request")
            source = arguments["source"].encode("utf-8")
            if len(source) > MAX_DECLARATION_BYTES:
                raise RequestError("request_size_limit")
            declaration = load_declaration(source)
            if not any(entry["classification"] == "protected" for bundle in declaration.model["inputs"]
                       for entry in bundle["files"]):
                raise RequestError("invalid_request")
            return HostRequest(verb, operation, revision, source)
        if verb == "export" and operation in {"attempts", "attempt"}:
            keys = ({"operation", "limit", "after_id"} if operation == "attempts" else
                    {"operation", "attempt_id", "after_event", "limit"})
            if set(arguments) != keys or type(arguments["limit"]) is not int or not 1 <= arguments["limit"] <= 100:
                raise RequestError("invalid_request")
            if operation == "attempts":
                cursor = arguments["after_id"]
                if cursor is not None:
                    _selection([cursor], stable=True)
                return HostRequest(verb, operation, page_limit=arguments["limit"], after_id=cursor)
            _selection([arguments["attempt_id"]], stable=True)
            after = arguments["after_event"]
            if type(after) is not int or not 0 <= after < 2**63 - 1:
                raise RequestError("invalid_request")
            return HostRequest(verb, operation, page_limit=arguments["limit"],
                               attempt_id=arguments["attempt_id"], after_event=after)
        if verb == "export":
            if set(arguments) != {"operation"} or operation not in {"current", "history"}:
                raise RequestError("invalid_request")
            return HostRequest(verb, operation)
        if operation == "initialize":
            if set(arguments) != {"operation"}:
                raise RequestError("invalid_request")
            return HostRequest(verb, operation)
        if operation not in {"intent", "adopt", "relinquish"}:
            raise RequestError("invalid_request")
        keys = {"operation", "expected_revision"}
        if operation in {"intent", "adopt"}:
            keys |= {"source", "source_is_nonsecret"}
            if "capture_inputs" in arguments:
                keys.add("capture_inputs")
            if "preparation_id" in arguments:
                keys.add("preparation_id")
        if operation in {"adopt", "relinquish"}:
            keys.add("resource_ids")
        if set(arguments) != keys:
            raise RequestError("invalid_request")
        capture_inputs = arguments.get("capture_inputs", False)
        if type(capture_inputs) is not bool:
            raise RequestError("invalid_request")
        revision = arguments["expected_revision"]
        if type(revision) is not int or not 0 <= revision < 2**63 - 1:
            raise RequestError("invalid_request")
        source = None
        preparation = arguments.get("preparation_id")
        if "preparation_id" in arguments:
            _selection([preparation], stable=True)
        if operation in {"intent", "adopt"}:
            if arguments["source_is_nonsecret"] is not True or type(arguments["source"]) is not str:
                raise RequestError("invalid_request")
            source = arguments["source"].encode("utf-8")
            if len(source) > MAX_DECLARATION_BYTES:
                raise RequestError("request_size_limit")
            declaration = load_declaration(source)
            protected = any(entry["classification"] == "protected" for bundle in declaration.model["inputs"]
                            for entry in bundle["files"])
            if protected and preparation is None:
                raise RequestError("protected_preparation_required")
            if not protected and preparation is not None:
                raise RequestError("invalid_request")
        resources = _selection(arguments["resource_ids"], stable=operation == "relinquish") if "resource_ids" in arguments else ()
        return HostRequest(verb, operation, revision, source, resources,
                           capture_inputs=capture_inputs, preparation_id=preparation)
    except RequestError:
        raise
    except DeclarationError:
        raise RequestError("invalid_declaration") from None
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise RequestError("invalid_request") from None
