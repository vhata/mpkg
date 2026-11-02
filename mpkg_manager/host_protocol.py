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
    if set(arguments) != {"operation", "expected_revision", "source", "source_is_nonsecret",
                          "selected_components", "probe_endpoints"}:
        raise RequestError("invalid_request")
    revision = arguments["expected_revision"]
    if revision is not None and (type(revision) is not int or not 0 <= revision < 2**63 - 1):
        raise RequestError("invalid_request")
    if type(arguments["probe_endpoints"]) is not bool:
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
                       selected_components=selection, probe_endpoints=arguments["probe_endpoints"])


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
        if verb not in {"record", "export"}:
            raise RequestError("operation_unsupported")
        operation = arguments.get("operation")
        if type(operation) is not str:
            raise RequestError("invalid_request")
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
        if operation in {"adopt", "relinquish"}:
            keys.add("resource_ids")
        if set(arguments) != keys:
            raise RequestError("invalid_request")
        revision = arguments["expected_revision"]
        if type(revision) is not int or not 0 <= revision < 2**63 - 1:
            raise RequestError("invalid_request")
        source = None
        if operation in {"intent", "adopt"}:
            if arguments["source_is_nonsecret"] is not True or type(arguments["source"]) is not str:
                raise RequestError("invalid_request")
            source = arguments["source"].encode("utf-8")
            if len(source) > MAX_DECLARATION_BYTES:
                raise RequestError("request_size_limit")
            declaration = load_declaration(source)
            if any(entry["classification"] == "protected" for bundle in declaration.model["inputs"]
                   for entry in bundle["files"]):
                raise RequestError("protected_recording_unsupported")
        resources = _selection(arguments["resource_ids"], stable=operation == "relinquish") if "resource_ids" in arguments else ()
        return HostRequest(verb, operation, revision, source, resources)
    except RequestError:
        raise
    except DeclarationError:
        raise RequestError("invalid_declaration") from None
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise RequestError("invalid_request") from None
