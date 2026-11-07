"""Unprivileged command entrypoints for the replacement manager."""
import argparse
import json
import os
import stat

from .declarations import DeclarationError, MAX_DECLARATION_BYTES, load_declaration
from .host_client import HostClientError, request_host
from .host_protocol import PROTOCOL_VERSION, RequestError


class _Arguments(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)

    def error(self, message):
        # argparse normally echoes arbitrary caller values in its diagnostics.
        raise DeclarationError("invalid_arguments")


def _source(path):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DeclarationError("declaration_not_regular_file")
        if before.st_size > MAX_DECLARATION_BYTES:
            raise DeclarationError("declaration_too_large")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_DECLARATION_BYTES + 1)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after):
            raise DeclarationError("declaration_changed_during_read")
        return raw
    except OSError:
        raise DeclarationError("declaration_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _revision(value):
    if not value.isascii() or not value.isdecimal() or len(value) > 19:
        raise DeclarationError("invalid_arguments")
    revision = int(value)
    if revision >= 2**63 - 1:
        raise DeclarationError("invalid_arguments")
    return revision


def _parser():
    parser = _Arguments(prog="mpkg-manager", description="Validate, record and inspect server-environment intent.")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Arguments)
    validate = commands.add_parser("validate", help="validate TOML without recording or applying it")
    validate.add_argument("source", metavar="PATH")
    validate.add_argument("--json", action="store_true", help="emit a bounded JSON summary")
    descriptions = {
        "init": "explicitly initialize the host store using installed policy",
        "record": "record intent without adopting or applying resources",
        "prepare-inputs": "prepare protected input captures for an exact declaration and revision",
        "adopt": "accept responsibility for selected declaration resources without observing them",
        "relinquish": "relinquish selected stable resource UUIDs without removing anything",
        "current": "show recorded revision and responsibility, without live observation",
        "history": "show recorded decisions without declaration contents",
        "status": "inspect recorded or working-tree intent without changing host state",
    }
    for name, help_text in descriptions.items():
        command = commands.add_parser(name, help=help_text, description=help_text)
        command.add_argument("--json", action="store_true", help="emit a bounded JSON result")
        if name in {"record", "adopt", "prepare-inputs"}:
            command.add_argument("source", metavar="PATH")
            command.add_argument("--source-is-nonsecret", action="store_true", required=True,
                                 help="explicitly classify the complete TOML source as nonsecret")
        if name in {"record", "adopt"}:
            command.add_argument("--prepared-inputs", metavar="UUID",
                                 help="consume an exact protected-input preparation once")
            command.add_argument("--capture-inputs", action="store_true",
                                 help="capture declared nonsecret files under installed host policy")
        if name in {"record", "adopt", "relinquish", "prepare-inputs"}:
            command.add_argument("--expected-revision", type=_revision, required=True, metavar="N",
                                 help="exact revision from current/history; stale decisions are refused")
        if name in {"adopt", "relinquish"}:
            command.add_argument("--resource", action="append", required=True,
                                 metavar="ID" if name == "adopt" else "UUID",
                                 help="select one resource; repeat to select more")
        if name == "status":
            command.add_argument("source", nargs="?", metavar="PATH",
                                 help="working-tree declaration; omit to inspect recorded intent")
            command.add_argument("--source-is-nonsecret", action="store_true",
                                 help="explicitly classify supplied TOML source as nonsecret")
            command.add_argument("--expected-revision", type=_revision, metavar="N",
                                 help="refuse inspection if recorded history changed")
            command.add_argument("--component", action="append", metavar="ID",
                                 help="select a component; retained obligations remain visible")
            command.add_argument("--probe-endpoints", action="store_true",
                                 help="explicitly probe recorded loopback routes; not a health claim")
            command.add_argument("--check-file-content", action="store_true",
                                 help="compare recorded file targets with captured input bytes")
            command.add_argument("--attribute-endpoints", action="store_true",
                                 help="inspect recorded runtime ownership and probe its loopback status")
            command.add_argument("--check-consumer-access", action="store_true",
                                 help="attempt recorded read/list checks as declared local users")
    return parser


def _request(options):
    command = options.command
    arguments = {"operation": {"init": "initialize", "record": "intent",
                               "prepare-inputs": "protected-inputs"}.get(command, command)}
    if command == "status":
        if (options.source is not None) != options.source_is_nonsecret:
            raise RequestError("invalid_request")
        source = None
        if options.source is not None:
            raw = _source(options.source)
            load_declaration(raw)
            source = raw.decode("utf-8")
        arguments.update(source=source, source_is_nonsecret=options.source_is_nonsecret,
                         expected_revision=options.expected_revision,
                         selected_components=options.component, probe_endpoints=options.probe_endpoints)
        for name in ("check_file_content", "attribute_endpoints", "check_consumer_access"):
            if getattr(options, name):
                arguments[name] = True
        return json.dumps({"version": PROTOCOL_VERSION, "verb": "observe", "arguments": arguments},
                          ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if command in {"record", "adopt", "relinquish", "prepare-inputs"}:
        arguments["expected_revision"] = options.expected_revision
    if command in {"record", "adopt", "prepare-inputs"}:
        raw = _source(options.source)
        declaration = load_declaration(raw)
        if command == "adopt":
            known = {resource["id"] for resource in declaration.model["resources"]}
            if not set(options.resource) <= known:
                raise RequestError("unknown_resource_selection")
        arguments.update(source=raw.decode("utf-8"), source_is_nonsecret=options.source_is_nonsecret)
        if command in {"record", "adopt"}:
            if options.capture_inputs:
                arguments["capture_inputs"] = True
            if options.prepared_inputs is not None:
                arguments["preparation_id"] = options.prepared_inputs
    if command in {"adopt", "relinquish"}:
        arguments["resource_ids"] = options.resource
    return json.dumps({"version": PROTOCOL_VERSION,
                       "verb": ("prepare" if command == "prepare-inputs" else
                                "export" if command in {"current", "history"} else "record"),
                       "arguments": arguments}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _human_result(command, result):
    if command == "init":
        print(f"Initialized host {result['host_id']} at revision 0.")
    elif command == "prepare-inputs":
        print(f"Prepared protected inputs at revision {result['revision']}: {result['preparation_id']}.")
        print("This replaces the previous pending preparation; recording consumes it once.")
    elif command in {"record", "adopt", "relinquish"}:
        labels = {"record": "Recorded intent", "adopt": "Recorded adoption",
                  "relinquish": "Recorded relinquishment"}
        print(f"{labels[command]} at revision {result['revision']}.")
    elif command == "current":
        print(f"Host {result['host_id']}: recorded revision {result['revision']}.")
        for resource in result["resources"]:
            print(f"{resource['logical_id']} ({resource['stable_id']}): {resource['kind']}; "
                  f"{resource['management']}; declaration {resource['declaration_state']}; "
                  f"pending disposition {'yes' if resource['pending_disposition'] else 'no'}.")
        print(f"{len(result['resources'])} recorded resources. Live state has not been observed.")
    elif command == "status":
        report, collection = result["report"], result["collection"]
        label = "recorded" if report["target"]["recorded"] else "working-tree (unrecorded)"
        print(f"Host {report['host_id']}: {label} status at revision {collection['revision']}.")
        for resource in report["resources"]:
            states = ", ".join(f"{row['property']}={row['comparison']}" for row in resource["properties"])
            print(f"{resource['resource_id']}: {states or 'no desired properties'}.")
            _human_checks(resource["checks"])
        for name in ("retained_resources", "unselected_resources"):
            for resource in report[name]:
                print(f"{resource['logical_id']} ({resource['stable_id']}): "
                      f"{name.removesuffix('_resources')}; {resource['management']}.")
                _human_checks(resource["checks"])
        print(f"Recorded inputs: {report['recorded_inputs']['reason']}. "
              f"Endpoint checks: {report['endpoint_checks']['reason']}.")
        for scope in report["recorded_inputs"]["scopes"]:
            for entry in scope["entries"]:
                owner = scope["stable_id"] if scope["role"] == "accepted" else "current"
                print(f"Input {entry['input_id']}[{entry['file_index']}] ({owner}): {entry['state']}.")
        if "file_content" in report:
            print(f"Target file content: {report['file_content']['reason']}.")
            for scope in report["file_content"]["scopes"]:
                owner = f"accepted {scope['stable_id']}" if scope["role"] == "accepted" else "current"
                for entry in scope["entries"]:
                    obligation = (f"consumer {entry['consumer_id']}" if entry["requirement"] == "consumer"
                                  else "desired")
                    print(f"Content {entry['resource_id']} ({owner}, {obligation}, input {entry['input_id']}): "
                          f"{entry['state']} ({entry['reason']}).")
        if "runtime_checks" in report:
            summary = report["runtime_checks"]
            print(f"Runtime and consumer checks: {summary['reason']}.")
            for row in summary["entries"]:
                owner = f"accepted {row['stable_id']}" if row["role"] == "accepted" else "current"
                outcome = (f"attribution {row['attribution']}, route {row['route_result']}"
                           if row["check_kind"] == "endpoint" else f"local-user access {row['access_result']}")
                print(f"Check {row['check_id']} ({owner}): {outcome} ({row['reason']}).")
            print("Runtime ownership and local-user access do not establish application functionality.")
        print("Blockers: " + ", ".join(report["blockers"]) + ".")
        print("Status is time-bounded evidence. Application and attempt history remain unavailable.")
    else:
        print(f"Host {result['host_id']}: {len(result['decisions'])} recorded decisions.")
        for decision in result["decisions"]:
            print(f"Revision {decision['revision']}: {decision['kind']} at {decision['created_at']}.")
    if command in {"init", "record", "adopt", "relinquish"}:
        print("Recording does not observe, apply or verify host state.")


def _human_checks(checks):
    for check in checks:
        route = f"; route {check['route_result']}" if "route_result" in check else ""
        print(f"  {check['role']} check {check['id']}: {check['result']}{route}.")


def _host_failure(options, code, category, *, path=None):
    error = {"code": code}
    if path is not None:
        error["path"] = list(path)
    if options is None or options.json:
        value = {"ok": False, "category": category, "error": error}
        if category == "uncertain":
            value["next_step"] = "inspect_current_and_history_before_deciding_to_retry"
        print(json.dumps(value, sort_keys=True))
    else:
        labels = {"authentication": "Authentication failed", "transport": "Helper transport failed",
                  "rejected": "Request rejected", "uncertain": "Recording outcome uncertain",
                  "validation": "Invalid request"}
        print(f"{labels[category]} ({code}).")
        if category == "uncertain":
            print("The helper may still be running. Inspect current and history before deciding whether to retry.")


def main(argv=None, *, _sender=None):
    parser = _parser()
    options = None
    try:
        options = parser.parse_args(argv)
        if options.command != "validate":
            result = request_host(_request(options), _sender=_sender)
            if options.json:
                print(json.dumps({"ok": True, "result": result}, sort_keys=True))
            else:
                _human_result(options.command, result)
            return 0
        declaration = load_declaration(_source(options.source))
        model = declaration.model
        summary = {"valid": True, "schema_version": declaration.schema_version,
                   "normalization_version": declaration.normalization_version,
                   "sha256": declaration.sha256,
                   "counts": {key: len(model[key]) for key in
                              ("components", "resources", "inputs", "checks", "runtime_rules")},
                   "application": "not_implemented"}
        if options.json:
            print(json.dumps(summary, sort_keys=True))
        else:
            print(f"Valid declaration (schema {declaration.schema_version}): "
                  f"{len(model['components'])} components, {len(model['resources'])} resources.")
            print("Validation does not observe, record or apply host state.")
        return 0
    except DeclarationError as error:
        # JSON is also used for argument errors: it never contains parser text,
        # filenames, unknown keys, invalid values, or protected input bytes.
        if options is None or options.command == "validate":
            print(json.dumps({"valid": False, "error": {"code": error.code,
                                                       "path": list(error.path)}}, sort_keys=True))
        else:
            _host_failure(options, error.code, "validation", path=error.path)
        return 3 if error.code == "declaration_unavailable" else 2
    except RequestError as error:
        _host_failure(options, error.code, "validation")
        return 2
    except HostClientError as error:
        _host_failure(options, error.code, error.category)
        return error.exit_status
