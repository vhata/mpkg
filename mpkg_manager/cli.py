"""Unprivileged command entrypoints for the replacement manager."""
import argparse
import json
import os
import stat

from .declarations import DeclarationError, MAX_DECLARATION_BYTES, load_declaration


class _Arguments(argparse.ArgumentParser):
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


def main(argv=None):
    parser = _Arguments(prog="mpkg-manager", description="Inspect and validate server-environment intent.")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Arguments)
    validate = commands.add_parser("validate", help="validate TOML without recording or applying it")
    validate.add_argument("source", metavar="PATH")
    validate.add_argument("--json", action="store_true", help="emit a bounded JSON summary")
    options = None
    try:
        options = parser.parse_args(argv)
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
        print(json.dumps({"valid": False, "error": {"code": error.code,
                                                   "path": list(error.path)}}, sort_keys=True))
        return 3 if error.code == "declaration_unavailable" else 2
