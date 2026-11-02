"""Bounded positive local account facts; no creation or absence authority."""
import posixpath
import re
import time

from .declarations import DeclarationError, validate_model
from .observations import Observation, ObservationBatch, utc_now, validate_context
from .query_process import QueryResult, run_bounded


MAX_RESOURCES = 64
MAX_OUTPUT = 16 * 1024
COLLECTION_SECONDS = 30
QUERY_SECONDS = 2
SOURCE = "local_account_properties"
ENVIRONMENT = {"PATH": "/usr/bin", "LC_ALL": "C", "LANG": "C"}
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@+-]{0,254}\Z")
_NUMBER = re.compile(r"(?:0|[1-9][0-9]{0,9})\Z")
_PROPERTIES = {"user": ("present", "home", "shell", "primary_group", "uid", "gid", "groups"),
               "group": ("present", "gid", "members")}


def _numeric(value):
    return type(value) is str and bool(_NUMBER.fullmatch(value)) and int(value) < 2**32 - 1


def _argv(database, key, local):
    return ("/usr/bin/getent", *(("--service=files",) if local else ()), "--", database, key)


def run_readonly(argv, *, timeout=QUERY_SECONDS):
    """Only one passwd/group key, with files or default NSS, is executable."""
    if type(argv) is not tuple or any(type(value) is not str for value in argv):
        return QueryResult("invalid_query")
    local = len(argv) == 5 and argv[:3] == ("/usr/bin/getent", "--service=files", "--")
    default = len(argv) == 4 and argv[:2] == ("/usr/bin/getent", "--")
    if (not (local or default) or argv[-2] not in ("passwd", "group")
            or not _NAME.fullmatch(argv[-1])
            or (argv[-1].isdigit() and not _numeric(argv[-1]))):
        return QueryResult("invalid_query")
    if type(timeout) not in (int, float) or not 0 < timeout <= QUERY_SECONDS:
        return QueryResult("invalid_query")
    return run_bounded(argv, environment=ENVIRONMENT, timeout=timeout, max_output=MAX_OUTPUT,
                       accepted_returncodes=(0, 2), require_empty_stderr=True)


def _path(value):
    if (not value.startswith("/") or value.startswith("//") or len(value.encode("utf-8")) > 4096
            or posixpath.normpath(value) != value):
        return None
    return value


def _parse(raw, database):
    try:
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise ValueError
        line = raw[:-1].decode("utf-8")
        if any(ord(char) < 32 or ord(char) == 127 for char in line):
            raise ValueError
        fields = line.split(":")
        if len(fields) != (7 if database == "passwd" else 4):
            raise ValueError
        if not _NAME.fullmatch(fields[0]) or fields[0].isdigit() or not _numeric(fields[2]):
            raise ValueError
        # Password/hash, GECOS and member-list fields are deliberately dropped.
        if database == "passwd":
            if not _numeric(fields[3]):
                raise ValueError
            return (fields[0], int(fields[2]), int(fields[3]), _path(fields[5]), _path(fields[6]))
        return (fields[0], int(fields[2]))
    except (UnicodeError, ValueError, TypeError, IndexError):
        return None


class _Queries:
    def __init__(self, runner):
        self.runner = runner
        self.deadline = time.monotonic() + COLLECTION_SECONDS

    def get(self, database, key, local):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return None, "account_collection_timeout"
        try:
            result = self.runner(_argv(database, key, local), timeout=min(QUERY_SECONDS, remaining))
        except Exception:
            return None, "account_query_unavailable"
        if time.monotonic() >= self.deadline:
            return None, "account_collection_timeout"
        if type(result) is not QueryResult:
            return None, "invalid_account_query_result"
        if result.code != "ok":
            return None, result.code
        if len(result.output) > MAX_OUTPUT:
            return None, "output_limit"
        if result.returncode == 2 and not result.output:
            return None, "account_not_found_or_unavailable"
        if result.returncode != 0:
            return None, "malformed_account_record"
        parsed = _parse(result.output, database)
        return (parsed, None) if parsed is not None else (None, "malformed_account_record")

    def consistent(self, database, key, *, numeric=False):
        first, error = self.get(database, key, True)
        if error:
            return None, error
        matches = first[1] == int(key) if numeric else first[0] == key
        if not matches:
            return None, "account_identity_mismatch"
        reverse = first[0] if numeric else str(first[1])
        for lookup, local in ((key, False), (reverse, True), (reverse, False)):
            record, error = self.get(database, lookup, local)
            if error:
                return None, error
            if record != first:
                return None, "account_identity_conflict"
        return first, None


def _sample(resource, queries):
    kind, name = resource["kind"], resource["identity"]["name"]
    database = "passwd" if kind == "user" else "group"
    record, error = queries.consistent(database, name)
    if error:
        return None, None, error
    if kind == "group":
        return record, None, None
    group, group_error = queries.consistent("group", str(record[2]), numeric=True)
    if group_error == "account_collection_timeout":
        return None, None, group_error
    return record, (None if group is None else group[0], group_error), None


def observe_accounts(resources, *, host_id, observed_at=None, runner=None):
    """Observe positive local scalar properties through repeated exact lookups.

    Imported JSON and injected runners are not authority. Default NSS matching
    cannot prove the absence of a hidden identical directory-service record.
    """
    when = utc_now() if observed_at is None else observed_at
    validate_context(host_id, when)
    try:
        if type(resources) not in (list, tuple) or len(resources) > MAX_RESOURCES:
            raise ValueError
        if runner is not None and not callable(runner):
            raise ValueError
        checked, seen = [], set()
        for resource in resources:
            if type(resource) is not dict or resource.get("kind") not in _PROPERTIES:
                raise ValueError
            minimal = {key: resource[key] for key in ("id", "kind", "identity")}
            item = validate_model({"schema": 1, "components": [], "resources": [minimal]})["resources"][0]
            if item["id"] in seen:
                raise ValueError
            seen.add(item["id"])
            checked.append(item)
    except (ValueError, TypeError, KeyError, AttributeError, DeclarationError, RecursionError):
        raise ValueError("invalid_account_observation_request") from None
    queries = _Queries(run_readonly if runner is None else runner)
    facts = []
    for resource in checked:
        values, reasons = {}, {}
        if resource["identity"]["name"].isdigit():
            error = "numeric_account_name_unsupported"
        else:
            first, first_group, error = _sample(resource, queries)
            if error is None:
                second, second_group, error = _sample(resource, queries)
                if error is None and first != second:
                    error = "account_properties_changed"
                if error is None:
                    values = {"present": True}
                    if resource["kind"] == "user":
                        values.update(uid=first[1], gid=first[2], home=first[3], shell=first[4])
                        if first_group != second_group:
                            reasons["primary_group"] = "primary_group_changed"
                        else:
                            values["primary_group"] = first_group[0]
                            reasons["primary_group"] = first_group[1]
                    else:
                        values["gid"] = first[1]
        for prop in _PROPERTIES[resource["kind"]]:
            reason = error
            value = values.get(prop)
            if reason is None:
                if prop in ("groups", "members"):
                    reason = "additive_memberships_not_observed"
                elif value is None:
                    reason = reasons.get(prop) or "account_property_unavailable"
            facts.append(Observation(host_id, resource["id"], resource["kind"], resource["identity"],
                prop, "unknown" if reason else "known", None if reason else value,
                when, SOURCE, (reason,) if reason else ()))
    return ObservationBatch(host_id, when, tuple(facts), tuple(item["id"] for item in checked),
        ("time_bounded_observation_not_atomic_nss_snapshot", "missing_record_not_verified_absence",
         "duplicate_and_hidden_identity_records_not_excluded", "additive_memberships_not_observed",
         "numeric_identity_changes_not_authorized", "no_management_authority_inferred"))
