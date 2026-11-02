"""Trusted read-only status assembly; private facts never become public JSON."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import time

from . import observe_accounts, observe_compose, observe_files, observe_native, observe_packages
from .declarations import Declaration, DeclarationError, canonical_json, load_declaration, physical_key
from .endpoint_checks import EndpointCollectionError, collect_endpoint_checks
from .host_policy import LoadedHostPolicy, PolicyError
from .observations import Observation, ObservationBatch, utc_now
from .planning import PlanningError, build_report
from .protected_bindings import BindingError, ProtectedRecorder
from .query_process import QueryResult
from .recorded_inputs import RecordedInputError
from .store import HostStore, StoreError


MAX_TARGETS = 1024
MAX_SCOPE_BYTES = 8 * 1024 * 1024
LIMITATIONS = (
    "time_bounded_observation_not_atomic_host_snapshot",
    "filesystem_nss_policy_and_store_latency_have_no_deadline",
    "protected_input_reads_have_separate_byte_bounds_and_no_deadline",
    "query_output_budget_reserves_combined_stdout_stderr_capacity",
    "endpoint_transport_has_separate_per_probe_byte_bounds",
    "complete_input_closure_and_functional_health_unverified",
    "no_application_or_management_authority_inferred",
)
_PROPERTIES = {
    "package": observe_native.PACKAGE_PROPERTIES,
    "service": observe_native.SERVICE_PROPERTIES,
    "compose": ("present", "container_count", "running", "input_closure", "images", "health"),
    "user": ("present", "home", "shell", "primary_group", "groups", "uid", "gid"),
    "group": ("present", "members", "gid"),
    "file": ("present", "mode", "owner", "group", "content", "content_input"),
    "directory": ("present", "mode", "owner", "group"),
    "symlink": ("present", "mode", "owner", "group", "target"),
}


class StatusCollectionError(ValueError):
    """Fixed diagnostics never include paths, source, predicates or tool output."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class StatusResult:
    """Immutable public report bound to the exact inspected declaration/context."""
    canonical_bytes: bytes = field(repr=False)

    @property
    def sha256(self):
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    def as_dict(self):
        return json.loads(self.canonical_bytes)


def _context(store, loaded_policy, *, complete_inputs=False):
    try:
        policy = loaded_policy.policy
        current = store.current_with_inputs() if complete_inputs else store.current()
        aliases = store.engine_aliases
        if policy.host_id != current["host_id"] or policy.engine_aliases != aliases:
            raise StatusCollectionError("status_policy_store_mismatch")
        return policy, current, aliases
    except PolicyError:
        raise StatusCollectionError("status_policy_unavailable") from None
    except StoreError:
        raise StatusCollectionError("status_store_unavailable") from None


def _key(resource, host_id, aliases):
    try:
        return physical_key(resource, host_id, aliases)
    except DeclarationError:
        return None


def _targets(model, current, aliases):
    """Retained targets first; logical labels never override physical context."""
    resources = model["resources"]
    if len(resources) + len(current["resources"]) > MAX_TARGETS:
        raise StatusCollectionError("status_scope_limit")
    if len(canonical_json([resources, current["resources"]])) > MAX_SCOPE_BYTES:
        raise StatusCollectionError("status_scope_limit")
    host_id = current["host_id"]
    declared = {}
    for resource in resources:
        key = _key(resource, host_id, aliases)
        if key is not None:
            if key in declared:
                raise StatusCollectionError("status_physical_identity_conflict")
            declared[key] = resource
    targets, by_id = [], {}

    def append(resource, *, record=None, reason=None):
        target = by_id.get(resource["id"])
        if target is None:
            target = {"resource": resource, "reason": reason, "stable_ids": [],
                      "current": False}
            targets.append(target)
            by_id[resource["id"]] = target
        elif (target["resource"]["kind"] != resource["kind"]
              or _key(target["resource"], host_id, aliases) != _key(resource, host_id, aliases)
              or target["resource"]["identity"] != resource["identity"]):
            target["reason"] = "status_logical_identity_conflict"
        elif reason:
            target["reason"] = reason
        if record is not None:
            target["stable_ids"].append(record["stable_id"])
        else:
            target["current"] = True
            # Current label/identity is used for comparisons. A collision stays
            # unknown for both it and historical predicates using this label.
            target["resource"] = resource

    for record in current["resources"]:
        original = record["definition"]
        resource = declared.get(tuple(record["physical_key"]), original)
        reason = None
        if resource["kind"] != original["kind"]:
            reason = "status_resource_kind_conflict"
        elif (resource["kind"] == "compose"
              and sorted(resource["desired"].get("services", []))
              != sorted(original["desired"].get("services", []))):
            reason = "status_compose_service_scope_conflict"
        append(resource, record=record, reason=reason)
    for resource in resources:
        append(resource)
    for target in targets:
        resource = target["resource"]
        if _key(resource, host_id, aliases) is None:
            target["reason"] = "status_physical_identity_unbound"
        elif resource["kind"] not in _PROPERTIES:
            target["reason"] = "status_resource_kind_unsupported"
    return targets


def _unknown(resource, host_id, when, reason):
    props = {"present", *_PROPERTIES.get(resource["kind"], ()), *resource["desired"]}
    return tuple(Observation(host_id, resource["id"], resource["kind"], resource["identity"],
                             prop, "unknown", None, when, "unsupported_adapter", (reason,))
                 for prop in sorted(props))


class _Budget:
    def __init__(self, seconds, count, output_bytes, runners):
        self.deadline = time.monotonic() + seconds
        self.max_queries, self.max_bytes = count, output_bytes
        self.query_count, self.reserved_bytes = 0, 0
        self.runners = runners
        self.reasons = set()

    def remaining(self):
        return self.deadline - time.monotonic()

    def reason(self):
        if self.remaining() <= 0:
            return "status_collection_budget_exhausted"
        return None

    def runner(self, adapter):
        def query(argv, *, timeout=None):
            if adapter == "native":
                cap = 1024 * 1024 if argv in (observe_native.PACKAGE_VERSIONS,
                                              observe_native.PACKAGE_EXPLICIT) else 16 * 1024
                seconds = 10
            elif adapter == "packages":
                cap, seconds = observe_packages.MAX_OUTPUT, 10
            elif adapter == "accounts":
                cap, seconds = observe_accounts.MAX_OUTPUT, min(2, timeout or 2)
            else:
                cap, seconds = observe_compose.MAX_OUTPUT, 10
            reason = self.reason()
            if reason is None and self.query_count >= self.max_queries:
                reason = "status_query_limit"
            if reason is None and self.reserved_bytes + cap > self.max_bytes:
                reason = "status_query_byte_limit"
            # The package adapter has a fixed ten-second process deadline.
            if reason is None and adapter == "packages" and self.remaining() < seconds:
                reason = "status_collection_budget_exhausted"
            if reason:
                self.reasons.add(reason)
                return QueryResult("output_limit" if reason.endswith("byte_limit") else "timeout")
            seconds = min(seconds, self.remaining())
            query_deadline = time.monotonic() + seconds
            self.query_count += 1
            # Reserve the full capture allowance, including failed output and
            # stderr which the QueryResult deliberately does not expose.
            self.reserved_bytes += cap
            try:
                runner = self.runners.get(adapter)
                if runner is not None:
                    result = runner(argv, timeout=seconds) if adapter == "accounts" else runner(argv)
                elif adapter == "native":
                    result = observe_native.run_readonly(argv, timeout=seconds, max_output=cap)
                elif adapter == "packages":
                    result = observe_packages.run_readonly(argv)
                elif adapter == "accounts":
                    result = observe_accounts.run_readonly(argv, timeout=seconds)
                else:
                    result = observe_compose.run_readonly(argv, timeout=seconds, max_output=cap)
            except Exception:
                self.reasons.add("status_query_failed")
                return QueryResult("io_error")
            if type(result) is not QueryResult:
                self.reasons.add("status_query_result_invalid")
                return QueryResult("io_error")
            if len(result.output) > cap:
                self.reasons.add("status_query_output_limit")
                return QueryResult("output_limit")
            if self.reason():
                self.reasons.add("status_collection_budget_exhausted")
                return QueryResult("timeout")
            if time.monotonic() >= query_deadline:
                self.reasons.add("status_query_timeout")
                return QueryResult("timeout")
            return result
        return query


def _package_facts(resources, host_id, when, budget):
    direct = observe_native.observe_resources(resources, host_id=host_id, observed_at=when,
                                              runner=budget.runner("native"))
    requests = observe_packages.observe_package_requests(resources, host_id=host_id, observed_at=when,
                                                         runner=budget.runner("packages"))
    satisfaction = {fact.resource_id: fact for fact in requests.facts}
    facts = []
    for fact in direct.facts:
        if fact.property == "present" and not (fact.state == "known" and fact.value is True):
            positive = satisfaction[fact.resource_id]
            if positive.state == "known" and positive.value is True:
                fact = positive
        facts.append(fact)
    return tuple(facts)


def collect_status(declaration, store, loaded_policy, *, selected_components=None,
                   probe_endpoints=False, budget_seconds=60, max_queries=1024,
                   max_query_bytes=64 * 1024 * 1024, max_resources=256,
                   max_endpoint_probes=64, max_age_seconds=60,
                   native_runner=None, package_runner=None, account_runner=None,
                   compose_runner=None, endpoint_runner=None, identities=None,
                   complete_inputs=False, expected_revision=None):
    """Collect and compare through live trusted read-only handles.

    Runners and name resolvers are trusted embedding/test seams, never request
    fields. They must bound their own execution; late returns are discarded.
    Filesystem, NSS, history and protected-input reads are not preemptible.
    Endpoint probes require an explicit flag and an exact recorded target.
    """
    runners = {"native": native_runner, "packages": package_runner,
               "accounts": account_runner, "compose": compose_runner}
    if (type(declaration) is not Declaration or type(store) is not HostStore
            or type(loaded_policy) is not LoadedHostPolicy
            or getattr(store, "readonly", None) is not True
            or type(probe_endpoints) is not bool
            or type(complete_inputs) is not bool
            or (expected_revision is not None and (type(expected_revision) is not int
                or not 0 <= expected_revision < 2**63 - 1))
            or type(budget_seconds) is not int or not 1 <= budget_seconds <= 300
            or type(max_queries) is not int or not 1 <= max_queries <= 4096
            or type(max_query_bytes) is not int or not 1 <= max_query_bytes <= 128 * 1024 * 1024
            or type(max_resources) is not int or not 1 <= max_resources <= 1024
            or type(max_endpoint_probes) is not int or not 1 <= max_endpoint_probes <= 256
            or type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 3600
            or any(runner is not None and not callable(runner)
                   for runner in (*runners.values(), endpoint_runner))):
        raise StatusCollectionError("invalid_status_collection_request")
    try:
        if load_declaration(declaration.source_bytes) != declaration:
            raise ValueError
        model = declaration.model
        if selected_components is not None:
            if (type(selected_components) not in (list, tuple)
                    or any(type(name) is not str for name in selected_components)
                    or len(set(selected_components)) != len(selected_components)
                    or not set(selected_components) <= {item["id"] for item in model["components"]}):
                raise ValueError
            selected_components = list(selected_components)
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise StatusCollectionError("invalid_status_declaration_or_selection") from None
    when = utc_now()
    budget = _Budget(budget_seconds, max_queries, max_query_bytes, runners)
    policy, current, aliases = _context(store, loaded_policy, complete_inputs=complete_inputs)
    if expected_revision is not None and current["revision"] != expected_revision:
        raise StatusCollectionError("status_revision_conflict")
    recorded = None
    if current["snapshot_id"] is not None:
        try:
            recorded = store.snapshot(current["snapshot_id"])
        except StoreError:
            raise StatusCollectionError("status_store_unavailable") from None
    targets = _targets(model, current, aliases)
    host_id = policy.host_id
    # Validate report inputs before any host query or probe.
    try:
        build_report(declaration, current, None, host_id=host_id, engine_aliases=aliases,
                     selected_components=selected_components, max_age_seconds=max_age_seconds)
    except PlanningError:
        raise StatusCollectionError("invalid_status_report_context") from None
    facts, rows, packages = [], [], []
    for index, target in enumerate(targets):
        resource = target["resource"]
        reason = target["reason"] or ("status_resource_limit" if index >= max_resources else None)
        reason = reason or budget.reason()
        row = {"resource_id": resource["id"], "kind": resource["kind"],
               "current": target["current"], "stable_ids": target["stable_ids"],
               "state": "unavailable" if reason else "collected", "reason": reason}
        rows.append(row)
        if reason:
            facts.extend(_unknown(resource, host_id, when, reason))
            continue
        if resource["kind"] == "package":
            packages.append((resource, row))
            continue
        try:
            if resource["kind"] == "service":
                batch = observe_native.observe_resources([resource], host_id=host_id, observed_at=when,
                                                          runner=budget.runner("native"))
            elif resource["kind"] in ("user", "group"):
                batch = observe_accounts.observe_accounts([resource], host_id=host_id, observed_at=when,
                                                          runner=budget.runner("accounts"))
            elif resource["kind"] in ("file", "directory", "symlink"):
                batch = observe_files.observe_files([resource], host_id=host_id, observed_at=when,
                                                    identities=identities)
            else:
                batch = observe_compose.observe_compose(resource, host_id=host_id, observed_at=when,
                    accepted_engine_id=aliases[resource["identity"]["engine"]],
                    runner=budget.runner("compose")).observations
            reason = budget.reason()
            result = batch.facts
        except Exception:
            result, reason = (), "status_adapter_unavailable"
        if reason:
            result = _unknown(resource, host_id, when, reason)
            row.update(state="unavailable", reason=reason)
        facts.extend(result)
    for offset in range(0, len(packages), observe_packages.MAX_RESOURCES):
        group = packages[offset:offset + observe_packages.MAX_RESOURCES]
        reason = budget.reason()
        if reason is None:
            try:
                result = _package_facts([item[0] for item in group], host_id, when, budget)
            except Exception:
                reason = "status_adapter_unavailable"
        if reason:
            result = tuple(fact for resource, row in group
                           for fact in _unknown(resource, host_id, when, reason))
            for resource, row in group:
                row.update(state="unavailable", reason=reason)
        facts.extend(result)
    batch = ObservationBatch(host_id, when, tuple(facts), tuple(row["resource_id"] for row in rows), LIMITATIONS)
    inputs, input_reason = None, "status_no_recorded_snapshot"
    if recorded is not None:
        input_reason = ("status_target_not_recorded" if complete_inputs and recorded != declaration
                        else budget.reason())
        if input_reason is None:
            try:
                recorder = ProtectedRecorder(store, loaded_policy)
                observe = recorder.observe_recorded_inputs if complete_inputs else recorder.observe_inputs
                inputs = observe(
                    revision=current["revision"], snapshot_id=current["snapshot_id"], observed_at=when)
                input_reason = budget.reason()
                if input_reason:
                    inputs = None
            except (BindingError, StoreError, RecordedInputError):
                input_reason = "status_input_observation_unavailable"
    endpoints, endpoint_reason = None, "status_endpoint_collection_not_requested"
    if probe_endpoints:
        endpoint_reason = "status_target_not_recorded"
        if recorded == declaration:
            remaining = int(budget.remaining())
            endpoint_reason = "status_collection_budget_exhausted"
            if remaining > 0:
                try:
                    endpoints = collect_endpoint_checks(store, revision=current["revision"],
                        snapshot_id=current["snapshot_id"], budget_seconds=remaining,
                        max_probes=max_endpoint_probes, runner=endpoint_runner)
                    endpoint_reason = None
                except EndpointCollectionError:
                    endpoint_reason = "status_endpoint_collection_unavailable"
    # Even empty scopes and failed adapters must cross the final live checks.
    final_policy, final_current, final_aliases = _context(store, loaded_policy, complete_inputs=complete_inputs)
    if policy != final_policy or aliases != final_aliases or current != final_current:
        raise StatusCollectionError("status_context_changed")
    if recorded is not None:
        try:
            if store.snapshot(current["snapshot_id"]) != recorded:
                raise StatusCollectionError("status_context_changed")
        except StoreError:
            raise StatusCollectionError("status_store_unavailable") from None
    try:
        input_arguments = {"recorded_input_observations" if complete_inputs else "input_observations": inputs}
        report = build_report(declaration, current, batch.as_dict(), host_id=host_id, engine_aliases=aliases,
            selected_components=selected_components, now=datetime.now(timezone.utc),
            max_age_seconds=max_age_seconds, endpoint_observations=endpoints, **input_arguments)
    except PlanningError:
        raise StatusCollectionError("invalid_status_report_context") from None
    collection = {
        "host_id": host_id, "revision": current["revision"], "snapshot_id": current["snapshot_id"],
        "observed_at": when, "targets": rows, "coverage_complete": True,
        "query_count": budget.query_count, "query_output_bytes_reserved": budget.reserved_bytes,
        "query_limits": sorted(budget.reasons), "protected_input_reason": input_reason,
        "endpoint_reason": endpoint_reason, "limitations": list(LIMITATIONS), "executable": False}
    if complete_inputs:
        collection["recorded_input_reason"] = collection.pop("protected_input_reason")
    return StatusResult(canonical_json({"report": report.as_dict(), "collection": collection}))
