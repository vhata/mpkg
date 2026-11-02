"""Declared local-user read/list evidence, never application identity."""
from dataclasses import dataclass, field
import json
import time

from ._access_process import AccessResult, RESULT_CODES, run_access
from ._access_worker import MAX_GROUPS
from .declarations import DeclarationError, canonical_json, physical_key, validate_model
from .observe_accounts import _NAME, _numeric, _parse, _argv, ENVIRONMENT
from .observations import utc_now, validate_context
from .query_process import QueryResult, run_bounded


MAX_QUERY_BYTES = 16 * 1024
MAX_BINDING_BYTES = 16 * 1024
QUERY_SECONDS = 2
LIMITATIONS = ('time_bounded_access_not_atomic_filesystem_snapshot',
              'declared_local_credentials_not_running_application_credentials',
              'caller_mount_namespace_not_application_namespace',
              'access_check_not_content_agreement_or_application_functionality',
              'no_write_or_management_authority_inferred')
_UNAVAILABLE = RESULT_CODES - {'ok', 'denied'} | {
    'unsupported_resource', 'unsupported_operation', 'unsupported_account',
    'account_unavailable', 'account_conflict', 'account_changed', 'account_output_invalid',
    'account_query_failed', 'account_query_timeout', 'account_query_limit', 'collection_timeout',
    'worker_result_invalid', 'worker_runner_failed'}


class ConsumerAccessError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _binding(check, resource, host_id, aliases):
    try:
        if (type(check) is not dict or type(resource) is not dict
                or type(aliases) is not dict
                or any(type(key) is not str or type(value) is not str or not value
                       or len(value) > 255 or '\0' in value for key, value in aliases.items())
                or type(resource.get('consumers')) is not list
                or check['consumer'] not in resource['consumers']):
            raise ValueError
        minimal = {key: resource[key] for key in ('id', 'kind', 'identity')}
        consumer = check['consumer']
        minimal.update(consumers=[consumer], checks=[check['id']])
        components = ([] if consumer.startswith('external:') else
                      [{'id': consumer, 'purpose': 'Access check', 'resources': [resource['id']]}])
        model = validate_model({'schema': 1, 'components': components,
                                'resources': [minimal], 'checks': [check]})
        if model['checks'][0]['kind'] != 'access':
            raise ValueError
        minimal = {key: model['resources'][0][key]
                   for key in ('id', 'kind', 'identity', 'consumers', 'checks')}
        target = list(physical_key(model['resources'][0], host_id, aliases))
        raw = canonical_json({'check': model['checks'][0], 'resource': minimal, 'target': target})
        if len(raw) > MAX_BINDING_BYTES:
            raise ValueError
        return raw
    except (ValueError, TypeError, KeyError, AttributeError, DeclarationError, RecursionError):
        raise ConsumerAccessError('invalid_consumer_access_context') from None


def _validate_binding(raw):
    try:
        if type(raw) is not bytes or len(raw) > MAX_BINDING_BYTES:
            raise ValueError
        value = json.loads(raw)
        if (type(value) is not dict or set(value) != {'check', 'resource', 'target'}
                or canonical_json(value) != raw):
            raise ValueError
        target, resource = value['target'], value['resource']
        if type(target) is not list or not target or type(target[0]) is not str:
            raise ValueError
        aliases = {resource['identity']['engine']: target[2]} if resource['kind'] == 'volume' else {}
        if _binding(value['check'], resource, target[0], aliases) != raw:
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
        raise ConsumerAccessError('invalid_consumer_access_observation') from None


@dataclass(frozen=True)
class ConsumerAccessObservation:
    """Private immutable predicate binding; public JSON is not import authority."""
    _binding: bytes = field(repr=False)
    observed_at: str
    access_result: str
    reason: str

    def __post_init__(self):
        context = _validate_binding(self._binding)
        try:
            validate_context(context['target'][0], self.observed_at)
            allowed = {'match': {'access_succeeded'}, 'mismatch': {'access_denied'},
                       'unavailable': _UNAVAILABLE}
            if (type(self.access_result) is not str or self.access_result not in allowed
                    or type(self.reason) is not str or self.reason not in allowed[self.access_result]):
                raise ValueError
        except ValueError:
            raise ConsumerAccessError('invalid_consumer_access_observation') from None

    def matches_context(self, check, resource, *, host_id, engine_aliases=None):
        try:
            return self._binding == _binding(check, resource, host_id,
                                             {} if engine_aliases is None else engine_aliases)
        except (ConsumerAccessError, AttributeError):
            return False

    def as_dict(self):
        context = json.loads(self._binding)
        check, resource = context['check'], context['resource']
        return {'host_id': context['target'][0], 'check_id': check['id'],
                'resource_id': resource['id'], 'resource_kind': resource['kind'],
                'consumer_id': check['consumer'], 'operation': check['operation'],
                'observed_at': self.observed_at, 'access_result': self.access_result,
                'reason': self.reason, 'functional_result': 'unverified',
                'evidence_source': 'declared_local_user_access', 'limitations': list(LIMITATIONS)}


def run_readonly(argv, *, timeout=QUERY_SECONDS):
    """Only bounded local/default passwd and initgroups queries are allowed."""
    if type(argv) is not tuple or any(type(item) is not str for item in argv):
        return QueryResult('invalid_query')
    local = len(argv) == 5 and argv[:3] == ('/usr/bin/getent', '--service=files', '--')
    default = len(argv) == 4 and argv[:2] == ('/usr/bin/getent', '--')
    if (not (local or default) or argv[-2] not in ('passwd', 'initgroups')
            or not _NAME.fullmatch(argv[-1])
            or (argv[-1].isdigit() and (argv[-2] != 'passwd' or not _numeric(argv[-1])))
            or type(timeout) not in (int, float) or not 0 < timeout <= QUERY_SECONDS):
        return QueryResult('invalid_query')
    return run_bounded(argv, environment=ENVIRONMENT, timeout=timeout, max_output=MAX_QUERY_BYTES,
                       accepted_returncodes=(0, 2), require_empty_stderr=True)


class _Unavailable(Exception):
    def __init__(self, code):
        self.code = code


class _Resolver:
    def __init__(self, runner, deadline):
        self.runner, self.deadline = runner, deadline
        self.queries = 0

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise _Unavailable('collection_timeout')
        return left

    def query(self, database, key, local):
        timeout = min(QUERY_SECONDS, self.remaining())
        if self.queries >= 12:
            raise _Unavailable('account_query_limit')
        self.queries += 1
        started = time.monotonic()
        try:
            result = self.runner(_argv(database, key, local), timeout=timeout)
        except Exception:
            raise _Unavailable('account_query_failed') from None
        self.remaining()
        if time.monotonic() - started >= timeout:
            raise _Unavailable('account_query_timeout')
        if (type(result) is not QueryResult or result.code != 'ok' or result.returncode != 0
                or type(result.output) is not bytes or len(result.output) > MAX_QUERY_BYTES):
            raise _Unavailable('account_unavailable')
        if database == 'passwd':
            value = _parse(result.output, database)
            if value is None:
                raise _Unavailable('account_output_invalid')
            return value[:3]
        try:
            if not result.output.endswith(b'\n') or result.output.count(b'\n') != 1:
                raise ValueError
            raw = result.output[:-1].decode('ascii')
            if any(ord(char) < 32 and char != '\t' or ord(char) == 127 for char in raw):
                raise ValueError
            fields = raw.split()
            if (not 2 <= len(fields) <= MAX_GROUPS + 1 or fields[0] != key
                    or any(not _numeric(item) for item in fields[1:])):
                raise ValueError
            groups = tuple(int(item) for item in fields[1:])
            if len(set(groups)) != len(groups):
                raise ValueError
            return tuple(sorted(groups))
        except (ValueError, UnicodeError):
            raise _Unavailable('account_output_invalid') from None

    def resolve(self, name):
        first = self.query('passwd', name, True)
        if first[0] != name:
            raise _Unavailable('account_conflict')
        if not first[1] or not first[2]:
            raise _Unavailable('unsupported_account')
        for key, local in ((name, False), (str(first[1]), True), (str(first[1]), False)):
            if self.query('passwd', key, local) != first:
                raise _Unavailable('account_conflict')
        groups = self.query('initgroups', name, True)
        if self.query('initgroups', name, False) != groups or first[2] not in groups:
            raise _Unavailable('account_conflict')
        return {'uid': first[1], 'gid': first[2], 'groups': list(groups)}


def observe_consumer_access(check, resource, *, host_id, engine_aliases=None,
                            observed_at=None, query_runner=None, worker_runner=None):
    """Observe one exact declared-user access predicate through trusted seams.

    No store, policy, adoption or application authority is inferred here.
    Caller-owned runners must honor their bounds; late results are discarded.
    """
    when = utc_now() if observed_at is None else observed_at
    try:
        validate_context(host_id, when)
        if any(runner is not None and not callable(runner) for runner in (query_runner, worker_runner)):
            raise ValueError
    except ValueError:
        raise ConsumerAccessError('invalid_consumer_access_context') from None
    binding = _binding(check, resource, host_id, {} if engine_aliases is None else engine_aliases)
    context = json.loads(binding)  # Freeze all caller values before any I/O.
    definition, target = context['check'], context['resource']
    reason = None
    if target['kind'] not in ('file', 'directory'):
        reason = 'unsupported_resource'
    elif definition['operation'] != {'file': 'read', 'directory': 'list'}[target['kind']]:
        reason = 'unsupported_operation'
    elif definition['as_user'].isdigit():
        reason = 'unsupported_account'
    result = None
    if reason is None:
        resolver = _Resolver(run_readonly if query_runner is None else query_runner,
                             time.monotonic() + definition['timeout_seconds'])
        try:
            credentials = resolver.resolve(definition['as_user'])
            credential_binding = canonical_json(credentials)
            request = dict(path=target['identity']['path'], kind=target['kind'],
                           operation=definition['operation'], **json.loads(credential_binding))
            try:
                result = (run_access if worker_runner is None else worker_runner)(
                    request, timeout=resolver.remaining())
            except Exception:
                raise _Unavailable('worker_runner_failed') from None
            resolver.remaining()
            if type(result) is not AccessResult:
                raise _Unavailable('worker_result_invalid')
            try:
                result = AccessResult(result.code)
            except (ValueError, AttributeError):
                raise _Unavailable('worker_result_invalid') from None
            if canonical_json(resolver.resolve(definition['as_user'])) != credential_binding:
                raise _Unavailable('account_changed')
        except _Unavailable as error:
            reason = error.code
    if reason is not None:
        state = 'unavailable'
    elif result.code == 'ok':
        state, reason = 'match', 'access_succeeded'
    elif result.code == 'denied':
        state, reason = 'mismatch', 'access_denied'
    else:
        state, reason = 'unavailable', result.code
    return ConsumerAccessObservation(binding, when, state, reason)
