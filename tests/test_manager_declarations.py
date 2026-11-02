"""The declaration model is pure and preserves immutable nonsecret snapshots."""
import hashlib
import json
import unittest

from mpkg_manager.declarations import (
    DeclarationError, canonical_json, load_declaration, physical_key, validate_model,
)


def _toml(value):
    if type(value) is dict:
        return '{' + ','.join(json.dumps(key) + '=' + _toml(item) for key, item in value.items()) + '}'
    if type(value) is list:
        return '[' + ','.join(_toml(item) for item in value) + ']'
    return json.dumps(value)


def declaration(resources=(), components=(), **extensions):
    model = dict(schema=1, resources=list(resources), components=list(components)) | extensions
    return load_declaration(('\n'.join(key + '=' + _toml(value) for key, value in model.items())).encode())


def resource(identity=None, **fields):
    return dict(id='data', kind='directory', identity=identity or {'path': '/srv/data'},
                desired={'mode': 0o750}, manage=['mode']) | fields


class DeclarationTests(unittest.TestCase):
    def test_decoded_model_matches_toml_and_does_not_share_caller_objects(self):
        original = dict(schema=1, resources=[resource({'path': '/srv/child/../data'})],
                        components=[dict(id='one', purpose='Use data', resources=['data'], requirements=[
                            dict(resource='data', property='mode', value=0o750)])])
        before = canonical_json(original)
        normalized = validate_model(original)
        from_toml = declaration(original['resources'], original['components']).model
        self.assertEqual(normalized, from_toml)
        self.assertEqual(normalized['resources'][0]['identity']['path'], '/srv/data')
        self.assertEqual(normalized['resources'][0]['consumers'], ['one'])
        self.assertEqual(canonical_json(original), before)
        normalized['components'][0]['requirements'][0]['value'] = 0o700
        normalized['resources'][0]['desired']['mode'] = 0o700
        self.assertEqual(canonical_json(original), before)
        original['resources'][0]['identity']['path'] = '/elsewhere'
        self.assertEqual(normalized['resources'][0]['identity']['path'], '/srv/data')
        self.assertEqual(validate_model(from_toml), from_toml)

    def test_decoded_model_and_toml_share_context_and_reference_errors(self):
        component = dict(id='one', purpose='Use resource', resources=['data'], requirements=[])
        cases = [
            ([resource({'name': 'example'}, kind='package', desired={'source': 'aur'}, manage=[])],
             [component | {'requirements': [dict(resource='data', property='version',
                                                  value={'policy': 'exact', 'value': '1-1'})]}]),
            ([resource({'path': '/fixture/config'}, kind='file', desired={}, manage=[])],
             [component | {'requirements': [dict(resource='data', property='content_input',
                                                  value='missing')]}]),
            ([resource()], [component | {'resources': ['missing']}]),
            ([resource(), resource({'path': '/srv/child/../data'}, id='other')], []),
        ]
        for resources, components in cases:
            with self.subTest(resources=resources, components=components):
                model = dict(schema=1, resources=resources, components=components)
                before = canonical_json(model)
                with self.assertRaises(DeclarationError) as decoded_error:
                    validate_model(model)
                with self.assertRaises(DeclarationError) as toml_error:
                    declaration(resources, components)
                self.assertEqual((decoded_error.exception.code, decoded_error.exception.path),
                                 (toml_error.exception.code, toml_error.exception.path))
                self.assertEqual(canonical_json(model), before)

    def test_decoded_model_rejects_malformed_cycles_and_depth_with_fixed_errors(self):
        cycle = {}
        cycle['value'] = cycle
        deep = []
        for _ in range(2000):
            deep = [deep]
        cases = [(None, 'expected_table'), ([], 'expected_table'),
                 ({'schema': True}, 'missing_key'),
                 ({'schema': 1, 'components': [], 'resources': [], 'SENTINEL': True}, 'unknown_key'),
                 ({'SENTINEL': float('nan')}, 'unsupported_value_type'),
                 ({'SENTINEL': object()}, 'unsupported_value_type'),
                 ({'SENTINEL': 2**63}, 'integer_out_of_range'),
                 (cycle, 'declaration_nesting_limit'), (deep, 'declaration_nesting_limit')]
        for value, code in cases:
            with self.subTest(code=code), self.assertRaises(DeclarationError) as error:
                validate_model(value)
            self.assertEqual(error.exception.code, code)
            self.assertNotIn('SENTINEL', str(error.exception))
            self.assertNotIn('SENTINEL', error.exception.path)

    def test_snapshot_is_stable_and_projection_is_independent(self):
        source = b'''schema = 1
[[components]]
id = "tools"
purpose = "Developer tools"
resources = ["git"]
[[resources]]
id = "git"
kind = "package"
identity = {name = "git"}
manage = ["present"]
desired = {present = true, source = "repository", version = {policy = "any"}}
'''
        declaration = load_declaration(source)
        self.assertEqual(declaration.source_bytes, source)
        self.assertEqual(declaration.sha256, hashlib.sha256(declaration.canonical_bytes).hexdigest())
        model = declaration.model
        model['resources'][0]['desired']['present'] = False
        self.assertTrue(declaration.model['resources'][0]['desired']['present'])
        self.assertEqual(load_declaration(source.replace(b'schema = 1', b'schema=1')).canonical_bytes,
                         declaration.canonical_bytes)
        self.assertEqual(physical_key(declaration.model['resources'][0], 'host', {}),
                         ('host', 'package', 'git'))

    def test_fixed_scalars_and_canonical_order(self):
        self.assertEqual(canonical_json({'b': [2, 1], 'a': True}), b'{"a":true,"b":[2,1]}')
        for value in (float('nan'), 1.5, 2**63, {'bad': object()}, {'bad': '\ud800'}):
            with self.subTest(value=type(value).__name__), self.assertRaises(DeclarationError):
                canonical_json(value)

    def test_closed_root_and_types(self):
        base = 'schema=1\ncomponents=[]\nresources=[]\n'
        for source in (base+'surprise="SENTINEL"', base.replace('schema=1', 'schema=true'),
                       base+'inputs=[{id="unchecked"}]', base+'value=2026-01-01'):
            with self.subTest(source=source), self.assertRaises(DeclarationError) as error:
                load_declaration(source.encode())
            self.assertNotIn('SENTINEL', str(error.exception))

    def test_all_resource_identities_are_typed_and_never_resolved(self):
        cases = [
            ('package', {'name': 'ack'}, {'present': True, 'source': 'aur',
             'version': {'policy': 'exact', 'value': '1:3.10-1', 'recipe_revision': 'a' * 40}}),
            ('compose', {'engine': 'local', 'project': 'sonarr'}, {'running': True,
             'images': [{'service': 'sonarr', 'policy': 'exact', 'reference': 'example/sonarr:latest',
                         'digest': 'sha256:' + 'a' * 64, 'platform': 'linux/amd64'}]}),
            ('volume', {'engine': 'local', 'name': 'media'}, {'present': True}),
            ('network', {'engine': 'local', 'name': 'bridge'}, {'present': True}),
            ('service', {'manager': 'system', 'unit': 'sshd.service'}, {'running': True, 'enabled': False}),
            ('user', {'name': 'svc'}, {'present': True, 'home': '/srv/./svc', 'shell': '/bin/false',
                                     'primary_group': 'media', 'groups': ['video']}),
            ('group', {'name': 'media'}, {'present': True, 'members': ['svc']}),
            ('file', {'path': '/definitely-absent/config'}, {'content': '', 'mode': 0o600}),
            ('directory', {'path': '/definitely-absent/data'}, {'present': True, 'owner': 'svc'}),
            ('symlink', {'path': '/definitely-absent/current'}, {'target': 'data'}),
            ('sonarr_xml', {'path': '/definitely-absent/config.xml'}, {'port': 8989}),
        ]
        for kind, identity, desired in cases:
            with self.subTest(kind=kind):
                item = resource(identity, kind=kind, desired=desired, manage=list(desired))
                parsed = declaration([item]).model['resources'][0]
                self.assertEqual(parsed['kind'], kind)
                self.assertEqual(parsed['identity'], identity)

    def test_duplicate_normalized_paths_include_different_resource_kinds(self):
        for second in [resource({'path': '/srv/child/../data'}, id='second'),
                       resource({'path': '/srv/data'}, id='second', kind='file')]:
            with self.subTest(second=second), self.assertRaises(DeclarationError) as error:
                declaration([resource(), second])
            self.assertEqual(error.exception.code, 'duplicate_physical_identity')

    def test_conflicting_shared_requirements_never_choose_a_winner(self):
        components = [dict(id=name, purpose='Use shared data', resources=['data'],
                           requirements=[dict(resource='data', property='mode', value=mode)])
                      for name, mode in [('one', 0o750), ('two', 0o700)]]
        with self.assertRaises(DeclarationError) as error:
            declaration([resource()], components)
        self.assertEqual(error.exception.code, 'conflicting_requirements')
        components[1]['requirements'][0]['value'] = 0o750
        parsed = declaration([resource()], components).model
        self.assertEqual(parsed['resources'][0]['consumers'], ['one', 'two'])
        self.assertEqual(parsed['resources'][0]['manage'], ['mode'])
        components[1]['requirements'][0]['value'] = True
        with self.assertRaises(DeclarationError):
            declaration([resource()], components)

    def test_package_version_context_combines_desired_and_consumer_requirements(self):
        exact = {'policy': 'exact', 'value': '1-1'}
        versions = [exact, exact | {'recipe_revision': 'a' * 40}, {'policy': 'any'}]
        placements = [('desired', 'desired'), ('desired', 'one'),
                      ('one', 'desired'), ('one', 'one'), ('one', 'two')]
        for source in ('aur', 'repository', 'unknown', None):
            for version in versions:
                for source_place, version_place in placements:
                    with self.subTest(source=source, version=version,
                                      placements=(source_place, version_place)):
                        desired = {}
                        components = {name: dict(id=name, purpose='Use package', resources=['data'],
                                                 requirements=[]) for name in ('one', 'two')}
                        for prop, value, place in [('source', source, source_place),
                                                   ('version', version, version_place)]:
                            if value is None:
                                continue
                            if place == 'desired':
                                desired[prop] = value
                            else:
                                components[place]['requirements'].append(
                                    dict(resource='data', property=prop, value=value))
                        package = resource({'name': 'example'}, kind='package',
                                           desired=desired, manage=[])
                        expected_error = None
                        if 'recipe_revision' in version and source != 'aur':
                            expected_error = 'unexpected_recipe_revision'
                        elif source == 'aur' and version == exact:
                            expected_error = 'missing_recipe_revision'
                        if expected_error:
                            with self.assertRaises(DeclarationError) as error:
                                declaration([package], components.values())
                            self.assertEqual(error.exception.code, expected_error)
                        else:
                            model = declaration([package], components.values()).model
                            self.assertEqual(model['resources'][0]['desired'], desired)
                            self.assertEqual(model['resources'][0]['manage'], [])

        # A disagreeing source remains a conflict, regardless of its version.
        package = resource({'name': 'example'}, kind='package', desired={
            'source': 'repository', 'version': exact | {'recipe_revision': 'a' * 40}}, manage=[])
        component = dict(id='one', purpose='Use package', resources=['data'], requirements=[
            dict(resource='data', property='source', value='aur')])
        with self.assertRaises(DeclarationError) as error:
            declaration([package], [component])
        self.assertEqual(error.exception.code, 'conflicting_requirements')

    def test_references_cycles_and_unsupported_properties_fail_closed(self):
        cases = [
            [resource(requires=['missing'])],
            [resource(requires=['other']), resource({'path': '/other'}, id='other', requires=['data'])],
            [resource(consumers=['external:'])],
            [resource(consumers=['missing'])],
            [resource(checks=['missing'])],
            [resource(input={'bundle': 'missing'})],
            [resource(desired={'uid': 123}, manage=['uid'])],
            [resource(manage=['present'])],
            [resource(identity={'path': 'relative'})],
            [resource(identity={'path': '/safe', 'command': 'SENTINEL'})],
            [resource(), resource({'path': '/other'})],
        ]
        for items in cases:
            with self.subTest(items=items), self.assertRaises(DeclarationError) as error:
                declaration(items)
            self.assertNotIn('SENTINEL', str(error.exception))

    def test_file_content_input_requirements_resolve_only_single_file_bundles(self):
        bundle = dict(id='bundle', base_directory='/does/not/exist', files=[
            dict(path='config', classification='nonsecret')])
        protected = bundle | {'files': [dict(path='secret', classification='protected',
            reference='0a89debe-8e38-4e24-a27f-b3763ad252a8')]}
        multiple = bundle | {'files': bundle['files'] + [
            dict(path='other', classification='nonsecret')]}
        for placement in ('desired', 'requirement'):
            for inputs in ([], [bundle], [protected], [multiple]):
                with self.subTest(placement=placement, inputs=inputs):
                    desired = {'content_input': 'bundle'} if placement == 'desired' else {}
                    requirements = [] if placement == 'desired' else [
                        dict(resource='data', property='content_input', value='bundle')]
                    component = dict(id='one', purpose='Use file', resources=['data'],
                                     requirements=requirements)
                    item = resource({'path': '/fixture/file'}, kind='file', desired=desired, manage=[])
                    if not inputs or inputs == [multiple]:
                        with self.assertRaises(DeclarationError) as error:
                            declaration([item], [component], inputs=inputs)
                        self.assertEqual(error.exception.code, 'content_requires_single_file_input')
                        expected_path = (('resources', 0, 'desired', 'content_input')
                                         if placement == 'desired' else
                                         ('components', 0, 'requirements', 0, 'value'))
                        self.assertEqual(error.exception.path, expected_path)
                    else:
                        model = declaration([item], [component], inputs=inputs).model
                        self.assertEqual(model['resources'][0]['desired'], desired)
                        self.assertEqual(model['resources'][0]['manage'], [])
                        if placement == 'requirement':
                            with self.assertRaises(DeclarationError) as error:
                                declaration([item | {'manage': ['content_input']}],
                                            [component], inputs=inputs)
                            self.assertEqual(error.exception.code, 'managed_property_without_value')

    def test_file_content_sources_are_exclusive_across_all_constraints(self):
        bundle = dict(id='bundle', base_directory='/does/not/exist', files=[
            dict(path='config', classification='nonsecret')])
        for content_place, input_place in [('desired', 'desired'), ('desired', 'one'),
                                           ('one', 'desired'), ('one', 'one'), ('one', 'two')]:
            with self.subTest(placements=(content_place, input_place)):
                desired = {}
                components = {name: dict(id=name, purpose='Use file', resources=['data'],
                                         requirements=[]) for name in ('one', 'two')}
                for prop, value, place in [('content', 'declared text', content_place),
                                           ('content_input', 'bundle', input_place)]:
                    if place == 'desired':
                        desired[prop] = value
                    else:
                        components[place]['requirements'].append(
                            dict(resource='data', property=prop, value=value))
                item = resource({'path': '/fixture/file'}, kind='file', desired=desired, manage=[])
                with self.assertRaises(DeclarationError) as error:
                    declaration([item], components.values(), inputs=[bundle])
                self.assertEqual(error.exception.code, 'conflicting_content_sources')

    def test_dependency_dag_can_share_prerequisites(self):
        items = [resource({'path': '/' + name}, id=name, requires=dependencies)
                 for name, dependencies in [('a', ['b', 'c']), ('b', ['d']), ('c', ['d']), ('d', [])]]
        self.assertEqual(len(declaration(items).model['resources']), 4)

    def test_inputs_preserve_order_and_protected_references_without_reads(self):
        bundle = dict(id='bundle', base_directory='/does/not/exist', files=[
            dict(path='compose.yaml', classification='nonsecret'),
            dict(path='./.env', classification='protected', reference='0a89debe-8e38-4e24-a27f-b3763ad252a8')])
        deploy = resource({'engine': 'local', 'project': 'sonarr'}, kind='compose',
                          desired={'running': True}, manage=['running'], input={'bundle': 'bundle'})
        original = declaration([deploy], inputs=[bundle])
        self.assertEqual(original.model['inputs'][0]['files'][1]['path'], '.env')
        bundle['files'].reverse()
        self.assertNotEqual(declaration([deploy], inputs=[bundle]).sha256, original.sha256)
        for bad in [dict(path='../escape', classification='nonsecret'),
                    dict(path='.env', classification='protected', reference='not-an-opaque-id'),
                    dict(path='secret', classification='nonsecret', reference='0a89debe-8e38-4e24-a27f-b3763ad252a8'),
                    dict(path='secret', classification='protected', value='SENTINEL')]:
            with self.subTest(bad=bad), self.assertRaises(DeclarationError):
                declaration([deploy], inputs=[bundle | {'files': [bad]}])

    def test_closed_checks_are_bounded_and_bound_to_resources(self):
        service = resource({'manager': 'system', 'unit': 'sonarr.service'}, kind='service',
                           desired={'running': True}, manage=['running'], checks=['healthy'])
        endpoint = dict(id='healthy', kind='endpoint', resource='data', timeout_seconds=5,
                        url='http://127.0.0.1:8989/ping', expected_status=200)
        self.assertEqual(declaration([service], checks=[endpoint]).model['checks'][0], endpoint)
        for update in [dict(url='https://remote.example:443/'), dict(url='http://user:secret@127.0.0.1:1/'),
                       dict(url='http://127.0.0.1:1/?token=secret'), dict(timeout_seconds=0),
                       dict(timeout_seconds=True), dict(expected_status=600), dict(command='SENTINEL')]:
            with self.subTest(update=update), self.assertRaises(DeclarationError):
                declaration([service], checks=[endpoint | update])
        package = resource({'name': 'git'}, kind='package', desired={'present': True}, manage=['present'])
        with self.assertRaises(DeclarationError):
            declaration([package], checks=[endpoint])
        check = dict(id='exists', kind='package', resource='data', timeout_seconds=5,
                     expected={'present': True, 'reason': 'explicit'})
        self.assertEqual(declaration([package], checks=[check]).model['checks'][0], check)

    def test_endpoint_urls_reject_literal_ascii_controls_with_private_errors(self):
        service = resource({'manager': 'system', 'unit': 'sonarr.service'}, kind='service',
                           desired={'running': True}, manage=['running'], checks=['healthy'])
        endpoint = dict(id='healthy', kind='endpoint', resource='data', timeout_seconds=5,
                        expected_status=200)
        for codepoint in (*range(32), 127):
            control = chr(codepoint)
            for url in (control + 'http://127.0.0.1:8989/private-sentinel',
                        'http://127.0.0.1:8989/private-sentinel' + control + '/health',
                        'http://127.0.0.1:8989/private-sentinel' + control):
                check = endpoint | {'url': url}
                model = dict(schema=1, components=[], resources=[service], checks=[check])
                loaders = {'model': lambda: validate_model(model),
                           'toml': lambda: declaration([service], checks=[check])}
                for name, load in loaders.items():
                    with self.subTest(codepoint=codepoint, source=name, url_position=url.index(control)):
                        with self.assertRaises(DeclarationError) as error:
                            load()
                        expected = 'expected_nonempty_string' if codepoint == 0 else 'unsupported_endpoint_url'
                        self.assertEqual(error.exception.code, expected)
                        self.assertEqual(str(error.exception), expected)
                        self.assertEqual(error.exception.path, ('checks', 0, 'url'))
                        self.assertNotIn('private-sentinel', str(error.exception))

    def test_endpoint_urls_preserve_normal_and_percent_encoded_paths(self):
        service = resource({'manager': 'system', 'unit': 'sonarr.service'}, kind='service',
                           desired={'running': True}, manage=['running'], checks=['healthy'])
        endpoint = dict(id='healthy', kind='endpoint', resource='data', timeout_seconds=5,
                        expected_status=200)
        urls = ['http://127.0.0.1:8989/health', 'https://localhost:443/health/readiness',
                'http://[::1]:8080/health', 'http://127.0.0.1:8989/%20health%2Fready',
                'http://127.0.0.1:8989/' + ''.join(f'%{codepoint:02X}' for codepoint in (*range(32), 127))]
        for url in urls:
            with self.subTest(url=url):
                check = endpoint | {'url': url}
                model = dict(schema=1, components=[], resources=[service], checks=[check])
                self.assertEqual(validate_model(model)['checks'][0]['url'], url)
                self.assertEqual(declaration([service], checks=[check]).model['checks'][0]['url'], url)

    def test_runtime_rules_cannot_hide_declared_configuration(self):
        component = dict(id='app', purpose='Service', resources=['config'])
        config = resource({'path': '/srv/config'}, id='config', kind='file',
                          desired={'content': 'setting=true'}, manage=['content'])
        rule = dict(id='runtime', component='app', root='/srv', patterns=['*'],
                    types=['file'], exceptions=[])
        with self.assertRaises(DeclarationError) as error:
            declaration([config], [component], runtime_rules=[rule])
        self.assertEqual(error.exception.code, 'runtime_scope_hides_configuration')
        rule['exceptions'] = ['/srv/config']
        self.assertEqual(declaration([config], [component], runtime_rules=[rule]).model['runtime_rules'][0], rule)
        for update in [dict(exceptions=['/elsewhere']), dict(patterns=['../outside']),
                       dict(component='missing'), dict(types=['device'])]:
            with self.subTest(update=update), self.assertRaises(DeclarationError):
                declaration([config], [component], runtime_rules=[rule | update])

    def test_invalid_utf8_and_toml_scalars_never_escape_the_public_error(self):
        for source in [b'\xff', b'schema=1\nresources=[]\ncomponents=[]\nvalue=nan',
                       b'schema=1\nresources=[]\ncomponents=[]\nvalue=2026-11-01',
                       b'schema=1\nresources=[]\ncomponents=[]\nvalue="SENTINEL',
                       b'schema=' + b'9' * 5000,
                       b'value=' + b'[' * 2000 + b'1' + b']' * 2000]:
            with self.subTest(source=source), self.assertRaises(DeclarationError) as error:
                load_declaration(source)
            self.assertNotIn('SENTINEL', str(error.exception))

    def test_host_and_engine_alias_binding_are_explicit(self):
        deploy = resource({'engine': 'local', 'project': 'sonarr'}, kind='compose',
                          desired={'running': True}, manage=['running'])
        parsed = declaration([deploy]).model['resources'][0]
        with self.assertRaises(DeclarationError):
            physical_key(parsed, 'host', {})
        self.assertEqual(physical_key(parsed, 'host', {'local': 'engine-id'}),
                         ('host', 'compose', 'engine-id', 'sonarr'))


if __name__ == '__main__':
    unittest.main()
