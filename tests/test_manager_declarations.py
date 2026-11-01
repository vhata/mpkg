"""The declaration model is pure and preserves immutable nonsecret snapshots."""
import hashlib
import unittest

from mpkg_manager.declarations import DeclarationError, canonical_json, load_declaration, physical_key


class DeclarationTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
