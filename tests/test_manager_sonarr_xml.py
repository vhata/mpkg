"""Pure protected XML transformation, with no application or file authority."""
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest
from unittest.mock import patch

from mpkg_manager.sonarr_xml import (
    MAX_ATTRIBUTES, MAX_DECLARATION_BYTES, MAX_FIELDS,
    SonarrXmlError, transform_port,
)


def transform(raw, port=8990):
    return transform_port(raw, port, expected_original=raw)


class SonarrXmlTests(unittest.TestCase):
    def test_changes_only_actual_port_digits_preserving_protected_bytes(self):
        prefix = (b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>\r\n'
                  b'<!-- <Port>1234</Port> -->\r\n'
                  b'<Config keep="a > b &amp; c"><ApiKey kind="opaque">'
                  b'SECRET_SENTINEL&amp;&#65;\xc3\xa9</ApiKey>\r\n'
                  b'<Port keep=\'yes > no\'> \r\n')
        suffix = (b'\t </Port><Unmanaged attr="same"><!-- keep -->value</Unmanaged>'
                  b'<Empty />\r\n</Config><!-- trailing -->\n')
        raw = prefix + b'8989' + suffix
        candidate = transform(raw)
        self.assertEqual(candidate.candidate_bytes, prefix + b'8990' + suffix)
        self.assertEqual(candidate.original_port, 8989)
        self.assertEqual(candidate.port, 8990)
        self.assertFalse(candidate.unchanged)
        self.assertFalse(candidate.as_dict()['serialization_changed'])
        self.assertEqual(transform(candidate.candidate_bytes).candidate_bytes, candidate.candidate_bytes)

    def test_noop_preserves_noncanonical_digits_whitespace_and_bytes(self):
        raw = b'<Config><Port> \r\n0000008989\t </Port><ApiKey>secret</ApiKey></Config>'
        result = transform(raw, 8989)
        self.assertTrue(result.unchanged)
        self.assertIs(result.candidate_bytes, raw)
        with self.assertRaises(FrozenInstanceError):
            result.port = 8990
        result.as_dict()['port'] = 9999
        self.assertEqual(result.port, 8989)

    def test_observed_and_target_port_ranges_are_distinct(self):
        for observed in (1, 80, 1024, 65535):
            for target in (1024, 65535):
                with self.subTest(observed=observed, target=target):
                    raw = f'<Config><Port>{observed}</Port></Config>'.encode()
                    result = transform(raw, target)
                    self.assertEqual(result.original_port, observed)
                    self.assertEqual(result.port, target)
                    self.assertEqual(result.candidate_bytes,
                                     f'<Config><Port>{target}</Port></Config>'.encode())
        for target in (True, False, 1023, 65536, 0, -1, '8989', 8989.0):
            with self.subTest(target=target), self.assertRaises(SonarrXmlError) as error:
                transform(b'<Config><Port>8989</Port></Config>', target)
            self.assertEqual(error.exception.code, 'invalid_target_port')
        for observed in ('0', '65536', '9999999999'):
            with self.subTest(observed=observed), self.assertRaises(SonarrXmlError) as error:
                transform(f'<Config><Port>{observed}</Port></Config>'.encode())
            self.assertEqual(error.exception.code, 'invalid_original_port')

    def test_requires_exact_accepted_original_without_host_access(self):
        raw = b'<Config><Port>8989</Port><ApiKey>SECRET_SENTINEL</ApiKey></Config>'
        with self.assertRaises(SonarrXmlError) as error:
            transform_port(raw, 8990, expected_original=raw + b'\n')
        self.assertEqual(error.exception.code, 'original_changed')
        for value in (raw.decode(), bytearray(raw), None):
            for first, second in ((value, raw), (raw, value)):
                with self.subTest(value=type(value).__name__), self.assertRaises(SonarrXmlError) as error:
                    transform_port(first, 8990, expected_original=second)
                self.assertEqual(error.exception.code, 'expected_protected_bytes')
        with patch('builtins.open', side_effect=AssertionError('file access')), \
                patch('os.open', side_effect=AssertionError('file access')), \
                patch('subprocess.Popen', side_effect=AssertionError('process access')), \
                patch('socket.socket', side_effect=AssertionError('network access')):
            self.assertEqual(transform(raw).port, 8990)
            with self.assertRaises(SonarrXmlError):
                transform(b'<!DOCTYPE Config SYSTEM "file:///private/secret">'
                          b'<Config><Port>8989</Port></Config>')

    def test_errors_and_projection_do_not_disclose_protected_data_or_digests(self):
        raw = b'<Config><Port>8989</Port><ApiKey>SECRET_SENTINEL</ApiKey></Config>'
        result = transform(raw)
        public = repr(result) + str(result) + json.dumps(result.as_dict())
        self.assertNotIn('SECRET_SENTINEL', public)
        self.assertNotIn('ApiKey', public)
        self.assertNotIn(hashlib.sha256(raw).hexdigest(), public)
        self.assertNotIn(hashlib.sha256(result.candidate_bytes).hexdigest(), public)
        self.assertFalse(result.as_dict()['apply_authorized'])
        for malformed in (raw[:-1], raw.replace(b'8989', b'SECRET_SENTINEL'),
                          raw.replace(b'ApiKey', b'SECRET_SENTINEL:Key')):
            with self.assertRaises(SonarrXmlError) as error:
                transform(malformed)
            self.assertNotIn('SECRET_SENTINEL', repr(error.exception))
            self.assertEqual(str(error.exception), error.exception.code)
            self.assertEqual(error.exception.args, (error.exception.code,))

    def test_rejects_malformed_duplicate_nested_and_namespaced_structures(self):
        cases = [b'', b'<Config>', b'<Other><Port>8989</Port></Other>',
                 b'<Config><Port>8989</Port><Port>8990</Port></Config>',
                 b'<Config><Port>8989</Port><ApiKey>a</ApiKey><ApiKey>b</ApiKey></Config>',
                 b'<Config><Port><Nested>8989</Nested></Port></Config>',
                 b'<Config><Port>8989</Port><Other><Nested/></Other></Config>',
                 b'<Config>extra<Port>8989</Port></Config>',
                 b'<Config><Port>8989</Port>extra</Config>',
                 b'<Config xmlns="urn:example"><Port>8989</Port></Config>',
                 b'<Config><Port xmlns="">8989</Port></Config>',
                 b'<Config><Port xml:space="preserve">8989</Port></Config>',
                 b'<Config><Port>8989</Port></Config><Config/>',
                 b'<Config><Port>8989</Port><Ported a="1" a="2"/></Config>']
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(SonarrXmlError):
                transform(raw)

    def test_rejects_missing_ambiguous_and_encoded_port_text(self):
        for body in (b'<Port/>', b'<Port></Port>', b'<Port> </Port>',
                     b'<Port>8 989</Port>', b'<Port>+8989</Port>', b'<Port>-8989</Port>',
                     b'<Port>00000008989</Port>', b'<Port>8<!--comment-->989</Port>',
                     b'<Port>&#56;989</Port>', b'<Port>&#x38;989</Port>',
                     b'<Port>\xc2\xa08989</Port>', b'<Port>\xef\xbc\x98\xef\xbc\x99</Port>'):
            with self.subTest(body=body), self.assertRaises(SonarrXmlError) as error:
                transform(b'<Config>' + body + b'</Config>')
            self.assertEqual(error.exception.code, 'unsupported_port_content')
        with self.assertRaises(SonarrXmlError) as error:
            transform(b'<Config><ApiKey>secret</ApiKey></Config>')
        self.assertEqual(error.exception.code, 'missing_port')

    def test_rejects_dtd_entities_cdata_and_processing_instructions(self):
        documents = [
            b'<!DOCTYPE Config><Config><Port>8989</Port></Config>',
            b'<!DOCTYPE Config SYSTEM "https://invalid.example/secret"><Config><Port>8989</Port></Config>',
            b'<!DOCTYPE Config [<!ENTITY key "SECRET_SENTINEL">]><Config><Port>8989</Port><ApiKey>&key;</ApiKey></Config>',
            b'<!DOCTYPE Config [<!ENTITY % p SYSTEM "file:///private/secret">%p;]><Config><Port>8989</Port></Config>',
            b'<Config><Port>8989</Port><ApiKey>&undefined;</ApiKey></Config>',
            b'<Config><Port><![CDATA[8989]]></Port></Config>',
            b'<Config><Port>8989</Port><ApiKey><![CDATA[secret]]></ApiKey></Config>',
            b'<?instruction SECRET_SENTINEL?><Config><Port>8989</Port></Config>',
        ]
        for raw in documents:
            with self.subTest(raw=raw), self.assertRaises(SonarrXmlError) as error:
                transform(raw)
            self.assertNotIn('SECRET_SENTINEL', str(error.exception))

    def test_encoding_and_xml_version_are_explicit(self):
        for declaration in (b'', b'<?xml version="1.0"?>',
                            b'<?xml version="1.0" encoding="utf-8" standalone="yes"?>'):
            raw = declaration + b'<Config><Port>8989</Port></Config>'
            self.assertEqual(transform(raw).candidate_bytes, raw.replace(b'8989', b'8990'))
        for raw in [b'<?xml version="1.1"?><Config><Port>8989</Port></Config>',
                    b'<?xml version="1.0" encoding="iso-8859-1"?><Config><Port>8989</Port></Config>',
                    '<Config><Port>8989</Port></Config>'.encode('utf-16'),
                    '<Config><Port>8989</Port></Config>'.encode('utf-16-le'),
                    b'<Config><Port>8989</Port><ApiKey>\xff</ApiKey></Config>']:
            with self.subTest(raw=raw), self.assertRaises(SonarrXmlError):
                transform(raw)

    def test_input_candidate_and_parser_limits_fail_closed(self):
        template = b'<Config><Port>1</Port><ApiKey></ApiKey></Config>'
        raw = template.replace(b'<ApiKey>', b'<ApiKey>' + b'x' * (MAX_DECLARATION_BYTES - len(template)))
        self.assertEqual(len(raw), MAX_DECLARATION_BYTES)
        with self.assertRaises(SonarrXmlError) as error:
            transform(raw)
        self.assertEqual(error.exception.code, 'xml_too_large')
        with self.assertRaises(SonarrXmlError) as error:
            transform(raw + b' ')
        self.assertEqual(error.exception.code, 'xml_too_large')
        small = b'<Config><Port>8989</Port></Config>'
        with patch('mpkg_manager.sonarr_xml.expat.version_info', (2, 5, 0)), \
                self.assertRaises(SonarrXmlError) as error:
            transform(small)
        self.assertEqual(error.exception.code, 'unsupported_xml_parser')
        for extra in (b''.join(f'<Field{i}/>'.encode() for i in range(MAX_FIELDS)),
                      b'<Field ' + b' '.join(f'a{i}="v"'.encode() for i in range(MAX_ATTRIBUTES + 1)) + b'/>'):
            with self.assertRaises(SonarrXmlError) as error:
                transform(small.replace(b'</Config>', extra + b'</Config>'))
            self.assertEqual(error.exception.code, 'xml_structure_limit')


if __name__ == '__main__':
    unittest.main()
