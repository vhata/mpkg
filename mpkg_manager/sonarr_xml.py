"""Pure protected-byte transformation of the supported Sonarr XML Port field.

This module neither reads files nor grants authority to publish its result.
Callers must keep input/candidate bytes private and establish writer exclusion,
fresh source identity and protected input binding before any future file write.
"""
from dataclasses import dataclass, field
import re
from xml.parsers import expat

from .declarations import MAX_DECLARATION_BYTES


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
_PORT = re.compile(rb"[ \t\r\n]*([0-9]{1,10})[ \t\r\n]*\Z")
MAX_FIELDS = 256
MAX_ATTRIBUTES = 64


class SonarrXmlError(ValueError):
    """Fixed diagnostics that never include XML, names, values or digests."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SonarrPortCandidate:
    candidate_bytes: bytes = field(repr=False)
    original_port: int
    port: int
    unchanged: bool

    def as_dict(self):
        """Return only the selected property and fixed capability metadata."""
        return {"adapter": "sonarr_xml_port_v1", "original_port": self.original_port,
                "port": self.port, "unchanged": self.unchanged,
                "serialization_changed": False, "apply_authorized": False}


def _fail(code):
    raise SonarrXmlError(code)


def _bytes(value):
    if type(value) is not bytes:
        _fail("expected_protected_bytes")
    if len(value) > MAX_DECLARATION_BYTES:
        _fail("xml_too_large")


def _port_span(raw):
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SonarrXmlError("unsupported_xml_encoding") from None
    if b"\0" in raw:
        _fail("unsupported_xml_encoding")
    if expat.version_info < (2, 6, 0):
        _fail("unsupported_xml_parser")

    parser = expat.ParserCreate()
    parser.buffer_text = False
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.UseForeignDTD(False)
    stack = []
    fields = set()
    content_start = None
    content_end = None

    def declaration(version, encoding, standalone):
        if version != "1.0":
            _fail("unsupported_xml_version")
        if encoding is not None and encoding.lower() != "utf-8":
            _fail("unsupported_xml_encoding")

    def forbidden_declaration(*args):
        _fail("unsupported_xml_declaration")

    def forbidden_structure(*args):
        _fail("unsupported_xml_structure")

    def start(name, attributes):
        if (not _NAME.fullmatch(name) or len(stack) >= 2
                or (not stack and name != "Config")):
            _fail("unsupported_xml_structure")
        if len(attributes) > MAX_ATTRIBUTES:
            _fail("xml_structure_limit")
        if any(not _NAME.fullmatch(key) or key == "xmlns" for key in attributes):
            _fail("unsupported_xml_structure")
        if stack:
            if name in fields:
                _fail("duplicate_xml_field")
            fields.add(name)
            if len(fields) > MAX_FIELDS:
                _fail("xml_structure_limit")
        stack.append(name)

    def end(name):
        nonlocal content_end
        if name == "Port":
            content_end = parser.CurrentByteIndex
        stack.pop()

    def characters(value):
        nonlocal content_start
        if len(stack) < 2:
            if value.strip(" \t\r\n"):
                _fail("unsupported_xml_structure")
        elif stack[-1] == "Port" and content_start is None:
            content_start = parser.CurrentByteIndex

    def comment(value):
        if stack and stack[-1] == "Port":
            _fail("unsupported_port_content")

    parser.XmlDeclHandler = declaration
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    parser.CommentHandler = comment
    parser.StartDoctypeDeclHandler = forbidden_declaration
    parser.EntityDeclHandler = forbidden_declaration
    parser.UnparsedEntityDeclHandler = forbidden_declaration
    parser.ExternalEntityRefHandler = forbidden_declaration
    parser.SkippedEntityHandler = forbidden_declaration
    parser.NotationDeclHandler = forbidden_declaration
    parser.StartCdataSectionHandler = forbidden_structure
    parser.ProcessingInstructionHandler = forbidden_structure
    try:
        parser.Parse(raw, True)
    except expat.ExpatError:
        raise SonarrXmlError("invalid_xml") from None

    if "Port" not in fields:
        _fail("missing_port")
    if content_start is None or content_end is None:
        _fail("unsupported_port_content")
    match = _PORT.fullmatch(raw[content_start:content_end])
    if match is None:
        _fail("unsupported_port_content")
    port = int(match[1])
    if not 1 <= port <= 65535:
        _fail("invalid_original_port")
    return port, content_start + match.start(1), content_start + match.end(1)


def transform_port(original, port, *, expected_original):
    """Make a protected candidate after matching the accepted original bytes.

    Exact equality is a stale-input precondition, not atomic file protection.
    The observed port may be 1..65535; requested intent is limited to
    1024..65535, matching the declaration schema. Only decimal Port bytes change.
    """
    _bytes(original)
    _bytes(expected_original)
    if type(port) is not int or not 1024 <= port <= 65535:
        _fail("invalid_target_port")
    if original != expected_original:
        _fail("original_changed")
    original_port, start, end = _port_span(original)
    unchanged = original_port == port
    candidate = original if unchanged else original[:start] + str(port).encode("ascii") + original[end:]
    if len(candidate) > MAX_DECLARATION_BYTES:
        _fail("xml_too_large")
    return SonarrPortCandidate(candidate, original_port, port, unchanged)
