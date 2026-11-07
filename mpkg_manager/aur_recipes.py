"""Pinned AUR acquisition and text metadata inspection, never recipe execution.

Trusted callers supply reviewed pins, explicit trust and dependency routing.
The result preserves private inputs; it grants neither build nor install
authority and leaves generated metadata and native resolution unverified.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re
import time
import urllib.parse
import urllib.request
import uuid


MAX_METADATA_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_RECIPES = 32
MAX_FILES = 128
_NAME = re.compile(r"[a-z0-9][a-z0-9@._+-]{0,127}\Z")
_FILE = re.compile(r"[A-Za-z0-9_.+-]{1,255}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_:~]*\Z")
_RELATION = re.compile(r"([a-z0-9][a-z0-9@._+-]{0,127})(?:(>=|<=|=|>|<)([A-Za-z0-9][A-Za-z0-9.+_:~\-]*))?\Z")
_HOSTS = frozenset({"raw.githubusercontent.com", "github.com", "codeload.github.com", "cpan.metacpan.org"})
_HASHES = {"md5sums": "md5", "sha1sums": "sha1", "sha224sums": "sha224",
           "sha256sums": "sha256", "sha384sums": "sha384", "sha512sums": "sha512", "b2sums": "blake2b"}
_MULTIPLE = {"arch", "license", "groups", "depends", "makedepends", "checkdepends", "optdepends",
             "provides", "conflicts", "replaces", "options", "backup", "source", "noextract", "validpgpkeys", *_HASHES}
_SINGLE = {"pkgdesc", "pkgver", "pkgrel", "epoch", "url", "install", "changelog"}
_ARCH_FIELDS = {"depends", "makedepends", "checkdepends", "optdepends", "provides", "conflicts",
                "replaces", "source", *_HASHES}
_BASE_ONLY = {"epoch", "pkgver", "pkgrel", "validpgpkeys", "makedepends", "checkdepends", "source", "noextract", *_HASHES}


class AurPreparationError(RuntimeError):
    """Fixed diagnostics; never raw recipe, URL or downloader exception text."""
    def __init__(self, code="invalid_aur_request"):
        self.code = code
        super().__init__(code)


def _require(condition, code="invalid_aur_request"):
    if not condition:
        raise AurPreparationError(code)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _name(value):
    return type(value) is str and bool(_NAME.fullmatch(value))


def _filename(value):
    return type(value) is str and bool(_FILE.fullmatch(value)) and value not in {".", ".."}


def _url(value):
    _require(type(value) is str and len(value) <= 4096, "unsupported_source")
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        raise AurPreparationError("unsupported_source") from None
    _require(parsed.scheme == "https" and parsed.netloc in _HOSTS and not parsed.query
             and not parsed.fragment and parsed.path.startswith("/")
             and not any(ord(char) < 33 or ord(char) > 126 for char in value)
             and "\\" not in value and "%" not in value and ".." not in parsed.path.split("/"),
             "unsupported_source")
    return value


def _digest(algorithm, raw):
    return hashlib.new(algorithm, raw, usedforsecurity=False).hexdigest()


@dataclass(frozen=True)
class FilePin:
    name: str
    url: str = field(repr=False)
    digests: tuple = field(repr=False)

    def __post_init__(self):
        _require(_filename(self.name))
        _url(self.url)
        _require(type(self.digests) is tuple and 1 <= len(self.digests) <= 2)
        seen = set()
        for item in self.digests:
            _require(type(item) is tuple and len(item) == 2)
            algorithm, value = item
            _require(type(algorithm) is str and algorithm in {"sha256", "sha512"} and algorithm not in seen
                     and type(value) is str and bool(re.fullmatch(
                         "[0-9a-f]{" + str(hashlib.new(algorithm).digest_size * 2) + "}", value)))
            seen.add(algorithm)

    def _model(self):
        return {"name": self.name, "url": self.url, "digests": dict(self.digests)}


@dataclass(frozen=True)
class RecipePin:
    package_base: str
    commit: str = field(repr=False)
    version: str
    packages: tuple
    files: tuple = field(repr=False)
    sources: tuple = field(repr=False)
    provenance: str

    def __post_init__(self):
        _require(_name(self.package_base) and type(self.commit) is str
                 and bool(re.fullmatch("[0-9a-f]{40}", self.commit)))
        _require(self.provenance == "aur_official_mirror", "unknown_recipe_provenance")
        _require(type(self.version) is str and len(self.version) <= 256
                 and bool(re.fullmatch(r"(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9.+_~]*-[0-9]+(?:\.[0-9]+)?", self.version)))
        _require(type(self.packages) is tuple and 1 <= len(self.packages) <= 64
                 and all(_name(name) for name in self.packages) and len(set(self.packages)) == len(self.packages))
        _require(type(self.files) is tuple and type(self.sources) is tuple
                 and 2 <= len(self.files) <= 64 and len(self.sources) <= 64)
        for pin in self.files + self.sources:
            _require(type(pin) is FilePin)
            pin.__post_init__()
        names = [pin.name for pin in self.files + self.sources]
        _require(len(names) == len(set(names)) and {"PKGBUILD", ".SRCINFO"} <= set(names))
        _require({"PKGBUILD", ".SRCINFO"} <= {pin.name for pin in self.files})
        for pin in self.files:
            _require(pin.url == f"https://raw.githubusercontent.com/archlinux/aur/{self.commit}/{pin.name}",
                     "recipe_provenance_mismatch")

    def _model(self):
        return {"package_base": self.package_base, "repository": f"https://aur.archlinux.org/{self.package_base}.git",
                "commit": self.commit, "version": self.version, "packages": list(self.packages),
                "files": [pin._model() for pin in self.files], "sources": [pin._model() for pin in self.sources],
                "provenance": self.provenance}

    @property
    def recipe_id(self):
        return hashlib.sha256(_json(self._model())).hexdigest()


@dataclass(frozen=True)
class RecipeTrust:
    """Explicit trusted acceptance of one complete pin; never execution authority."""
    recipe_id: str = field(repr=False)
    operator_uid: int
    decision_id: str

    def __post_init__(self):
        _require(type(self.recipe_id) is str and bool(re.fullmatch("[0-9a-f]{64}", self.recipe_id))
                 and type(self.operator_uid) is int and 0 <= self.operator_uid < 2**32 - 1)
        try:
            valid = type(self.decision_id) is str and str(uuid.UUID(self.decision_id)) == self.decision_id
        except ValueError:
            valid = False
        _require(valid)


@dataclass(frozen=True)
class DependencyChoice:
    """Explicit source routing, without solving versions or selecting native providers."""
    name: str
    source: str
    recipe_base: str | None = None
    package: str | None = None

    def __post_init__(self):
        _require(_name(self.name) and self.source in {"native", "aur"})
        _require((self.source == "native" and self.recipe_base is None and self.package is None)
                 or (self.source == "aur" and _name(self.recipe_base) and _name(self.package)))


@dataclass(frozen=True)
class SrcInfo:
    _data: bytes = field(repr=False)

    @property
    def model(self):
        """Private untrusted metadata, not an ordinary user-facing projection."""
        return json.loads(self._data)


def _field(key):
    if key in _MULTIPLE | _SINGLE:
        return key, None
    for prefix in sorted(_ARCH_FIELDS, key=len, reverse=True):
        if key.startswith(prefix + "_"):
            architecture = key[len(prefix) + 1:]
            _require(_name(architecture) and architecture != "any", "invalid_srcinfo")
            return prefix, architecture
    raise AurPreparationError("unsupported_srcinfo_field")


def parse_srcinfo(raw, *, architecture="x86_64"):
    """Read bounded text only. PKGBUILD is never parsed, sourced or executed."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_METADATA_BYTES and _name(architecture), "invalid_srcinfo")
    try:
        text = raw.decode("utf-8")
        _require(not any(ord(char) < 32 and char not in "\n\t" for char in text), "invalid_srcinfo")
        lines = text.splitlines()
        _require(len(lines) <= 8192, "invalid_srcinfo")
        base, packages, section = None, [], None
        for line in lines:
            line = line.lstrip()
            if not line or line.startswith("#"):
                continue
            _require(" =" in line and len(line) <= 8192, "invalid_srcinfo")
            key, value = line.split(" =", 1)
            _require(not value or value.startswith(" "), "invalid_srcinfo")
            value = value[1:] if value else value
            _require(value == value.strip() and not any(ord(char) < 32 for char in value), "invalid_srcinfo")
            if key in {"pkgbase", "pkgname"}:
                _require(_name(value), "invalid_srcinfo")
                if key == "pkgbase":
                    _require(base is None, "invalid_srcinfo")
                    base = {"name": value, "fields": {}}
                    section = base
                else:
                    _require(base is not None and len(packages) < 64
                             and value not in {row["name"] for row in packages}, "invalid_srcinfo")
                    section = {"name": value, "fields": {}}
                    packages.append(section)
                continue
            _require(section is not None, "invalid_srcinfo")
            kind, _ = _field(key)
            _require(section is base or kind not in _BASE_ONLY, "invalid_srcinfo")
            values = section["fields"].setdefault(key, [])
            _require(kind in _MULTIPLE or not values, "invalid_srcinfo")
            _require(value or (section is not base and kind not in _BASE_ONLY), "invalid_srcinfo")
            values.append(value)
        _require(base is not None and packages, "invalid_srcinfo")
        fields = base["fields"]
        _require(len(fields.get("pkgver", [])) == 1 and len(fields.get("pkgrel", [])) == 1, "invalid_srcinfo")
        version, release = fields["pkgver"][0], fields["pkgrel"][0]
        _require(bool(_VERSION.fullmatch(version)) and ":" not in version
                 and bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", release)), "invalid_srcinfo")
        epoch = fields.get("epoch", [None])[0]
        _require(epoch is None or bool(re.fullmatch("[0-9]+", epoch)), "invalid_srcinfo")
        full_version = ("" if epoch is None else epoch + ":") + version + "-" + release
        outputs = []
        for package in packages:
            effective = fields | package["fields"]
            arches = effective.get("arch", [])
            _require(arches and len(set(arches)) == len(arches)
                     and (arches == ["any"] or ("any" not in arches and architecture in arches)), "unsupported_architecture")
            dependencies = []
            provides = []
            for kind in ("depends", "provides", "conflicts", "replaces"):
                for value in effective.get(kind, []) + effective.get(kind + "_" + architecture, []):
                    if not value:
                        continue  # An empty package override unsets the base list.
                    match = _RELATION.fullmatch(value)
                    _require(match is not None and match[2] in (None, "=", ">", "<", ">=", "<="), "invalid_srcinfo")
                    if kind == "depends":
                        dependencies.append(value)
                    if kind == "provides":
                        _require(match[2] in (None, "="), "invalid_srcinfo")
                        provides.append(value)
            outputs.append({"name": package["name"], "version": full_version,
                            "dependencies": dependencies, "provides": provides, "fields": effective})
        for kind in ("makedepends", "checkdepends"):
            for value in fields.get(kind, []) + fields.get(kind + "_" + architecture, []):
                match = _RELATION.fullmatch(value)
                _require(match is not None and match[2] in (None, "=", ">", "<", ">=", "<="), "invalid_srcinfo")
        return SrcInfo(_json({"package_base": base["name"], "version": full_version,
                             "architecture": architecture, "fields": fields, "outputs": outputs}))
    except (UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise AurPreparationError("invalid_srcinfo") from None


def _sources(metadata):
    fields, architecture = metadata["fields"], metadata["architecture"]
    result = []
    for suffix in ("", "_" + architecture):
        sources = fields.get("source" + suffix, [])
        checksums = {key: fields[key + suffix] for key in _HASHES if key + suffix in fields}
        _require(all(len(values) == len(sources) for values in checksums.values()), "source_metadata_mismatch")
        for index, source in enumerate(sources):
            rename, separator, location = source.partition("::")
            if not separator:
                location, rename = source, None
            if "://" in location:
                _url(location)
                name = rename or urllib.parse.urlsplit(location).path.rsplit("/", 1)[-1]
            else:
                _require(rename is None and _filename(location), "unsupported_source")
                name = location
            _require(_filename(name), "unsupported_source")
            digests = {}
            for key, values in checksums.items():
                value, algorithm = values[index], _HASHES[key]
                _require(type(value) is str and bool(re.fullmatch(
                    "[0-9a-f]{" + str(hashlib.new(algorithm).digest_size * 2) + "}", value)), "unsupported_source_checksum")
                digests[algorithm] = value
            _require(set(digests) & {"sha256", "sha512"}, "strong_source_checksum_required")
            result.append({"name": name, "url": location if "://" in location else None, "digests": digests})
    _require(len({row["name"] for row in result}) == len(result), "source_metadata_mismatch")
    return result


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url, maximum, deadline):
    """Fixed HTTPS transport with no proxy environment or executable process."""
    _url(url)
    _require(time.monotonic() < deadline, "source_timeout")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _Redirect())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with opener.open(request, timeout=min(30, deadline - time.monotonic())) as response:
        _require(response.status == 200, "source_unavailable")
        chunks, size = [], 0
        while True:
            _require(time.monotonic() < deadline, "source_timeout")
            # read1 returns after one buffered read rather than accumulating
            # an entire requested buffer while a peer trickles content.
            # DNS, headers and HTTP chunk framing are not a hard deadline.
            chunk = response.read1(min(65536, maximum + 1 - size))
            _require(time.monotonic() < deadline, "source_timeout")
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            _require(size <= maximum, "source_size_limit")
            chunks.append(chunk)


@dataclass(frozen=True)
class PreparedRecipes:
    """Private acquired bytes and provenance; no execution authority."""
    _manifest: bytes = field(repr=False)
    _files: tuple = field(repr=False)

    def as_dict(self):
        manifest = json.loads(self._manifest)
        return {"preparation_id": manifest["preparation_id"], "architecture": manifest["architecture"],
                "roots": manifest["roots"], "recipes": [{"package_base": row["package_base"],
                    "version": row["version"], "packages": row["packages"],
                    "input_count": len(row["acquired_files"]), "trust": "explicitly_accepted"}
                    for row in manifest["recipes"]], "dependencies": manifest["dependencies"],
                "build_order": manifest["build_order"], "build_authorized": False, "installation_authorized": False,
                "generated_metadata": "unverified", "source_signatures": "unverified",
                "native_resolution": "required", "dependency_installation": "not_performed"}


def prepare_recipes(pins, trusts, *, roots, choices, architecture="x86_64", _fetcher=None):
    """Acquire an explicitly routed recursive input closure without any execution.

    Private fetcher injection is trusted fixture embedding. This is not a wire
    request and no caller metadata selects a program, environment or command.
    """
    _require(type(pins) is tuple and 1 <= len(pins) <= MAX_RECIPES
             and all(type(pin) is RecipePin for pin in pins) and _name(architecture))
    for pin in pins:
        pin.__post_init__()
    indexed = {pin.package_base: pin for pin in pins}
    _require(len(indexed) == len(pins) and type(roots) is tuple and roots
             and all(type(root) is str and root in indexed for root in roots) and len(set(roots)) == len(roots))
    _require(type(trusts) is tuple and all(type(trust) is RecipeTrust for trust in trusts))
    for trust in trusts:
        trust.__post_init__()
    accepted = {trust.recipe_id: trust for trust in trusts}
    _require(len(accepted) == len(trusts) and set(accepted) == {pin.recipe_id for pin in pins}, "recipe_trust_required")
    _require(type(choices) is tuple and len(choices) <= 1024 and all(type(choice) is DependencyChoice for choice in choices))
    for choice in choices:
        choice.__post_init__()
    routes = {choice.name: choice for choice in choices}
    _require(len(routes) == len(choices))
    fetcher = _fetch if _fetcher is None else _fetcher
    deadline = time.monotonic() + 120
    files, loaded, visiting, order, dependencies = [], {}, set(), [], []
    total = 0

    def acquire(base, pin, maximum):
        nonlocal total
        _require(len(files) < MAX_FILES and total < MAX_TOTAL_BYTES, "aur_scope_limit")
        try:
            raw = fetcher(pin.url, min(maximum, MAX_TOTAL_BYTES - total), deadline)
        except AurPreparationError:
            raise
        except Exception:
            raise AurPreparationError("source_unavailable") from None
        _require(type(raw) is bytes and len(raw) <= min(maximum, MAX_TOTAL_BYTES - total), "source_size_limit")
        _require(time.monotonic() < deadline, "source_timeout")
        _require(all(_digest(algorithm, raw) == value for algorithm, value in pin.digests), "source_digest_mismatch")
        total += len(raw)
        files.append((base, pin.name, raw))
        return raw

    def visit(base):
        _require(base not in visiting, "aur_dependency_cycle")
        if base in loaded:
            return loaded[base]
        _require(base in indexed, "aur_recipe_missing")
        visiting.add(base)
        pin = indexed[base]
        content = {item.name: acquire(base, item, MAX_METADATA_BYTES) for item in pin.files}
        metadata = parse_srcinfo(content[".SRCINFO"], architecture=architecture).model
        _require(metadata["package_base"] == base and metadata["version"] == pin.version
                 and tuple(row["name"] for row in metadata["outputs"]) == pin.packages, "recipe_metadata_mismatch")
        for output in metadata["outputs"]:
            for key in ("install", "changelog"):
                for name in output["fields"].get(key, []):
                    _require(not name or (_filename(name) and name in content), "recipe_file_missing")
        sources = _sources(metadata)
        source_pins = {item.name: item for item in pin.sources}
        _require(set(source_pins) == {item["name"] for item in sources if item["url"] is not None}, "source_metadata_mismatch")
        for source in sources:
            if source["url"] is None:
                _require(source["name"] in content, "recipe_file_missing")
                raw = content[source["name"]]
            else:
                item = source_pins[source["name"]]
                _require(item.url == source["url"] and all(dict(item.digests).get(key) == value
                    for key, value in source["digests"].items() if key in {"sha256", "sha512"}), "source_metadata_mismatch")
                raw = acquire(base, item, MAX_SOURCE_BYTES)
            _require(all(_digest(key, raw) == value for key, value in source["digests"].items()), "source_digest_mismatch")
        requests = [(output["name"], "runtime", value) for output in metadata["outputs"] for value in output["dependencies"]]
        for key, phase in (("makedepends", "build"), ("checkdepends", "check")):
            requests += [(None, phase, value) for value in metadata["fields"].get(key, [])
                         + metadata["fields"].get(key + "_" + architecture, [])]
        for output, phase, expression in requests:
            name = _RELATION.fullmatch(expression)[1]
            _require(name in routes, "dependency_source_required")
            choice = routes[name]
            edge = {"recipe_base": base, "output": output, "phase": phase, "request": expression,
                    "source": choice.source, "target_recipe": choice.recipe_base, "target_package": choice.package,
                    "constraint_verification": "requires_native_resolution"}
            if choice.source == "aur":
                _require(choice.recipe_base != base or (phase == "runtime" and output != choice.package),
                         "aur_dependency_cycle")
                child = metadata if choice.recipe_base == base else visit(choice.recipe_base)
                targets = [item for item in child["outputs"] if item["name"] == choice.package]
                _require(len(targets) == 1 and (name == choice.package or name in {
                    _RELATION.fullmatch(value)[1] for value in targets[0]["provides"]}), "aur_provider_mismatch")
            dependencies.append(edge)
        loaded[base] = metadata
        visiting.remove(base)
        order.append(base)
        return metadata

    for root in roots:
        visit(root)
    _require(set(loaded) == set(indexed), "unused_recipe_pin")
    recipes = []
    for base in order:
        pin = indexed[base]
        trust = accepted[pin.recipe_id]
        recipes.append({**pin._model(), "recipe_id": pin.recipe_id, "metadata": loaded[base],
                        "trust": {"decision_id": trust.decision_id, "operator_uid": trust.operator_uid},
                        "acquired_files": [{"name": name, "size": len(raw), "sha256": _digest("sha256", raw)}
                                           for owner, name, raw in files if owner == base]})
    return PreparedRecipes(_json({"version": 1, "preparation_id": str(uuid.uuid4()), "architecture": architecture,
        "roots": list(roots), "recipes": recipes, "dependencies": dependencies, "build_order": order}), tuple(files))
