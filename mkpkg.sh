#!/usr/bin/env bash

if (( $# < 2 )); then
  echo "Usage: $0 METAPKG_NAME DESC PKG [ PKG .. ]"
  echo "       $0 METAPKG_NAME +PKG|-PKG [ +PKG|-PKG .. ]"
  echo "       $0 METAPKG_NAME --refresh"
  exit 1
fi

if [[ ! "$1" =~ ^[a-z0-9][a-z0-9_+-]*$ ]]; then
  echo "Invalid package name: use lowercase letters, digits, underscores, plus signs, or hyphens; start with a letter or digit." >&2
  exit 1
fi

METAPKG_NAME="vhata-${1#vhata-}"
# Refresh never rewrites the PKGBUILD or increments its release.
if [[ "$2" == --refresh ]]; then
  if (( $# != 2 )) || [[ ! -f "${METAPKG_NAME}/PKGBUILD" ]]; then
    echo "Refresh requires an existing metapackage and no additional arguments." >&2
    exit 1
  fi
  SRCINFO=$(cd "$METAPKG_NAME" && makepkg --printsrcinfo) || exit $?
  VERSION= RELEASE= EPOCH=
  DEPENDENCIES=()
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*(pkgver|pkgrel|epoch|depends)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      case "${BASH_REMATCH[1]}" in
        pkgver) VERSION=${BASH_REMATCH[2]} ;;
        pkgrel) RELEASE=${BASH_REMATCH[2]} ;;
        epoch) EPOCH=${BASH_REMATCH[2]} ;;
        depends) DEPENDENCIES+=("${BASH_REMATCH[2]}") ;;
      esac
    fi
  done <<< "$SRCINFO"
  if [[ -z "$VERSION" || -z "$RELEASE" ]]; then
    echo "Cannot refresh: missing version metadata." >&2
    exit 1
  fi
  TARGET_VERSION="${VERSION}-${RELEASE}"
  [[ -z "$EPOCH" || "$EPOCH" == 0 ]] || TARGET_VERSION="${EPOCH}:${TARGET_VERSION}"
  INSTALLED=$(pacman -Q "$METAPKG_NAME" 2>/dev/null) || INSTALLED=
  NEED_BUILD=false
  [[ "$INSTALLED" == "$METAPKG_NAME $TARGET_VERSION" ]] || NEED_BUILD=true
  if (( ${#DEPENDENCIES[@]} > 0 )); then
    pacman -T "${DEPENDENCIES[@]}" >/dev/null || NEED_BUILD=true
  fi
  if "$NEED_BUILD"; then
    (cd "$METAPKG_NAME" && makepkg -sif) || exit $?
  else
    echo "$METAPKG_NAME is up to date ($TARGET_VERSION)."
  fi
  # Resolve version constraints and virtual dependencies to installed providers.
  if (( ${#DEPENDENCIES[@]} > 0 )); then
    INSTALLED_INFO=$(LC_ALL=C pacman -Qi) || exit $?
    PROVIDERS=$(printf '%s\n' "$INSTALLED_INFO" | python3 -c '
import re, sys
records = []
for block in sys.stdin.read().split("\n\n"):
    fields = {}
    key = None
    for line in block.splitlines():
        match = re.match(r"^([^ :][^:]*?)\s*:\s*(.*)$", line)
        if match:
            key = match[1].strip()
            fields[key] = match[2]
        elif key and line.startswith(" "):
            fields[key] += " " + line.strip()
    if "Name" in fields:
        records.append(fields)
selected = set()
for dep in sys.argv[1:]:
    name = re.split(r"[<>=]", dep, maxsplit=1)[0]
    direct = [r["Name"] for r in records if r["Name"] == name]
    providers = direct or [r["Name"] for r in records if name in
        [p.split("=", 1)[0] for p in r.get("Provides", "").split()]]
    if not providers:
        sys.exit("Cannot find installed provider for " + dep)
    selected.update(providers)
print("\n".join(sorted(selected)))
' "${DEPENDENCIES[@]}") || exit $?
    mapfile -t PROVIDER_ARRAY <<< "$PROVIDERS"
    sudo pacman -D --asdeps "${PROVIDER_ARRAY[@]}" || exit $?
  fi
  exit 0
fi

EDIT_MODE=false
if [[ "$2" == [+-]* ]]; then
  EDIT_MODE=true
  if [[ ! -f "${METAPKG_NAME}/PKGBUILD" ]]; then
    echo "Cannot edit: ${METAPKG_NAME}/PKGBUILD does not exist." >&2
    exit 1
  fi
  shift
else
  if (( $# < 3 )); then
    echo "Supply a description and at least one dependency." >&2
    exit 1
  fi
  DESC="$2"
  shift ; shift
fi

PKGREL=1
if [[ -f "${METAPKG_NAME}/PKGBUILD" ]]; then
  PREVIOUS_PKGREL=$(sed -n 's/^pkgrel=\([0-9][0-9]*\)$/\1/p' "${METAPKG_NAME}/PKGBUILD")
  if [[ ! "$PREVIOUS_PKGREL" =~ ^[0-9]+$ ]]; then
    echo "Cannot increment pkgrel: expected one integer pkgrel assignment in ${METAPKG_NAME}/PKGBUILD." >&2
    exit 1
  fi
  # ensure base 10 arithmetic
  PKGREL=$((10#$PREVIOUS_PKGREL + 1))
  if (( PKGREL <= 0 )); then
    echo "Cannot increment pkgrel: release number is too large." >&2
    exit 1
  fi
fi

if "$EDIT_MODE"; then
  DEPENDENCIES=$(python3 - "${METAPKG_NAME}/PKGBUILD" "$PKGREL" "$@" <<'PYEDIT'
import pathlib
import re
import shlex
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
try:
    blocks = list(re.finditer(r"^depends=\((.*?)\)", text, re.M | re.S))
    if len(blocks) != 1:
        raise ValueError("expected one literal depends array")
    block = blocks[0]
    body = block.group(1)
    # Parse literal shell words only; never execute the existing PKGBUILD.
    if any(char in body for char in "$`\\"):
        raise ValueError("depends array must contain literal package names")
    dependencies = set(shlex.split(body, comments=True))
    pattern = r"[a-zA-Z0-9_+][a-zA-Z0-9@._+:<>=~-]*"
    if any(not re.fullmatch(pattern, dep) for dep in dependencies):
        raise ValueError("unsupported dependency in existing array")
    for change in sys.argv[3:]:
        if len(change) < 2 or change[0] not in "+-" or not re.fullmatch(pattern, change[1:]):
            raise ValueError("each edit must be +PACKAGE or -PACKAGE")
        if change[0] == "+":
            dependencies.add(change[1:])
        else:
            dependencies.discard(change[1:])
    ordered = sorted(dependencies)
    replacement = "depends=(\n" + "".join("  '" + dep + "'\n" for dep in ordered) + ")"
    updated = text[:block.start()] + replacement + text[block.end():]
    updated = re.sub(r"^pkgrel=[0-9]+$", "pkgrel=" + sys.argv[2], updated, count=1, flags=re.M)
    path.write_text(updated)
    print("\n".join(ordered), end="")
except ValueError as error:
    sys.exit("Cannot edit dependencies: " + str(error))
PYEDIT
  ) || exit $?
  set --
  if [[ -n "$DEPENDENCIES" ]]; then
    mapfile -t DEPENDENCY_ARRAY <<< "$DEPENDENCIES"
    set -- "${DEPENDENCY_ARRAY[@]}"
  fi
else
mkdir -p "$METAPKG_NAME" || exit
cat <<EOF > "${METAPKG_NAME}/PKGBUILD"
pkgname=${METAPKG_NAME}
pkgver=1
pkgrel=${PKGREL}
pkgdesc=$(printf '%q' "$DESC")
arch=('any')

depends=(
$(
  printf '  %s\n' "$@" | LC_ALL=C sort
)
)

package() {
  :
}
EOF
fi

(
  cd "$METAPKG_NAME" || exit
  makepkg -si
) || exit $?
if (( $# > 0 )); then
  sudo pacman -D --asdeps "$@"
fi
